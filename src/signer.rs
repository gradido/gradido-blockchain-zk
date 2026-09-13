//! The device's side of the custody split (privacy_todo.md E5): check a transfer, then sign it.
//!
//! The community server builds and proves; the device holds the spending key and authorises.
//! If the device signed whatever 32-byte hash the server sent, a compromised server could swap
//! a payment to Bob for one to itself and get it signed — the node would accept it, because it
//! is a perfectly valid transfer. So the device never takes a hash from the server. It gets the
//! transaction body and the openings of every created note, and recomputes everything that
//! decides where the money goes:
//!
//! 1. the sighash, from the body bytes
//! 2. the body itself: a local shielded transfer and nothing else (`wire::parse_transfer_body`)
//! 3. every created note: its commitment must be the one in the body, its ciphertexts must be
//!    exactly what encrypting the opening gives, its memo must match `memo_cm`
//! 4. every created note is sorted into own (change), value 0 (padding) or a payment, and the
//!    payments are what the device shows
//! 5. it signs only actions whose `rk` is derived from its own `ak`
//!
//! That is enough because every created note of the transfer passes through step 3, and the
//! proof and the binding signature guarantee that the created notes add up to the spent ones.
//! The server cannot hide an output, and if it spends more of the owner's notes than needed, the
//! surplus comes back as change the device sees.
//!
//! What this does not cover: the sealed memos in `TransactionBody.memos` (E15) are not opened
//! here, so a wrong one costs the recipient the memo text, not money; `rseed` comes from the
//! server, so a server that chooses it badly can weaken the privacy of the notes, not move them.
//! And none of this helps if the device's code comes from the server it is meant to check —
//! the signer has to be an app or extension of its own, not a page the community server delivers.

use ff::PrimeField;
use group::Curve;
use pasta_curves::pallas;
use prost::Message;
use rand::{rngs::StdRng, CryptoRng, RngCore, SeedableRng};
use reddsa::{orchard::SpendAuth, Signature};

use crate::bundle::{body_sighash, ACTIONS};
use crate::keys::{Address, SpendingKey};
use crate::memo::{self, MEMO_LEN};
use crate::note::{from_parts, NoteError, NoteKind, RandomSeed};
use crate::note_encryption::{encrypt, GradidoDomain, NoteWithSeed, FREE_MEMO_SIZE};
use crate::signature;
use crate::wire::{self, WireError};

pub type Base = pallas::Base;

/// Text and randomness of a memo (E15), so the device can check it against `memo_cm`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoOpening {
    pub text: [u8; MEMO_LEN],
    pub r_memo: Base,
}

/// Everything about one created note that is not in the transaction body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputOpening {
    pub address: Address,
    pub value: u64,
    pub kind: NoteKind,
    pub expiry_epoch: u64,
    pub rseed: RandomSeed,
    /// `Base::zero()` for no memo
    pub memo_cm: Base,
    /// the free part of the memo slot inside the note encryption
    pub free_memo: [u8; FREE_MEMO_SIZE],
    /// required whenever `memo_cm` is not zero
    pub memo: Option<MemoOpening>,
}

/// What the server sends to the device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigningRequest {
    /// `GradidoTransaction.body_bytes`, exactly as they will be submitted
    pub body: Vec<u8>,
    /// one opening per action, in action order
    pub outputs: Vec<OutputOpening>,
    /// the rerandomiser of every action the device has to sign, `None` for the others
    pub alphas: Vec<Option<pallas::Scalar>>,
}

/// A payment to someone else, as the device shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Payment {
    pub address: Address,
    /// GradidoUnit at `created_at`
    pub value: u64,
    pub kind: NoteKind,
    pub memo: Option<[u8; MEMO_LEN]>,
    pub free_memo: [u8; FREE_MEMO_SIZE],
}

/// The result of checking a request: what signing it means.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Review {
    pub created_at: u64,
    pub payments: Vec<Payment>,
    /// value that comes back to the device's own addresses
    pub change: u64,
    /// the hash the signatures will cover, computed from the body
    pub sighash: [u8; 32],
    /// how many spends the device signs
    pub spends: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReviewError {
    /// the body is not a well-formed local shielded transfer
    Body(WireError),
    WrongOutputCount(usize),
    WrongAlphaCount(usize),
    /// the opening of this action is not a valid note
    InvalidNote(usize, NoteError),
    /// the opening does not give the note commitment in the body
    CommitmentMismatch(usize),
    /// the ciphertexts in the body are not the encryption of the opening
    CiphertextMismatch(usize),
    /// `memo_cm` is set but no memo, or a memo that does not match, was sent
    MemoMismatch(usize),
    /// an alpha was sent for an action that does not spend with this device's key
    ForeignSpend(usize),
    NothingToSign,
    /// the request itself could not be decoded
    Request,
}

/// Checks a request against the device's own key. Nothing is signed.
pub fn review(request: &SigningRequest, sk: &SpendingKey, community: Base) -> Result<Review, ReviewError> {
    let body = wire::parse_transfer_body(&request.body).map_err(ReviewError::Body)?;
    let (_, actions) = wire::decode_shielded(&body.shielded).map_err(ReviewError::Body)?;
    if request.outputs.len() != ACTIONS {
        return Err(ReviewError::WrongOutputCount(request.outputs.len()));
    }
    if request.alphas.len() != ACTIONS {
        return Err(ReviewError::WrongAlphaCount(request.alphas.len()));
    }
    let fvk = sk.full_viewing_key();

    let mut payments = Vec::new();
    let mut change = 0u64;
    let mut spends = 0;
    for (i, ((action, opening), alpha)) in actions.iter().zip(&request.outputs).zip(&request.alphas).enumerate() {
        // the created note: commitment, ciphertexts, memo
        let note = from_parts(
            community,
            community,
            opening.value,
            body.created_at,
            opening.kind,
            opening.expiry_epoch,
            &opening.address,
            action.nullifier,
            opening.memo_cm,
            opening.rseed,
        )
        .map_err(|e| ReviewError::InvalidNote(i, e))?;
        if note.commitment() != action.cm {
            return Err(ReviewError::CommitmentMismatch(i));
        }
        let domain = GradidoDomain { community, coin_community: community, rho: action.nullifier };
        // with an outgoing viewing key the encryption is deterministic; the rng is never used
        let expected = encrypt(
            domain,
            &NoteWithSeed { note, rseed: opening.rseed },
            opening.free_memo,
            Some(fvk.ovk),
            action.cv_net.into(),
            &mut StdRng::seed_from_u64(0),
        );
        if expected.epk_bytes.0 != action.encrypted.epk_bytes.0
            || expected.enc_ciphertext != action.encrypted.enc_ciphertext
            || expected.out_ciphertext != action.encrypted.out_ciphertext
        {
            return Err(ReviewError::CiphertextMismatch(i));
        }
        let memo_text = match (&opening.memo, opening.memo_cm == Base::zero()) {
            (None, true) => None,
            (Some(m), false) if memo::verify(&m.text, m.r_memo, opening.memo_cm) => Some(m.text),
            _ => return Err(ReviewError::MemoMismatch(i)),
        };

        // where it goes
        if fvk.owns(&opening.address) {
            change = change.checked_add(opening.value).ok_or(ReviewError::InvalidNote(i, NoteError::ValueTooLarge))?;
        } else if opening.value > 0 {
            payments.push(Payment {
                address: opening.address,
                value: opening.value,
                kind: opening.kind,
                memo: memo_text,
                free_memo: opening.free_memo,
            });
        }

        // the spend: only with our own key
        if let Some(alpha) = alpha {
            let rk = (pallas::Point::from(fvk.ak) + signature::spend_auth_base() * alpha).to_affine();
            if rk != action.rk {
                return Err(ReviewError::ForeignSpend(i));
            }
            spends += 1;
        }
    }
    if spends == 0 {
        return Err(ReviewError::NothingToSign);
    }
    Ok(Review { created_at: body.created_at, payments, change, sighash: body_sighash(&request.body), spends })
}

/// Reviews the request and, if it holds, signs every spend of this device. The signatures come
/// in action order, as `UnauthorizedBundle::authorize` expects them. Show the `Review` to the
/// owner before the signatures leave the device.
pub fn sign(
    request: &SigningRequest,
    sk: &SpendingKey,
    community: Base,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(Review, Vec<Signature<SpendAuth>>), ReviewError> {
    let review = review(request, sk, community)?;
    let ask = sk.spend_authorizing_key();
    let signatures = request
        .alphas
        .iter()
        .flatten()
        .map(|alpha| signature::sign_spend_auth(&ask, *alpha, &review.sighash, &mut *rng))
        .collect();
    Ok((review, signatures))
}

// ------------------------------------------------------------------------------ transport

/// Upper bound for an encoded request, checked before decoding.
pub const MAX_REQUEST_SIZE: usize = 64 * 1024;

#[derive(Clone, PartialEq, Message)]
struct OutputOpeningMessage {
    #[prost(bytes = "vec", tag = "1")]
    address: Vec<u8>,
    #[prost(uint64, tag = "2")]
    value: u64,
    #[prost(uint32, tag = "3")]
    kind: u32,
    #[prost(uint64, tag = "4")]
    expiry_epoch: u64,
    #[prost(bytes = "vec", tag = "5")]
    rseed: Vec<u8>,
    #[prost(bytes = "vec", tag = "6")]
    memo_cm: Vec<u8>,
    #[prost(bytes = "vec", tag = "7")]
    free_memo: Vec<u8>,
    #[prost(bytes = "vec", tag = "8")]
    memo_text: Vec<u8>,
    #[prost(bytes = "vec", tag = "9")]
    r_memo: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
struct SigningRequestMessage {
    #[prost(bytes = "vec", tag = "1")]
    body: Vec<u8>,
    #[prost(message, repeated, tag = "2")]
    outputs: Vec<OutputOpeningMessage>,
    /// 32 bytes per action, empty for an action the device does not sign
    #[prost(bytes = "vec", repeated, tag = "3")]
    alphas: Vec<Vec<u8>>,
}

impl SigningRequest {
    /// Protobuf encoding for the way from the server to the device.
    pub fn encode(&self) -> Vec<u8> {
        SigningRequestMessage {
            body: self.body.clone(),
            outputs: self
                .outputs
                .iter()
                .map(|o| OutputOpeningMessage {
                    address: o.address.to_raw().to_vec(),
                    value: o.value,
                    kind: o.kind as u32,
                    expiry_epoch: o.expiry_epoch,
                    rseed: o.rseed.to_bytes().to_vec(),
                    memo_cm: o.memo_cm.to_repr().to_vec(),
                    free_memo: o.free_memo.to_vec(),
                    memo_text: o.memo.as_ref().map(|m| m.text.to_vec()).unwrap_or_default(),
                    r_memo: o.memo.as_ref().map(|m| m.r_memo.to_repr().to_vec()).unwrap_or_default(),
                })
                .collect(),
            alphas: self.alphas.iter().map(|a| a.map(|a| a.to_repr().to_vec()).unwrap_or_default()).collect(),
        }
        .encode_to_vec()
    }

    /// Strict decoding: canonical encoding and exact lengths only. The content is checked by
    /// `review`, not here.
    pub fn decode(bytes: &[u8]) -> Result<Self, ReviewError> {
        if bytes.len() > MAX_REQUEST_SIZE {
            return Err(ReviewError::Request);
        }
        let message = SigningRequestMessage::decode(bytes).map_err(|_| ReviewError::Request)?;
        if message.encode_to_vec() != bytes {
            return Err(ReviewError::Request);
        }
        fn array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], ReviewError> {
            bytes.try_into().map_err(|_| ReviewError::Request)
        }
        fn field(bytes: &[u8]) -> Result<Base, ReviewError> {
            Option::from(Base::from_repr(array(bytes)?)).ok_or(ReviewError::Request)
        }
        let outputs = message
            .outputs
            .iter()
            .map(|o| {
                let memo = match (o.memo_text.is_empty(), o.r_memo.is_empty()) {
                    (true, true) => None,
                    (false, false) => Some(MemoOpening { text: array(&o.memo_text)?, r_memo: field(&o.r_memo)? }),
                    _ => return Err(ReviewError::Request),
                };
                Ok(OutputOpening {
                    address: Address::from_raw(&array(&o.address)?).ok_or(ReviewError::Request)?,
                    value: o.value,
                    kind: match o.kind {
                        0 => NoteKind::Normal,
                        1 => NoteKind::Deferred,
                        _ => return Err(ReviewError::Request),
                    },
                    expiry_epoch: o.expiry_epoch,
                    rseed: RandomSeed::from_bytes(array(&o.rseed)?),
                    memo_cm: field(&o.memo_cm)?,
                    free_memo: array(&o.free_memo)?,
                    memo,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let alphas = message
            .alphas
            .iter()
            .map(|a| {
                if a.is_empty() {
                    return Ok(None);
                }
                Option::<pallas::Scalar>::from(pallas::Scalar::from_repr(array(a)?))
                    .map(Some)
                    .ok_or(ReviewError::Request)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { body: message.body, outputs, alphas })
    }
}

/// A signature leaves the device as 64 bytes.
pub fn signature_bytes(signature: &Signature<SpendAuth>) -> [u8; 64] {
    <[u8; 64]>::from(*signature)
}
