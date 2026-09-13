//! The bundle in the wire format of `gradido_protocol/proto/gradido/shielded.proto`.
//!
//! `ShieldedBundle` goes into the transaction body and is covered by the signatures;
//! `ShieldedAuthorization` (proof and signatures) sits next to the body in `GradidoTransaction`.
//! Time and community are not repeated here — they come from `TransactionBody.created_at` and
//! the community the transaction belongs to.
//!
//! The messages are written out by hand with `prost` derives instead of generated, so no
//! protoc is needed; the C side decodes the same bytes with its pbtools code.
//!
//! Decoding is strict, so that one bundle has exactly one encoding:
//! * the bytes must be the canonical encoding of what they decode to — no unknown fields, no
//!   repeated singular fields, no non-minimal varints, fields in tag order. Protobuf decoders
//!   disagree on duplicates (prost merges sub-messages, pbtools replaces them), so without this
//!   the node's parser and this one could see different anchors or nullifiers in the same bytes;
//!   and the authorisation, which no signature covers, could be changed by anyone relaying it
//! * every field has its exact length, the proof included (halo2 would ignore trailing bytes)
//! * every point and field element has its canonical encoding, and the points are not the identity
//!
//! all before any cryptography runs.

use ff::PrimeField;
use group::GroupEncoding;
use pasta_curves::pallas;
use prost::Message;
use reddsa::Signature;
use zcash_note_encryption::{EphemeralKeyBytes, ENC_CIPHERTEXT_SIZE, OUT_CIPHERTEXT_SIZE};

use crate::bundle::{Action, Bundle, ACTIONS, CIRCUIT_VERSION, PROOF_SIZE};

/// Upper bounds for the encoded messages, checked before decoding allocates anything. The exact
/// sizes are fixed by the checks after decoding; these only keep garbage cheap.
pub const MAX_SHIELDED_BUNDLE_SIZE: usize = 4 * 1024;
pub const MAX_AUTHORIZATION_SIZE: usize = PROOF_SIZE + 1024;
use crate::note_encryption::EncryptedNote;

pub type Base = pallas::Base;

#[derive(Clone, PartialEq, Message)]
pub struct Anchor {
    #[prost(bytes = "vec", tag = "1")]
    pub root: Vec<u8>,
    #[prost(uint32, tag = "2")]
    pub tree_epoch: u32,
}

#[derive(Clone, PartialEq, Message)]
pub struct ShieldedAction {
    #[prost(bytes = "vec", tag = "1")]
    pub cv: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub nullifier: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub rk: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub cm_x: Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    pub ephemeral_key: Vec<u8>,
    #[prost(bytes = "vec", tag = "6")]
    pub enc_ciphertext: Vec<u8>,
    #[prost(bytes = "vec", tag = "7")]
    pub out_ciphertext: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub struct ShieldedBundle {
    #[prost(message, optional, tag = "1")]
    pub anchor: Option<Anchor>,
    #[prost(message, repeated, tag = "2")]
    pub actions: Vec<ShieldedAction>,
    #[prost(bytes = "vec", tag = "3")]
    pub cross_community_cv: Vec<u8>,
    #[prost(uint32, tag = "4")]
    pub circuit_version: u32,
}

#[derive(Clone, PartialEq, Message)]
pub struct ShieldedAuthorization {
    #[prost(bytes = "vec", tag = "1")]
    pub proof: Vec<u8>,
    #[prost(bytes = "vec", repeated, tag = "2")]
    pub spend_auth_sigs: Vec<Vec<u8>>,
    #[prost(bytes = "vec", tag = "3")]
    pub binding_sig: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireError {
    Protobuf,
    MissingAnchor,
    WrongCircuitVersion(u32),
    WrongActionCount(usize),
    WrongLength(&'static str),
    NotCanonical(&'static str),
    CrossCommunityNotSupported,
    /// tree epochs (E10) are not implemented, only epoch 0 exists
    UnsupportedTreeEpoch(u32),
    TooLarge,
    /// the transaction body has a field a shielded transfer does not have (tag)
    UnsupportedBody(u32),
    MissingField(&'static str),
}

fn bytes32(field: &'static str, bytes: &[u8]) -> Result<[u8; 32], WireError> {
    bytes.try_into().map_err(|_| WireError::WrongLength(field))
}

fn base(field: &'static str, bytes: &[u8]) -> Result<Base, WireError> {
    Option::from(Base::from_repr(bytes32(field, bytes)?)).ok_or(WireError::NotCanonical(field))
}

/// A canonical point other than the identity. No honest `cv` or `rk` is the identity, and the
/// public inputs of the proof need affine coordinates.
fn point(field: &'static str, bytes: &[u8]) -> Result<pallas::Affine, WireError> {
    use group::prime::PrimeCurveAffine;
    let p = Option::<pallas::Affine>::from(pallas::Affine::from_bytes(&bytes32(field, bytes)?))
        .ok_or(WireError::NotCanonical(field))?;
    if bool::from(p.is_identity()) {
        return Err(WireError::NotCanonical(field));
    }
    Ok(p)
}

/// The part of a bundle inside the transaction body: anchor and actions. It exists before the
/// bundle is authorised, because the signatures cover the body it sits in.
pub fn shielded_to_wire(anchor: Base, actions: &[Action]) -> ShieldedBundle {
    ShieldedBundle {
        anchor: Some(Anchor { root: anchor.to_repr().to_vec(), tree_epoch: 0 }),
        actions: actions
            .iter()
            .map(|a| ShieldedAction {
                cv: a.cv_net.to_bytes().to_vec(),
                nullifier: a.nullifier.to_repr().to_vec(),
                rk: a.rk.to_bytes().to_vec(),
                cm_x: a.cm.to_repr().to_vec(),
                ephemeral_key: a.encrypted.epk_bytes.0.to_vec(),
                enc_ciphertext: a.encrypted.enc_ciphertext.to_vec(),
                out_ciphertext: a.encrypted.out_ciphertext.to_vec(),
            })
            .collect(),
        cross_community_cv: Vec::new(),
        circuit_version: CIRCUIT_VERSION,
    }
}

/// Serialised `ShieldedBundle`, what goes into `TransactionBody.shielded_transfer`.
pub fn encode_shielded(anchor: Base, actions: &[Action]) -> Vec<u8> {
    shielded_to_wire(anchor, actions).encode_to_vec()
}

/// Splits a bundle into the part inside the body and the authorisation next to it.
pub fn to_wire(bundle: &Bundle) -> (ShieldedBundle, ShieldedAuthorization) {
    let shielded = shielded_to_wire(bundle.anchor, &bundle.actions);
    let authorization = ShieldedAuthorization {
        proof: bundle.proof.clone(),
        spend_auth_sigs: bundle
            .spend_auth_sigs
            .iter()
            .map(|s| <[u8; 64]>::from(*s).to_vec())
            .collect(),
        binding_sig: <[u8; 64]>::from(bundle.binding_sig).to_vec(),
    };
    (shielded, authorization)
}

/// Anchor and actions of a `ShieldedBundle`, checked field by field.
pub fn shielded_from_wire(shielded: &ShieldedBundle) -> Result<(Base, Vec<Action>), WireError> {
    if shielded.circuit_version != CIRCUIT_VERSION {
        return Err(WireError::WrongCircuitVersion(shielded.circuit_version));
    }
    if !shielded.cross_community_cv.is_empty() {
        return Err(WireError::CrossCommunityNotSupported);
    }
    if shielded.actions.len() != ACTIONS {
        return Err(WireError::WrongActionCount(shielded.actions.len()));
    }
    let anchor = shielded.anchor.as_ref().ok_or(WireError::MissingAnchor)?;
    if anchor.tree_epoch != 0 {
        return Err(WireError::UnsupportedTreeEpoch(anchor.tree_epoch));
    }

    let mut actions = Vec::with_capacity(ACTIONS);
    for a in &shielded.actions {
        let enc_ciphertext: [u8; ENC_CIPHERTEXT_SIZE] = a
            .enc_ciphertext
            .as_slice()
            .try_into()
            .map_err(|_| WireError::WrongLength("enc_ciphertext"))?;
        let out_ciphertext: [u8; OUT_CIPHERTEXT_SIZE] = a
            .out_ciphertext
            .as_slice()
            .try_into()
            .map_err(|_| WireError::WrongLength("out_ciphertext"))?;
        let cm = base("cm_x", &a.cm_x)?;
        actions.push(Action {
            cv_net: point("cv", &a.cv)?,
            nullifier: base("nullifier", &a.nullifier)?,
            rk: point("rk", &a.rk)?,
            cm,
            encrypted: EncryptedNote {
                epk_bytes: EphemeralKeyBytes(bytes32("ephemeral_key", &a.ephemeral_key)?),
                cm,
                enc_ciphertext,
                out_ciphertext,
            },
        });
    }
    Ok((base("anchor", &anchor.root)?, actions))
}

/// Rebuilds a bundle from the wire, with the time and community of the transaction.
pub fn from_wire(
    shielded: &ShieldedBundle,
    authorization: &ShieldedAuthorization,
    community: Base,
    now: u64,
) -> Result<Bundle, WireError> {
    let (anchor, actions) = shielded_from_wire(shielded)?;
    if authorization.spend_auth_sigs.len() != ACTIONS {
        return Err(WireError::WrongActionCount(authorization.spend_auth_sigs.len()));
    }
    if authorization.proof.len() != PROOF_SIZE {
        return Err(WireError::WrongLength("proof"));
    }

    let signature = |field: &'static str, bytes: &[u8]| -> Result<[u8; 64], WireError> {
        bytes.try_into().map_err(|_| WireError::WrongLength(field))
    };
    let spend_auth_sigs = authorization
        .spend_auth_sigs
        .iter()
        .map(|s| signature("spend_auth_sig", s).map(Signature::from))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Bundle {
        anchor,
        now,
        community,
        actions,
        proof: authorization.proof.clone(),
        spend_auth_sigs,
        binding_sig: Signature::from(signature("binding_sig", &authorization.binding_sig)?),
    })
}

/// Serialised `ShieldedBundle` and `ShieldedAuthorization`.
pub fn encode(bundle: &Bundle) -> (Vec<u8>, Vec<u8>) {
    let (shielded, authorization) = to_wire(bundle);
    (shielded.encode_to_vec(), authorization.encode_to_vec())
}

fn decode_shielded_message(bytes: &[u8]) -> Result<ShieldedBundle, WireError> {
    if bytes.len() > MAX_SHIELDED_BUNDLE_SIZE {
        return Err(WireError::TooLarge);
    }
    let shielded = ShieldedBundle::decode(bytes).map_err(|_| WireError::Protobuf)?;
    if shielded.encode_to_vec() != bytes {
        return Err(WireError::NotCanonical("ShieldedBundle"));
    }
    Ok(shielded)
}

/// Anchor and actions from a serialised `ShieldedBundle`, as strictly as `decode`.
pub fn decode_shielded(bytes: &[u8]) -> Result<(Base, Vec<Action>), WireError> {
    shielded_from_wire(&decode_shielded_message(bytes)?)
}

/// Decodes both messages; see the module documentation for what "strict" covers.
pub fn decode(
    shielded_bytes: &[u8],
    authorization_bytes: &[u8],
    community: Base,
    now: u64,
) -> Result<Bundle, WireError> {
    if authorization_bytes.len() > MAX_AUTHORIZATION_SIZE {
        return Err(WireError::TooLarge);
    }
    let shielded = decode_shielded_message(shielded_bytes)?;
    let authorization =
        ShieldedAuthorization::decode(authorization_bytes).map_err(|_| WireError::Protobuf)?;
    if authorization.encode_to_vec() != authorization_bytes {
        return Err(WireError::NotCanonical("ShieldedAuthorization"));
    }
    from_wire(&shielded, &authorization, community, now)
}

// ------------------------------------------------------------------------ transaction body

/// What a shielded transfer's `TransactionBody` says, as far as signing it is concerned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransferBody {
    /// `created_at.seconds`, the `now` of the proof
    pub created_at: u64,
    pub version_number: u32,
    /// the serialised `ShieldedBundle` inside it
    pub shielded: Vec<u8>,
    /// number of `EncryptedMemo` entries; their content is not interpreted here
    pub memos: usize,
}

/// Tags of `TransactionBody` (transaction_body.proto).
mod body_tag {
    pub const MEMOS: u32 = 1;
    pub const CREATED_AT: u32 = 2;
    pub const VERSION_NUMBER: u32 = 3;
    pub const TYPE: u32 = 4;
    pub const OTHER_COMMUNITY_UUID: u32 = 5;
    pub const SHIELDED_TRANSFER: u32 = 6;
}

enum FieldValue<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
}

fn read_varint(bytes: &mut &[u8]) -> Result<u64, WireError> {
    let mut value = 0u64;
    for i in 0..10 {
        let (&byte, rest) = bytes.split_first().ok_or(WireError::Protobuf)?;
        *bytes = rest;
        value |= u64::from(byte & 0x7f) << (7 * i);
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(WireError::Protobuf)
}

/// Top-level fields of a message, in order. Only varint and length-delimited fields exist in the
/// messages read here; anything else is rejected.
fn fields(mut bytes: &[u8]) -> Result<Vec<(u32, FieldValue<'_>)>, WireError> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        let key = read_varint(&mut bytes)?;
        let tag = u32::try_from(key >> 3).map_err(|_| WireError::Protobuf)?;
        let value = match key & 7 {
            0 => FieldValue::Varint(read_varint(&mut bytes)?),
            2 => {
                let len = usize::try_from(read_varint(&mut bytes)?).map_err(|_| WireError::Protobuf)?;
                if len > bytes.len() {
                    return Err(WireError::Protobuf);
                }
                let (value, rest) = bytes.split_at(len);
                bytes = rest;
                FieldValue::Bytes(value)
            }
            _ => return Err(WireError::Protobuf),
        };
        out.push((tag, value));
    }
    Ok(out)
}

/// Reads a `TransactionBody` that carries a local shielded transfer, and nothing else.
///
/// Whoever signs a body must know everything in it that has a meaning. So instead of skipping
/// what it does not know, as protobuf decoders do, this parser accepts exactly the fields of a
/// local shielded transfer, each singular field at most once: any other `data` (creation, …),
/// any unknown field, a cross community type or a repeated field is an error.
pub fn parse_transfer_body(body: &[u8]) -> Result<TransferBody, WireError> {
    let mut created_at = None;
    let mut version_number = None;
    let mut transfer_type = None;
    let mut other_community = None;
    let mut shielded = None;
    let mut memos = 0;
    fn once<T>(slot: &mut Option<T>, value: T, field: &'static str) -> Result<(), WireError> {
        if slot.replace(value).is_some() {
            return Err(WireError::NotCanonical(field));
        }
        Ok(())
    }
    for (tag, value) in fields(body)? {
        match (tag, value) {
            (body_tag::MEMOS, FieldValue::Bytes(_)) => memos += 1,
            (body_tag::CREATED_AT, FieldValue::Bytes(timestamp)) => {
                once(&mut created_at, parse_timestamp(timestamp)?, "created_at")?
            }
            (body_tag::VERSION_NUMBER, FieldValue::Varint(v)) => {
                once(&mut version_number, u32::try_from(v).map_err(|_| WireError::Protobuf)?, "version_number")?
            }
            (body_tag::TYPE, FieldValue::Varint(v)) => once(&mut transfer_type, v, "type")?,
            (body_tag::OTHER_COMMUNITY_UUID, FieldValue::Bytes(uuid)) => once(&mut other_community, uuid, "other_community_uuid")?,
            (body_tag::SHIELDED_TRANSFER, FieldValue::Bytes(bundle)) => once(&mut shielded, bundle, "shielded_transfer")?,
            _ => return Err(WireError::UnsupportedBody(tag)),
        }
    }
    if transfer_type.unwrap_or(0) != 0 || other_community.is_some_and(|uuid| !uuid.is_empty()) {
        return Err(WireError::CrossCommunityNotSupported);
    }
    Ok(TransferBody {
        created_at: created_at.ok_or(WireError::MissingField("created_at"))?,
        version_number: version_number.unwrap_or(0),
        shielded: shielded.ok_or(WireError::MissingField("shielded_transfer"))?.to_vec(),
        memos,
    })
}

/// `Timestamp { int64 seconds = 1; int32 nanos = 2; }`, only whole, non-negative seconds that
/// fit into a note timestamp.
fn parse_timestamp(bytes: &[u8]) -> Result<u64, WireError> {
    let mut seconds = None;
    let mut nanos = None;
    for (tag, value) in fields(bytes)? {
        match (tag, value) {
            (1, FieldValue::Varint(v)) if seconds.replace(v).is_none() => {}
            (2, FieldValue::Varint(v)) if nanos.replace(v).is_none() => {}
            _ => return Err(WireError::NotCanonical("created_at")),
        }
    }
    let seconds = seconds.unwrap_or(0);
    if nanos.unwrap_or(0) != 0 || seconds >= 1 << crate::note::TIMESTAMP_BITS {
        return Err(WireError::NotCanonical("created_at"));
    }
    Ok(seconds)
}

#[derive(Clone, PartialEq, Message)]
struct Timestamp {
    #[prost(int64, tag = "1")]
    seconds: i64,
    #[prost(int32, tag = "2")]
    nanos: i32,
}

#[derive(Clone, PartialEq, Message)]
struct LocalTransferBody {
    #[prost(message, optional, tag = "2")]
    created_at: Option<Timestamp>,
    #[prost(uint32, tag = "3")]
    version_number: u32,
    #[prost(bytes = "vec", tag = "6")]
    shielded_transfer: Vec<u8>,
}

/// A `TransactionBody` for a local shielded transfer without memos. The community server builds
/// the real body; this is the minimal one for tests and tools.
pub fn encode_transfer_body(created_at: u64, version_number: u32, shielded: &[u8]) -> Vec<u8> {
    LocalTransferBody {
        created_at: Some(Timestamp { seconds: created_at as i64, nanos: 0 }),
        version_number,
        shielded_transfer: shielded.to_vec(),
    }
    .encode_to_vec()
}
