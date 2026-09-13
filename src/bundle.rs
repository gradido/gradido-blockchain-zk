//! A shielded transfer: building it, authorising it, verifying it, applying it to the ledger.
//!
//! A bundle has a fixed number of actions (`ACTIONS`, privacy_todo.md §5: padded, so the size
//! leaks nothing). Each action spends one note and creates one; missing spends and outputs are
//! filled with dummies of value 0. All actions are proven in **one** proof. Values balance across
//! the actions: every action publishes `cv_net = [decayed(v_old) - v_new] V + [rcv] R`, and the
//! binding signature under `sum rcv` shows the net value commitments add up to zero.
//!
//! The custody split of E5 shows in the API: the community server builds and proves with the
//! full viewing key (`build`), the device checks the transfer and signs each real spend
//! (`crate::signer`), the server adds the binding signature and the dummy signatures
//! (`authorize`).

use std::sync::OnceLock;

use ff::{Field, PrimeField};
use group::{prime::PrimeCurveAffine, Curve, GroupEncoding};
use halo2_proofs::{
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, ProvingKey, SingleVerifier, VerifyingKey},
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use pasta_curves::{pallas, vesta};
use rand::{CryptoRng, RngCore};
use reddsa::{
    orchard::{Binding, SpendAuth},
    Signature,
};

use crate::circuit::action_slice::{ActionSliceCircuit, K, MERKLE_DEPTH};
use crate::decay;
use crate::keys::{Address, FullViewingKey, SpendAuthorizingKey, SpendingKey};
use crate::note::{from_parts, NoteError, NoteKind, RandomSeed};
use crate::note_encryption::{encrypt, EncryptedNote, GradidoDomain, NoteWithSeed, FREE_MEMO_SIZE};
use crate::signature;
use crate::signer::{MemoOpening, OutputOpening, SigningRequest};
use crate::tree::{AnchorHistory, CommitmentTree, DoubleSpend, NullifierSet};

pub type Base = pallas::Base;
/// The production circuit: exact decay with the windowed factor chain.
pub type ActionCircuit = ActionSliceCircuit<true, true>;
/// Actions per bundle.
pub const ACTIONS: usize = 2;
/// Version of the circuit, so a verifying key can be picked (proto field `circuit_version`).
pub const CIRCUIT_VERSION: u32 = 2;
/// Size of the proof for `ACTIONS` actions. halo2 does not check that the transcript is used up,
/// so without this bound trailing bytes would verify and the same bundle would exist in more
/// than one encoding.
pub const PROOF_SIZE: usize = 7936;

const SIGHASH_PERSONALIZATION: &[u8; 16] = b"Gradido_Sighash_";

// ------------------------------------------------------------------------------ keys

pub struct ProvingSetup {
    pub params: Params<vesta::Affine>,
    pub pk: ProvingKey<vesta::Affine>,
    pub vk: VerifyingKey<vesta::Affine>,
}

/// Parameters and keys of the action circuit, built once per process.
pub fn setup() -> &'static ProvingSetup {
    static SETUP: OnceLock<ProvingSetup> = OnceLock::new();
    SETUP.get_or_init(|| {
        let params = Params::new(K);
        let empty = ActionCircuit::default();
        let vk = keygen_vk(&params, &empty).expect("keygen_vk");
        let pk = keygen_pk(&params, vk.clone(), &empty).expect("keygen_pk");
        ProvingSetup { params, pk, vk }
    })
}

// ------------------------------------------------------------------------------ inputs

/// A note the wallet owns and wants to spend.
#[derive(Clone, Debug)]
pub struct SpendInfo {
    pub fvk: FullViewingKey,
    pub note: NoteWithSeed,
    /// position in the commitment tree and the path to the anchor
    pub position: u32,
    pub path: [Base; MERKLE_DEPTH],
}

/// A note to create.
#[derive(Clone, Debug)]
pub struct OutputInfo {
    pub address: Address,
    /// nominal value at `now`
    pub value: u64,
    pub kind: NoteKind,
    pub expiry_epoch: u64,
    /// commitment to the memo (E15), `Base::zero()` for none
    pub memo_cm: Base,
    /// text and randomness behind `memo_cm`; the signing device needs it to check the memo
    pub memo_opening: Option<MemoOpening>,
    /// free text inside the note encryption, readable with the viewing key
    pub memo: [u8; FREE_MEMO_SIZE],
}

impl OutputInfo {
    pub fn new(address: Address, value: u64) -> Self {
        Self {
            address,
            value,
            kind: NoteKind::Normal,
            expiry_epoch: 0,
            memo_cm: Base::zero(),
            memo_opening: None,
            memo: [0u8; FREE_MEMO_SIZE],
        }
    }
}

// ------------------------------------------------------------------------------ bundle

/// What one action publishes (proto `ShieldedAction`).
#[derive(Clone, Debug)]
pub struct Action {
    pub cv_net: pallas::Affine,
    pub nullifier: Base,
    pub rk: pallas::Affine,
    pub cm: Base,
    pub encrypted: EncryptedNote,
}

/// Proven, not yet signed. Holds the secrets the signatures need.
pub struct UnauthorizedBundle {
    pub anchor: Base,
    pub now: u64,
    pub community: Base,
    pub actions: Vec<Action>,
    pub proof: Vec<u8>,
    /// rerandomisers; the device needs the one of its spend to sign
    pub alphas: Vec<pallas::Scalar>,
    rcvs: Vec<pallas::Scalar>,
    /// for dummy spends the builder holds the key and signs itself
    dummy_asks: Vec<Option<SpendAuthorizingKey>>,
    /// openings of the created notes, for the signing device
    outputs: Vec<OutputOpening>,
}

/// A complete shielded transfer (proto `ShieldedBundle` + `ShieldedAuthorization`).
#[derive(Clone, Debug)]
pub struct Bundle {
    pub anchor: Base,
    pub now: u64,
    pub community: Base,
    pub actions: Vec<Action>,
    pub proof: Vec<u8>,
    pub spend_auth_sigs: Vec<Signature<SpendAuth>>,
    pub binding_sig: Signature<Binding>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum BuildError {
    TooManySpends,
    TooManyOutputs,
    /// the decayed spends do not add up to the outputs
    Unbalanced { spent: u64, created: u64 },
    /// more value than a note can hold
    Overflow,
    NoteFromTheFuture,
    /// the spent note belongs to another community
    WrongCommunity,
    /// the output cannot be written as a note (value, time or expiry out of range)
    InvalidNote(NoteError),
    /// the memo opening of an output does not give its `memo_cm`
    MemoMismatch,
    Proof,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AuthorizeError {
    /// not exactly one device signature per real spend
    SignatureCount { expected: usize, got: usize },
    /// the device signature for this action does not verify against its `rk`
    BadSignature(usize),
}

#[derive(Debug, PartialEq, Eq)]
pub enum VerifyError {
    WrongActionCount,
    /// the tree cannot take the new notes
    TreeFull,
    UnknownAnchor,
    DoubleSpend(DoubleSpend),
    Proof,
    SpendAuth(usize),
    Binding,
}

/// What a spend is worth at `now`.
pub fn spendable_value(note: &NoteWithSeed, now: u64) -> Option<u64> {
    let age = now.checked_sub(note.note.t_note)?;
    Some(decay::decay_windowed(note.note.value, age))
}

fn random_base(rng: &mut impl RngCore) -> Base {
    let mut wide = [0u8; 64];
    rng.fill_bytes(&mut wide);
    <Base as ff::FromUniformBytes<64>>::from_uniform_bytes(&wide)
}

/// A spend of value 0 with a throwaway key, for padding.
fn dummy_spend(community: Base, now: u64, rng: &mut (impl RngCore + CryptoRng)) -> (SpendInfo, SpendAuthorizingKey) {
    let sk = SpendingKey::random(rng);
    let fvk = sk.full_viewing_key();
    let mut diversifier = [0u8; 11];
    rng.fill_bytes(&mut diversifier);
    let rseed = RandomSeed::random(rng);
    let note = from_parts(
        community,
        community,
        0,
        now,
        NoteKind::Normal,
        0,
        &fvk.address(diversifier),
        random_base(rng),
        Base::zero(),
        rseed,
    )
    .expect("a note of value 0 dated now is valid, `build` checked `now`");
    let mut path = [Base::zero(); MERKLE_DEPTH];
    for node in path.iter_mut() {
        *node = random_base(rng);
    }
    (
        SpendInfo { fvk, note: NoteWithSeed { note, rseed }, position: 0, path },
        sk.spend_authorizing_key(),
    )
}

/// An output of value 0 to a throwaway address, for padding.
fn dummy_output(rng: &mut (impl RngCore + CryptoRng)) -> OutputInfo {
    let fvk = SpendingKey::random(rng).full_viewing_key();
    let mut d = [0u8; 11];
    rng.fill_bytes(&mut d);
    OutputInfo::new(fvk.address(d), 0)
}

/// Builds and proves a bundle. `ovk` lets the sender recover its outputs later.
pub fn build(
    community: Base,
    anchor: Base,
    now: u64,
    spends: Vec<SpendInfo>,
    outputs: Vec<OutputInfo>,
    ovk: Option<[u8; 32]>,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<UnauthorizedBundle, BuildError> {
    if spends.len() > ACTIONS {
        return Err(BuildError::TooManySpends);
    }
    if outputs.len() > ACTIONS {
        return Err(BuildError::TooManyOutputs);
    }
    if now >= 1 << crate::note::TIMESTAMP_BITS {
        return Err(BuildError::InvalidNote(NoteError::TimestampTooLarge));
    }
    let mut spent = 0u64;
    for s in &spends {
        if s.note.note.community != community || s.note.note.coin_community != community {
            return Err(BuildError::WrongCommunity);
        }
        let worth = spendable_value(&s.note, now).ok_or(BuildError::NoteFromTheFuture)?;
        spent = spent.checked_add(worth).ok_or(BuildError::Overflow)?;
    }
    let mut created = 0u64;
    for o in &outputs {
        created = created.checked_add(o.value).ok_or(BuildError::Overflow)?;
        let memo_matches = match &o.memo_opening {
            Some(m) => crate::memo::verify(&m.text, m.r_memo, o.memo_cm),
            None => o.memo_cm == Base::zero(),
        };
        if !memo_matches {
            return Err(BuildError::MemoMismatch);
        }
    }
    if spent != created {
        return Err(BuildError::Unbalanced { spent, created });
    }

    // pad both sides with dummies
    let mut spends: Vec<(SpendInfo, Option<SpendAuthorizingKey>)> =
        spends.into_iter().map(|s| (s, None)).collect();
    while spends.len() < ACTIONS {
        let (spend, ask) = dummy_spend(community, now, rng);
        spends.push((spend, Some(ask)));
    }
    let mut outputs = outputs;
    while outputs.len() < ACTIONS {
        outputs.push(dummy_output(rng));
    }

    let mut circuits = Vec::with_capacity(ACTIONS);
    let mut instances = Vec::with_capacity(ACTIONS);
    let mut actions = Vec::with_capacity(ACTIONS);
    let mut alphas = Vec::with_capacity(ACTIONS);
    let mut rcvs = Vec::with_capacity(ACTIONS);
    let mut dummy_asks = Vec::with_capacity(ACTIONS);
    let mut openings = Vec::with_capacity(ACTIONS);

    for ((spend, dummy_ask), output) in spends.into_iter().zip(outputs) {
        let old = spend.note.note;
        let nf = old.nullifier(spend.fvk.nk);
        let decayed = spendable_value(&spend.note, now).ok_or(BuildError::NoteFromTheFuture)?;

        let out_rseed = RandomSeed::random(rng);
        let new = from_parts(
            community,
            community,
            output.value,
            now,
            output.kind,
            output.expiry_epoch,
            &output.address,
            nf,
            output.memo_cm,
            out_rseed,
        )
        .map_err(BuildError::InvalidNote)?;

        let alpha = pallas::Scalar::random(&mut *rng);
        let rcv = pallas::Scalar::random(&mut *rng);
        let rk = (pallas::Point::from(spend.fvk.ak) + signature::spend_auth_base() * alpha).to_affine();
        let cv_net_point = signature::value_commitment(decayed as i128 - output.value as i128, rcv);
        let cv_net = cv_net_point.to_affine();

        circuits.push(ActionCircuit::new(&old, &spend.fvk, spend.position, spend.path, &new, rcv, alpha));
        let cm = new.commitment();
        instances.push(ActionCircuit::instance(community, anchor, nf, rk, cm, cv_net, now));

        let domain = GradidoDomain { community, coin_community: community, rho: nf };
        let encrypted = encrypt(
            domain,
            &NoteWithSeed { note: new, rseed: out_rseed },
            output.memo,
            ovk,
            cv_net_point,
            rng,
        );
        actions.push(Action { cv_net, nullifier: nf, rk, cm, encrypted });
        openings.push(OutputOpening {
            address: output.address,
            value: output.value,
            kind: output.kind,
            expiry_epoch: output.expiry_epoch,
            rseed: out_rseed,
            memo_cm: output.memo_cm,
            free_memo: output.memo,
            memo: output.memo_opening,
        });
        alphas.push(alpha);
        rcvs.push(rcv);
        dummy_asks.push(dummy_ask);
    }

    let s = setup();
    let instance_refs: Vec<Vec<&[Base]>> = instances.iter().map(|i| vec![i.as_slice()]).collect();
    let instance_refs: Vec<&[&[Base]]> = instance_refs.iter().map(|v| v.as_slice()).collect();
    let mut transcript = Blake2bWrite::<_, vesta::Affine, Challenge255<_>>::init(vec![]);
    create_proof(&s.params, &s.pk, &circuits, &instance_refs, &mut *rng, &mut transcript)
        .map_err(|_| BuildError::Proof)?;

    Ok(UnauthorizedBundle {
        anchor,
        now,
        community,
        actions,
        proof: transcript.finalize(),
        alphas,
        rcvs,
        dummy_asks,
        outputs: openings,
    })
}

/// Public inputs of every action, in proof order.
fn instances(community: Base, anchor: Base, now: u64, actions: &[Action]) -> Vec<Vec<Base>> {
    actions
        .iter()
        .map(|a| ActionCircuit::instance(community, anchor, a.nullifier, a.rk, a.cm, a.cv_net, now))
        .collect()
}

const BODY_SIGHASH_PERSONALIZATION: &[u8; 16] = b"Gradido_BodySigh";

/// The sighash of a transaction: BLAKE2b-256 over `GradidoTransaction.body_bytes`. Spend
/// authorisation and binding signatures cover it; node, server and signing device compute it
/// the same way.
pub fn body_sighash(body_bytes: &[u8]) -> [u8; 32] {
    let hash = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(BODY_SIGHASH_PERSONALIZATION)
        .hash(body_bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_bytes());
    out
}

/// A canonical hash over the effecting data of a bundle: anchor, time, community and actions.
/// Proof and signatures are not covered, as in Orchard — the proof only attests to public inputs
/// that are covered. In a transaction the sighash is the hash of `body_bytes` instead; this is
/// the standalone equivalent.
pub fn sighash(anchor: Base, now: u64, community: Base, actions: &[Action]) -> [u8; 32] {
    let mut state = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(SIGHASH_PERSONALIZATION)
        .to_state();
    state.update(&anchor.to_repr());
    state.update(&now.to_le_bytes());
    state.update(&community.to_repr());
    state.update(&CIRCUIT_VERSION.to_le_bytes());
    for a in actions {
        state.update(&a.cv_net.to_bytes());
        state.update(&a.nullifier.to_repr());
        state.update(&a.rk.to_bytes());
        state.update(&a.cm.to_repr());
        state.update(&a.encrypted.epk_bytes.0);
        state.update(&a.encrypted.enc_ciphertext);
        state.update(&a.encrypted.out_ciphertext);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(state.finalize().as_bytes());
    out
}

impl UnauthorizedBundle {
    pub fn sighash(&self) -> [u8; 32] {
        sighash(self.anchor, self.now, self.community, &self.actions)
    }

    /// The serialised `ShieldedBundle` for the transaction body.
    pub fn shielded_bytes(&self) -> Vec<u8> {
        crate::wire::encode_shielded(self.anchor, &self.actions)
    }

    /// What the signing device needs (`crate::signer`): the body the bundle was put into, the
    /// openings of all created notes, and the rerandomisers of the real spends. Build the bundle
    /// with the owner's `ovk`, or the device cannot check the outgoing ciphertexts.
    pub fn signing_request(&self, body: Vec<u8>) -> SigningRequest {
        SigningRequest {
            body,
            outputs: self.outputs.clone(),
            alphas: (0..self.actions.len())
                .map(|i| self.dummy_asks[i].is_none().then_some(self.alphas[i]))
                .collect(),
        }
    }

    /// Indices of the actions whose spend the device has to sign.
    pub fn real_spends(&self) -> Vec<usize> {
        (0..self.actions.len()).filter(|i| self.dummy_asks[*i].is_none()).collect()
    }

    /// Adds the binding signature and the dummy spend signatures. `device_sigs` holds the
    /// signatures of the real spends, in the order of `real_spends()`; each one is checked, so a
    /// wrong signature from the device is reported here and not only by the node.
    pub fn authorize(
        self,
        sighash: &[u8; 32],
        device_sigs: Vec<Signature<SpendAuth>>,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Bundle, AuthorizeError> {
        let expected = self.real_spends().len();
        if device_sigs.len() != expected {
            return Err(AuthorizeError::SignatureCount { expected, got: device_sigs.len() });
        }
        let mut device_sigs = device_sigs.into_iter();
        let mut spend_auth_sigs = Vec::with_capacity(self.actions.len());
        for i in 0..self.actions.len() {
            let sig = match &self.dummy_asks[i] {
                Some(ask) => signature::sign_spend_auth(ask, self.alphas[i], sighash, &mut *rng),
                None => {
                    let sig = device_sigs.next().expect("count checked above");
                    let rk = reddsa::VerificationKey::<SpendAuth>::try_from(self.actions[i].rk.to_bytes())
                        .map_err(|_| AuthorizeError::BadSignature(i))?;
                    if !signature::verify_spend_auth(&rk, sighash, &sig) {
                        return Err(AuthorizeError::BadSignature(i));
                    }
                    sig
                }
            };
            spend_auth_sigs.push(sig);
        }
        let binding_sig = signature::sign_binding(&self.rcvs, sighash, &mut *rng);
        Ok(Bundle {
            anchor: self.anchor,
            now: self.now,
            community: self.community,
            actions: self.actions,
            proof: self.proof,
            spend_auth_sigs,
            binding_sig,
        })
    }
}

/// Signs one spend with `ask` over a given sighash — blindly. A device must not sign what it has
/// not checked; it uses `signer::sign`, which computes the sighash from the body it reviewed.
/// This stays for tests and for callers that built the transfer themselves.
pub fn sign_spend(
    ask: &SpendAuthorizingKey,
    alpha: pallas::Scalar,
    sighash: &[u8; 32],
    rng: impl RngCore + CryptoRng,
) -> Signature<SpendAuth> {
    signature::sign_spend_auth(ask, alpha, sighash, rng)
}

// ------------------------------------------------------------------------------ verification

/// The ledger state a node keeps for one community.
#[derive(Default)]
pub struct Ledger {
    pub tree: CommitmentTree,
    pub anchors: AnchorHistoryWrapper,
    pub nullifiers: NullifierSet,
}

/// `AnchorHistory` with a sensible default size.
pub struct AnchorHistoryWrapper(pub AnchorHistory);

/// Roots a bundle may still use as anchor. At a hundred transactions per second this is about
/// three minutes, enough for building, proving, signing on a device and ordering. The node keeps
/// its own history in LMDB and may choose a time window instead.
pub const ANCHOR_HISTORY: usize = 20_000;

impl Default for AnchorHistoryWrapper {
    fn default() -> Self {
        Self(AnchorHistory::new(ANCHOR_HISTORY))
    }
}

impl Ledger {
    pub fn new() -> Self {
        let mut ledger = Self::default();
        let root = ledger.tree.root();
        ledger.anchors.0.push(root);
        ledger
    }

    /// Adds a note commitment from outside a bundle (creation, migration).
    pub fn add_note(&mut self, cm: Base) -> Result<incrementalmerkletree::Position, VerifyError> {
        let position = self.tree.append(cm, true).ok_or(VerifyError::TreeFull)?;
        self.tree.checkpoint();
        self.anchors.0.push(self.tree.root());
        Ok(position)
    }

    /// Checks a bundle against the current state without changing it. `sighash` is what the
    /// signatures cover: `Bundle::sighash()` standalone, the hash of `body_bytes` in a transaction.
    pub fn verify(&self, bundle: &Bundle, sighash: &[u8; 32]) -> Result<(), VerifyError> {
        if bundle.actions.len() != ACTIONS || bundle.spend_auth_sigs.len() != ACTIONS {
            return Err(VerifyError::WrongActionCount);
        }
        if !self.tree.has_room_for(ACTIONS) {
            return Err(VerifyError::TreeFull);
        }
        if !self.anchors.0.contains(&bundle.anchor) {
            return Err(VerifyError::UnknownAnchor);
        }
        let nullifiers: Vec<Base> = bundle.actions.iter().map(|a| a.nullifier).collect();
        let mut probe = NullifierSet::default();
        probe.insert_all(&nullifiers).map_err(VerifyError::DoubleSpend)?;
        for nf in &nullifiers {
            if self.nullifiers.contains(nf) {
                return Err(VerifyError::DoubleSpend(DoubleSpend(nf.to_repr())));
            }
        }
        verify_bundle_crypto(bundle, sighash)
    }

    /// Verifies and, if valid, applies the bundle: nullifiers spent, new notes in the tree.
    /// Every check runs in `verify`, so nothing below can fail halfway.
    pub fn apply(&mut self, bundle: &Bundle, sighash: &[u8; 32]) -> Result<(), VerifyError> {
        self.verify(bundle, sighash)?;
        let nullifiers: Vec<Base> = bundle.actions.iter().map(|a| a.nullifier).collect();
        self.nullifiers.insert_all(&nullifiers).map_err(VerifyError::DoubleSpend)?;
        for action in &bundle.actions {
            self.tree.append(action.cm, false).expect("room checked in verify");
        }
        self.tree.checkpoint();
        self.anchors.0.push(self.tree.root());
        Ok(())
    }
}

impl Bundle {
    /// The standalone sighash, when there is no transaction body around the bundle.
    pub fn sighash(&self) -> [u8; 32] {
        sighash(self.anchor, self.now, self.community, &self.actions)
    }

    pub fn nullifiers(&self) -> Vec<Base> {
        self.actions.iter().map(|a| a.nullifier).collect()
    }
}

/// Proof and signatures only — everything that does not need the ledger state. The signatures
/// are checked first: they are cheaper than the proof.
pub fn verify_bundle_crypto(bundle: &Bundle, sighash: &[u8; 32]) -> Result<(), VerifyError> {
    if bundle.actions.len() != ACTIONS || bundle.spend_auth_sigs.len() != ACTIONS {
        return Err(VerifyError::WrongActionCount);
    }
    if bundle.proof.len() != PROOF_SIZE {
        return Err(VerifyError::Proof);
    }
    for (i, (action, sig)) in bundle.actions.iter().zip(&bundle.spend_auth_sigs).enumerate() {
        if bool::from(action.rk.is_identity()) {
            return Err(VerifyError::SpendAuth(i));
        }
        let rk = reddsa::VerificationKey::<SpendAuth>::try_from(action.rk.to_bytes())
            .map_err(|_| VerifyError::SpendAuth(i))?;
        if !signature::verify_spend_auth(&rk, sighash, sig) {
            return Err(VerifyError::SpendAuth(i));
        }
    }
    let cvs: Vec<pallas::Point> = bundle.actions.iter().map(|a| a.cv_net.into()).collect();
    let bvk = signature::binding_verification_key(&cvs, 0).ok_or(VerifyError::Binding)?;
    if !signature::verify_binding(&bvk, sighash, &bundle.binding_sig) {
        return Err(VerifyError::Binding);
    }

    let s = setup();
    let instances = instances(bundle.community, bundle.anchor, bundle.now, &bundle.actions);
    let instance_refs: Vec<Vec<&[Base]>> = instances.iter().map(|i| vec![i.as_slice()]).collect();
    let instance_refs: Vec<&[&[Base]]> = instance_refs.iter().map(|v| v.as_slice()).collect();
    let mut transcript = Blake2bRead::<_, vesta::Affine, Challenge255<_>>::init(&bundle.proof[..]);
    verify_proof(&s.params, &s.vk, SingleVerifier::new(&s.params), &instance_refs, &mut transcript)
        .map_err(|_| VerifyError::Proof)
}
