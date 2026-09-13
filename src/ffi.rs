//! C ABI for gradido_blockchain. Mirrors the style of `iota_rust_clib`.
//!
//! All entry points are panic-safe: a Rust panic is caught and turned into an error
//! code instead of unwinding across the FFI boundary (which would be UB).
//!
//! Byte arrays are passed as pointer and length. A null pointer is rejected even for length 0,
//! and a length above `isize::MAX` is rejected, since no allocation can be that large.

use std::os::raw::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

use ff::PrimeField;
use pasta_curves::Fp;

use crate::circuit::value_balance::{N_IN, N_OUT};
use crate::prover;

/// Field elements cross the boundary as 32-byte little-endian, matching `Fp::to_repr`.
pub const GRDZK_VALUE_BYTES: usize = 32;

pub const GRDZK_OK: i32 = 0;
pub const GRDZK_ERR_NULL_POINTER: i32 = -1;
pub const GRDZK_ERR_BAD_ARITY: i32 = -2;
pub const GRDZK_ERR_BAD_VALUE: i32 = -3;
pub const GRDZK_ERR_PROVE_FAILED: i32 = -4;
pub const GRDZK_ERR_VERIFY_FAILED: i32 = -5;
pub const GRDZK_ERR_UNBALANCED: i32 = -6;
pub const GRDZK_ERR_VALUE_RANGE: i32 = -7;
pub const GRDZK_ERR_PANIC: i32 = -99;

/// Owned byte buffer handed to C. Release with `grdzk_buffer_free`.
#[repr(C)]
pub struct GrdzkBuffer {
    pub data: *mut u8,
    pub len: usize,
}

impl GrdzkBuffer {
    fn empty() -> Self {
        Self { data: ptr::null_mut(), len: 0 }
    }
    /// Hands the bytes over as a boxed slice, so `grdzk_buffer_free` knows the exact allocation.
    fn from_vec(v: Vec<u8>) -> Self {
        let boxed = v.into_boxed_slice();
        let len = boxed.len();
        let data = Box::into_raw(boxed) as *mut u8;
        Self { data, len }
    }
}

/// Decode a 32-byte little-endian field element. Rejects values >= the field modulus.
fn field_from_bytes(raw: &[u8]) -> Option<Fp> {
    let mut repr = [0u8; GRDZK_VALUE_BYTES];
    repr.copy_from_slice(raw);
    Option::<Fp>::from(Fp::from_repr(repr))
}

/// Library version string, valid for the lifetime of the process.
#[no_mangle]
pub extern "C" fn grdzk_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr() as *const c_char
}

/// Build the proving/verifying keys up front. Optional — the first prove/verify does it
/// lazily — but it lets the caller pay the cost at a controlled moment.
#[no_mangle]
pub extern "C" fn grdzk_init() -> i32 {
    match catch_unwind(|| {
        prover::setup();
    }) {
        Ok(()) => GRDZK_OK,
        Err(_) => GRDZK_ERR_PANIC,
    }
}

/// Prove `sum(inputs) == sum(outputs)` in anchored units, bound to `sighash`.
///
/// `inputs`/`outputs` are `n_in`/`n_out` consecutive 32-byte little-endian values.
/// `sighash` is 32 bytes little-endian. On success `out` owns a buffer the caller
/// must release with `grdzk_buffer_free`.
#[no_mangle]
pub unsafe extern "C" fn grdzk_prove(
    inputs: *const u8,
    n_in: usize,
    outputs: *const u8,
    n_out: usize,
    sighash: *const u8,
    out: *mut GrdzkBuffer,
) -> i32 {
    if inputs.is_null() || outputs.is_null() || sighash.is_null() || out.is_null() {
        return GRDZK_ERR_NULL_POINTER;
    }
    if n_in != N_IN || n_out != N_OUT {
        return GRDZK_ERR_BAD_ARITY;
    }
    *out = GrdzkBuffer::empty();

    let in_slice = std::slice::from_raw_parts(inputs, n_in * GRDZK_VALUE_BYTES);
    let out_slice = std::slice::from_raw_parts(outputs, n_out * GRDZK_VALUE_BYTES);
    let sig_slice = std::slice::from_raw_parts(sighash, GRDZK_VALUE_BYTES);

    let result = catch_unwind(AssertUnwindSafe(|| {
        let mut ins = [Fp::zero(); N_IN];
        for (i, slot) in ins.iter_mut().enumerate() {
            *slot = field_from_bytes(&in_slice[i * GRDZK_VALUE_BYTES..(i + 1) * GRDZK_VALUE_BYTES])?;
        }
        let mut outs = [Fp::zero(); N_OUT];
        for (i, slot) in outs.iter_mut().enumerate() {
            *slot = field_from_bytes(&out_slice[i * GRDZK_VALUE_BYTES..(i + 1) * GRDZK_VALUE_BYTES])?;
        }
        let sig = field_from_bytes(sig_slice)?;
        Some((ins, outs, sig))
    }));

    let (ins, outs, sig) = match result {
        Err(_) => return GRDZK_ERR_PANIC,
        Ok(None) => return GRDZK_ERR_BAD_VALUE,
        Ok(Some(v)) => v,
    };

    match catch_unwind(AssertUnwindSafe(|| prover::prove(ins, outs, sig))) {
        Err(_) => GRDZK_ERR_PANIC,
        Ok(Err(prover::ProveError::Unbalanced)) => GRDZK_ERR_UNBALANCED,
        Ok(Err(prover::ProveError::ValueOutOfRange)) => GRDZK_ERR_VALUE_RANGE,
        Ok(Err(prover::ProveError::Synthesis(_))) => GRDZK_ERR_PROVE_FAILED,
        Ok(Ok(proof)) => {
            *out = GrdzkBuffer::from_vec(proof);
            GRDZK_OK
        }
    }
}

/// Verify a proof produced by `grdzk_prove`.
#[no_mangle]
pub unsafe extern "C" fn grdzk_verify(proof: *const u8, proof_len: usize, sighash: *const u8) -> i32 {
    if proof.is_null() || sighash.is_null() {
        return GRDZK_ERR_NULL_POINTER;
    }
    let proof_slice = std::slice::from_raw_parts(proof, proof_len);
    let sig_slice = std::slice::from_raw_parts(sighash, GRDZK_VALUE_BYTES);

    match catch_unwind(AssertUnwindSafe(|| {
        let sig = field_from_bytes(sig_slice)?;
        Some(prover::verify(proof_slice, sig))
    })) {
        Err(_) => GRDZK_ERR_PANIC,
        Ok(None) => GRDZK_ERR_BAD_VALUE,
        Ok(Some(true)) => GRDZK_OK,
        Ok(Some(false)) => GRDZK_ERR_VERIFY_FAILED,
    }
}

/// Release a buffer returned by `grdzk_prove`. Safe to call on an already-empty buffer.
#[no_mangle]
pub unsafe extern "C" fn grdzk_buffer_free(buf: *mut GrdzkBuffer) {
    if buf.is_null() || (*buf).data.is_null() {
        return;
    }
    drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut((*buf).data, (*buf).len)));
    (*buf).data = ptr::null_mut();
    (*buf).len = 0;
}

// ================================================================== shielded transfers
//
// What the node needs, in the order it needs it:
//   1. grdzk_bundle_verify   — proof and signatures of a shielded transfer
//   2. grdzk_tree_*          — the note commitment tree, whose roots are the valid anchors
//   3. grdzk_creation_commitment — the note commitment of a public creation (E7)
//
// Anchor history and nullifier set stay in the node, in LMDB. It takes anchor, nullifiers and
// note commitments from what grdzk_bundle_verify returns, not from its own protobuf parser, so
// what the node checks and appends is exactly what the proof covered.

use crate::bundle;
use crate::keys::Address;
use crate::note::{creation_rho, from_parts, NoteKind, RandomSeed};
use crate::tree::CommitmentTree;
use crate::wire;

pub const GRDZK_ERR_WIRE: i32 = -10;
pub const GRDZK_ERR_PROOF: i32 = -11;
pub const GRDZK_ERR_SPEND_AUTH: i32 = -12;
pub const GRDZK_ERR_BINDING: i32 = -13;
pub const GRDZK_ERR_BAD_ADDRESS: i32 = -14;
pub const GRDZK_ERR_TREE_FULL: i32 = -15;

unsafe fn slice<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if ptr.is_null() || len > isize::MAX as usize {
        None
    } else {
        Some(std::slice::from_raw_parts(ptr, len))
    }
}

unsafe fn array32(ptr: *const u8) -> Option<[u8; 32]> {
    slice(ptr, 32).map(|s| s.try_into().unwrap())
}

/// Build the keys of the shielded transfer circuit up front (about a second).
#[no_mangle]
pub extern "C" fn grdzk_bundle_init() -> i32 {
    match catch_unwind(|| {
        bundle::setup();
    }) {
        Ok(()) => GRDZK_OK,
        Err(_) => GRDZK_ERR_PANIC,
    }
}

/// Actions per bundle, and the size of what `grdzk_bundle_verify` writes to `out_effects`:
/// the anchor root, then nullifier and note commitment of every action, 32 bytes each.
pub const GRDZK_BUNDLE_ACTIONS: usize = bundle::ACTIONS;
pub const GRDZK_BUNDLE_EFFECTS_SIZE: usize = 32 + 64 * GRDZK_BUNDLE_ACTIONS;

/// Verify proof and signatures of a shielded transfer.
///
/// `shielded`/`authorization` are the serialised `ShieldedBundle` and `ShieldedAuthorization`,
/// exactly as they appear in the transaction (not re-encoded), `community` the 32-byte field
/// element of the transaction's community, `now` its `created_at` in seconds, `sighash` the
/// 32-byte hash the signatures cover.
///
/// On success `out_effects` receives `GRDZK_BUNDLE_EFFECTS_SIZE` bytes:
/// `anchor | nf_0 | cm_0 | nf_1 | cm_1`. The node checks anchor and nullifiers against its
/// state and appends the commitments from there.
#[no_mangle]
pub unsafe extern "C" fn grdzk_bundle_verify(
    shielded: *const u8,
    shielded_len: usize,
    authorization: *const u8,
    authorization_len: usize,
    community: *const u8,
    now: u64,
    sighash: *const u8,
    out_effects: *mut u8,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let (Some(body), Some(auth), Some(community), Some(sighash), false) = (
            slice(shielded, shielded_len),
            slice(authorization, authorization_len),
            array32(community),
            array32(sighash),
            out_effects.is_null(),
        ) else {
            return GRDZK_ERR_NULL_POINTER;
        };
        let Some(community) = field_from_bytes(&community) else {
            return GRDZK_ERR_BAD_VALUE;
        };
        let Ok(bundle) = wire::decode(body, auth, community, now) else {
            return GRDZK_ERR_WIRE;
        };
        match bundle::verify_bundle_crypto(&bundle, &sighash) {
            Ok(()) => {
                let mut effects = Vec::with_capacity(GRDZK_BUNDLE_EFFECTS_SIZE);
                effects.extend_from_slice(&bundle.anchor.to_repr());
                for action in &bundle.actions {
                    effects.extend_from_slice(&action.nullifier.to_repr());
                    effects.extend_from_slice(&action.cm.to_repr());
                }
                std::ptr::copy_nonoverlapping(effects.as_ptr(), out_effects, GRDZK_BUNDLE_EFFECTS_SIZE);
                GRDZK_OK
            }
            Err(bundle::VerifyError::Proof) => GRDZK_ERR_PROOF,
            Err(bundle::VerifyError::SpendAuth(_)) => GRDZK_ERR_SPEND_AUTH,
            Err(bundle::VerifyError::Binding) => GRDZK_ERR_BINDING,
            Err(_) => GRDZK_ERR_VERIFY_FAILED,
        }
    }));
    result.unwrap_or(GRDZK_ERR_PANIC)
}

/// The sighash of a transaction, BLAKE2b-256 over `body_bytes` (`bundle::body_sighash`): what
/// the node passes to `grdzk_bundle_verify`, and what the signing device signed.
#[no_mangle]
pub unsafe extern "C" fn grdzk_body_sighash(body: *const u8, body_len: usize, out: *mut u8) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let (Some(body), false) = (slice(body, body_len), out.is_null()) else {
            return GRDZK_ERR_NULL_POINTER;
        };
        let hash = bundle::body_sighash(body);
        std::ptr::copy_nonoverlapping(hash.as_ptr(), out, 32);
        GRDZK_OK
    }));
    result.unwrap_or(GRDZK_ERR_PANIC)
}

/// Opaque note commitment tree.
pub struct GrdzkTree(CommitmentTree);

/// A new, empty tree. Release with `grdzk_tree_free`. The tree lives in memory; a node rebuilds
/// it at startup by appending the stored commitments in order.
#[no_mangle]
pub extern "C" fn grdzk_tree_new() -> *mut GrdzkTree {
    catch_unwind(|| Box::into_raw(Box::new(GrdzkTree(CommitmentTree::default()))))
        .unwrap_or(ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "C" fn grdzk_tree_free(tree: *mut GrdzkTree) {
    if !tree.is_null() {
        drop(Box::from_raw(tree));
    }
}

/// Append one 32-byte note commitment.
#[no_mangle]
pub unsafe extern "C" fn grdzk_tree_append(tree: *mut GrdzkTree, cm: *const u8) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let (Some(tree), Some(cm)) = (tree.as_mut(), array32(cm)) else {
            return GRDZK_ERR_NULL_POINTER;
        };
        let Some(cm) = field_from_bytes(&cm) else {
            return GRDZK_ERR_BAD_VALUE;
        };
        match tree.0.append(cm, false) {
            Some(_) => GRDZK_OK,
            None => GRDZK_ERR_TREE_FULL,
        }
    }));
    result.unwrap_or(GRDZK_ERR_PANIC)
}

/// Seal the tree after a transaction; call once per confirmed transaction.
#[no_mangle]
pub unsafe extern "C" fn grdzk_tree_checkpoint(tree: *mut GrdzkTree) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| match tree.as_mut() {
        Some(tree) => {
            tree.0.checkpoint();
            GRDZK_OK
        }
        None => GRDZK_ERR_NULL_POINTER,
    }));
    result.unwrap_or(GRDZK_ERR_PANIC)
}

/// Current root, 32 bytes into `out`. Valid anchors are the roots after each checkpoint.
#[no_mangle]
pub unsafe extern "C" fn grdzk_tree_root(tree: *const GrdzkTree, out: *mut u8) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let (Some(tree), false) = (tree.as_ref(), out.is_null()) else {
            return GRDZK_ERR_NULL_POINTER;
        };
        let root = tree.0.root().to_repr();
        std::ptr::copy_nonoverlapping(root.as_ptr(), out, 32);
        GRDZK_OK
    }));
    result.unwrap_or(GRDZK_ERR_PANIC)
}

/// Number of notes in the tree, which is also the position the next note gets (the `position`
/// of `grdzk_creation_commitment`, `first_note_position` of a confirmed transaction).
#[no_mangle]
pub unsafe extern "C" fn grdzk_tree_size(tree: *const GrdzkTree, out: *mut u64) -> i32 {
    let (Some(tree), false) = (tree.as_ref(), out.is_null()) else {
        return GRDZK_ERR_NULL_POINTER;
    };
    *out = tree.0.size();
    GRDZK_OK
}

/// Note commitment of a public creation (E7): the node computes it from the public fields.
///
/// `address` is the raw 43-byte address (diversifier and compressed pk_d), `position` the leaf
/// position the note gets in the tree (its `rho` is derived from it, `note::creation_rho`),
/// `rseed` and `memo_cm` 32 bytes each as published.
#[no_mangle]
pub unsafe extern "C" fn grdzk_creation_commitment(
    community: *const u8,
    value: u64,
    created_at: u64,
    expiry_epoch: u64,
    address: *const u8,
    position: u64,
    rseed: *const u8,
    memo_cm: *const u8,
    out_cm: *mut u8,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let (Some(community), Some(address), Some(rseed), Some(memo_cm), false) = (
            array32(community),
            slice(address, 43),
            array32(rseed),
            array32(memo_cm),
            out_cm.is_null(),
        ) else {
            return GRDZK_ERR_NULL_POINTER;
        };
        let (Some(community), Some(memo_cm)) = (field_from_bytes(&community), field_from_bytes(&memo_cm)) else {
            return GRDZK_ERR_BAD_VALUE;
        };
        let Some(address) = Address::from_raw(address.try_into().unwrap()) else {
            return GRDZK_ERR_BAD_ADDRESS;
        };
        let note = from_parts(
            community,
            community,
            value,
            created_at,
            NoteKind::Normal,
            expiry_epoch,
            &address,
            creation_rho(community, position),
            memo_cm,
            RandomSeed::from_bytes(rseed),
        );
        let Ok(note) = note else {
            return GRDZK_ERR_BAD_VALUE;
        };
        let cm = note.commitment().to_repr();
        std::ptr::copy_nonoverlapping(cm.as_ptr(), out_cm, 32);
        GRDZK_OK
    }));
    result.unwrap_or(GRDZK_ERR_PANIC)
}
