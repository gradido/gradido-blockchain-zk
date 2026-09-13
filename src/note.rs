//! The shielded note (privacy_todo.md E4) and the two hashes over it.
//!
//! Both the commitment and the nullifier use Poseidon over field elements, not Sinsemilla over
//! bits. That is a deliberate departure from Orchard: Sinsemilla hashes a bit string, so every
//! field of the note has to be decomposed and checked for canonicity before it can be bound to
//! the cells the rest of the circuit uses — that is what orchard's 2000 line NoteCommit chip
//! does. Poseidon takes field elements as they are, so the same cell that carries the value
//! into the decay gadget also goes into the commitment. Nothing can drift apart.
//!
//! ```text
//! cm = Poseidon(community, coin_community, value|t_note, kind|expiry,
//!               g_d_x, g_d_y, pk_d_x, pk_d_y, rho, psi, memo_cm, rcm)
//! nf = Poseidon(nk, rho, cm)
//! ```
//!
//! Field packing keeps every element well below the modulus, so the encoding is unambiguous:
//!
//! | element | contents | bits |
//! |---|---|---|
//! | `community` | community id | 128 |
//! | `coin_community` | id of the coin's home community | 128 |
//! | `amount` | `value` (63) and `t_note` (40) | 103 |
//! | `meta` | `note_kind` (1) and `expiry_epoch` (16) | 17 |
//! | `g_d_x`, `g_d_y`, `pk_d_x`, `pk_d_y`, `rho`, `psi`, `memo_cm`, `rcm` | one field element each | 255 |
//!
//! The commitment binds `g_d`, not the diversifier `d`, as Orchard does. The circuit proves
//! `pk_d = [ivk] g_d`; if `g_d` were free, anyone who knows a note could pick `g_d = pk_d` and
//! `ivk = 1` and spend it. The diversifier itself travels only in the encrypted plaintext.

use ff::PrimeField;
use halo2_gadgets::poseidon::primitives::{ConstantLength, Hash, P128Pow5T3};
use pasta_curves::pallas;

pub type Base = pallas::Base;

/// Number of field elements in the commitment.
pub const COMMIT_ELEMENTS: usize = 12;

/// Bit widths of the packed parts, least significant first. A value is a non-negative int64
/// GradidoUnit as in unit.c, so 63 bits.
pub const VALUE_BITS: u32 = 63;
pub const TIMESTAMP_BITS: u32 = 40;
pub const NOTE_KIND_BITS: u32 = 1;
pub const EXPIRY_BITS: u32 = 16;

/// A note field outside the width the circuit can prove.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoteError {
    ValueTooLarge,
    TimestampTooLarge,
    ExpiryTooLarge,
    /// the transmission key is the identity, no key can own such an address
    InvalidAddress,
}

/// What a note is spent as; a deferred note carries a time lock (E8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoteKind {
    Normal = 0,
    Deferred = 1,
}

#[derive(Clone, Copy, Debug)]
pub struct Note {
    pub community: Base,
    pub coin_community: Base,
    /// nominal GradidoUnit (GDD * 10^4) at `t_note`
    pub value: u64,
    /// seconds, never before DECAY_START_TIME
    pub t_note: u64,
    pub kind: NoteKind,
    pub expiry_epoch: u64,
    /// diversifier of the address; not committed, `g_d` is
    pub d: u128,
    /// `g_d = diversify_hash(d)`, both coordinates
    pub g_d_x: Base,
    pub g_d_y: Base,
    /// the address point, both coordinates; no sign bit, so the circuit needs no parity check
    pub pk_d_x: Base,
    pub pk_d_y: Base,
    pub rho: Base,
    pub psi: Base,
    /// commitment to the memo, see E15
    pub memo_cm: Base,
    /// randomness that makes the commitment hiding
    pub rcm: Base,
}

fn two_pow(bits: u32) -> Base {
    let mut acc = Base::one();
    for _ in 0..bits {
        acc = acc.double();
    }
    acc
}

/// `value + t_note * 2^63`
pub fn pack_amount(value: u64, t_note: u64) -> Base {
    Base::from(value) + Base::from(t_note) * two_pow(VALUE_BITS)
}

/// `kind + expiry * 2^1`
pub fn pack_meta(kind: NoteKind, expiry_epoch: u64) -> Base {
    Base::from(kind as u64) + Base::from(expiry_epoch) * two_pow(NOTE_KIND_BITS)
}

impl Note {
    /// The field elements the commitment hashes, in circuit order.
    pub fn commit_elements(&self) -> [Base; COMMIT_ELEMENTS] {
        [
            self.community,
            self.coin_community,
            pack_amount(self.value, self.t_note),
            pack_meta(self.kind, self.expiry_epoch),
            self.g_d_x,
            self.g_d_y,
            self.pk_d_x,
            self.pk_d_y,
            self.rho,
            self.psi,
            self.memo_cm,
            self.rcm,
        ]
    }

    pub fn commitment(&self) -> Base {
        commit(self.commit_elements())
    }

    /// `nf = Poseidon(nk, rho, cm)`; unique because `rho` is the nullifier of the note that was
    /// spent to create this one.
    pub fn nullifier(&self, nk: Base) -> Base {
        nullifier(nk, self.rho, self.commitment())
    }
}

/// The seed every per-note random value is derived from, so a receiver who learns `rseed` and
/// `rho` can rebuild the note. Same idea as Orchard's `RandomSeed`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RandomSeed([u8; 32]);

const RSEED_PERSONALIZATION: &[u8; 16] = b"Gradido_RSeedExp";

impl RandomSeed {
    pub fn random(rng: &mut (impl rand::RngCore + rand::CryptoRng)) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    fn expand(&self, tag: u8, rho: Base) -> [u8; 64] {
        let hash = blake2b_simd::Params::new()
            .hash_length(64)
            .personal(RSEED_PERSONALIZATION)
            .to_state()
            .update(&self.0)
            .update(&[tag])
            .update(&rho.to_repr())
            .finalize();
        let mut out = [0u8; 64];
        out.copy_from_slice(hash.as_bytes());
        out
    }

    /// ephemeral secret key of the note encryption
    pub fn esk(&self, rho: Base) -> pallas::Scalar {
        <pallas::Scalar as ff::FromUniformBytes<64>>::from_uniform_bytes(&self.expand(0x04, rho))
    }

    /// `psi`, which goes into the commitment
    pub fn psi(&self, rho: Base) -> Base {
        <Base as ff::FromUniformBytes<64>>::from_uniform_bytes(&self.expand(0x09, rho))
    }

    /// `rcm`, the randomness that makes the commitment hiding
    pub fn rcm(&self, rho: Base) -> Base {
        <Base as ff::FromUniformBytes<64>>::from_uniform_bytes(&self.expand(0x05, rho))
    }
}

/// Everything a note needs besides what the transaction already fixes. Fails for fields the
/// circuit could never open, so such a note is never committed in the first place.
#[allow(clippy::too_many_arguments)]
pub fn from_parts(
    community: Base,
    coin_community: Base,
    value: u64,
    t_note: u64,
    kind: NoteKind,
    expiry_epoch: u64,
    address: &crate::keys::Address,
    rho: Base,
    memo_cm: Base,
    rseed: RandomSeed,
) -> Result<Note, NoteError> {
    use group::Curve;
    use pasta_curves::arithmetic::CurveAffine;
    if value >= 1 << VALUE_BITS {
        return Err(NoteError::ValueTooLarge);
    }
    if t_note >= 1 << TIMESTAMP_BITS {
        return Err(NoteError::TimestampTooLarge);
    }
    if expiry_epoch >= 1 << EXPIRY_BITS {
        return Err(NoteError::ExpiryTooLarge);
    }
    type Coordinates = pasta_curves::arithmetic::Coordinates<pallas::Affine>;
    let pk_d = Option::<Coordinates>::from(address.pk_d.coordinates()).ok_or(NoteError::InvalidAddress)?;
    let g_d = Option::<Coordinates>::from(crate::keys::diversify_hash(&address.d).to_affine().coordinates())
        .ok_or(NoteError::InvalidAddress)?;
    Ok(Note {
        community,
        coin_community,
        value,
        t_note,
        kind,
        expiry_epoch,
        d: u128::from_le_bytes({
            let mut b = [0u8; 16];
            b[..11].copy_from_slice(&address.d);
            b
        }),
        g_d_x: *g_d.x(),
        g_d_y: *g_d.y(),
        pk_d_x: *pk_d.x(),
        pk_d_y: *pk_d.y(),
        rho,
        psi: rseed.psi(rho),
        memo_cm,
        rcm: rseed.rcm(rho),
    })
}

/// `rho` of a public creation, from its position in the commitment tree.
///
/// A created note in a transfer takes the nullifier of the spent note as `rho`, which is unique.
/// A creation spends nothing, so its `rho` comes from the one thing no other note shares: its
/// leaf position. Two creations with identical public fields therefore still get different
/// commitments and different nullifiers — otherwise the second one could never be spent. The
/// personalisation keeps it apart from every nullifier.
pub fn creation_rho(community: Base, position: u64) -> Base {
    let hash = blake2b_simd::Params::new()
        .hash_length(64)
        .personal(b"Gradido_CreatRho")
        .to_state()
        .update(&community.to_repr())
        .update(&position.to_le_bytes())
        .finalize();
    <Base as ff::FromUniformBytes<64>>::from_uniform_bytes(hash.as_array())
}

pub fn commit(elements: [Base; COMMIT_ELEMENTS]) -> Base {
    Hash::<_, P128Pow5T3, ConstantLength<COMMIT_ELEMENTS>, 3, 2>::init().hash(elements)
}

pub fn nullifier(nk: Base, rho: Base, cm: Base) -> Base {
    Hash::<_, P128Pow5T3, ConstantLength<3>, 3, 2>::init().hash([nk, rho, cm])
}
