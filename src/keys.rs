//! Keys and addresses, in the shape privacy_todo.md E5 needs: the community server holds the
//! full viewing key and can prove and decrypt, the user's device holds `ask` and can only
//! authorise spending.
//!
//! ```text
//! sk ──┬─ ask ─── ak            spend authorisation (RedPallas), only ak enters the proof
//!      ├─ nk                    nullifier key, in the proof
//!      ├─ rivk ─┬─ ivk          incoming viewing key, in the proof: pk_d = [ivk] g_d
//!      └─ ovk               ┘   outgoing viewing key, recovers own outgoing notes
//! ```
//!
//! Same structure as Orchard, with two deliberate differences: `ivk` is a Poseidon commitment
//! rather than a Sinsemilla one (as everywhere else here, see `crate::note`), and the
//! diversifier hash uses a Gradido personalisation.

use blake2b_simd::Params as Blake2bParams;
use ff::{Field, FromUniformBytes, PrimeField};
use group::{prime::PrimeCurveAffine, Curve, Group, GroupEncoding};
use pasta_curves::arithmetic::CurveExt;
use halo2_gadgets::poseidon::primitives::{ConstantLength, Hash, P128Pow5T3};
use pasta_curves::pallas;
use rand::{CryptoRng, RngCore};

pub const PRF_EXPAND_PERSONALIZATION: &[u8; 16] = b"Gradido_ExpandSd";
pub const DIVERSIFY_HASH_PERSONALIZATION: &str = "Gradido_gd";
pub const MONTHLY_DIVERSIFIER_PERSONALIZATION: &[u8; 16] = b"Gradido_MonthlyD";

/// Diversifier, 11 bytes as in Orchard.
pub type Diversifier = [u8; 11];

fn prf_expand(sk: &[u8; 32], tag: u8) -> [u8; 64] {
    let hash = Blake2bParams::new()
        .hash_length(64)
        .personal(PRF_EXPAND_PERSONALIZATION)
        .to_state()
        .update(sk)
        .update(&[tag])
        .finalize();
    let mut out = [0u8; 64];
    out.copy_from_slice(hash.as_bytes());
    out
}

/// Hash of a diversifier to a curve point, never the identity.
pub fn diversify_hash(d: &Diversifier) -> pallas::Point {
    let point = pallas::Point::hash_to_curve(DIVERSIFY_HASH_PERSONALIZATION)(d);
    if bool::from(point.is_identity()) {
        // cannot happen for the hash we use, but the address would be unusable
        pallas::Point::generator()
    } else {
        point
    }
}

/// What the user has to keep. Everything else is derived from it.
#[derive(Clone, Copy, Debug)]
pub struct SpendingKey([u8; 32]);

/// What the device keeps in the custody split: it can sign, nothing else.
#[derive(Clone, Debug)]
pub struct SpendAuthorizingKey(pub pallas::Scalar);

/// What the community server may hold: prove, decrypt, show balances — but not spend.
#[derive(Clone, Copy, Debug)]
pub struct FullViewingKey {
    /// public part of the spend authorising key, goes into the proof
    pub ak: pallas::Affine,
    /// nullifier key
    pub nk: pallas::Base,
    /// randomness of `ivk`; the proof re-derives `ivk` from `ak`, `nk` and `rivk`
    pub rivk: pallas::Base,
    /// incoming viewing key, used as the scalar in `pk_d = [ivk] g_d`
    pub ivk: pallas::Scalar,
    /// outgoing viewing key, recovers notes the wallet itself sent
    pub ovk: [u8; 32],
}

/// A shielded address: diversifier plus the transmission key derived from it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Address {
    pub d: Diversifier,
    pub pk_d: pallas::Affine,
}

impl SpendingKey {
    pub fn random(rng: &mut (impl RngCore + CryptoRng)) -> Self {
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

    pub fn spend_authorizing_key(&self) -> SpendAuthorizingKey {
        SpendAuthorizingKey(pallas::Scalar::from_uniform_bytes(&prf_expand(&self.0, 0x06)))
    }

    pub fn full_viewing_key(&self) -> FullViewingKey {
        let ask = self.spend_authorizing_key().0;
        // the basepoint of the signature scheme, not the curve generator
        let ak = (crate::signature::spend_auth_base() * ask).to_affine();
        let nk = pallas::Base::from_uniform_bytes(&prf_expand(&self.0, 0x07));
        let mut rivk = pallas::Base::from_uniform_bytes(&prf_expand(&self.0, 0x08));
        // ivk = 0 would make every address the identity; resample rivk deterministically
        let ivk = loop {
            match commit_ivk(ak, nk, rivk) {
                Some(ivk) => break ivk,
                None => rivk = Hash::<_, P128Pow5T3, ConstantLength<1>, 3, 2>::init().hash([rivk]),
            }
        };
        let mut ovk = [0u8; 32];
        ovk.copy_from_slice(&prf_expand(&self.0, 0x09)[..32]);
        FullViewingKey { ak, nk, rivk, ivk, ovk }
    }
}

/// `ivk = Poseidon(ak_x, nk, rivk)`, the same hash the circuit computes; `None` for zero.
///
/// The Poseidon output is a base field element, and on Pallas the base field is the smaller
/// one (p < q), so every output is a valid scalar with the same integer value — which is what
/// `ScalarVar::from_base` in the circuit relies on. Only zero has to be excluded.
pub fn commit_ivk(ak: pallas::Affine, nk: pallas::Base, rivk: pallas::Base) -> Option<pallas::Scalar> {
    use pasta_curves::arithmetic::CurveAffine;
    let ak_x = *Option::<pasta_curves::arithmetic::Coordinates<pallas::Affine>>::from(ak.coordinates())?.x();
    let ivk = Hash::<_, P128Pow5T3, ConstantLength<3>, 3, 2>::init().hash([ak_x, nk, rivk]);
    let scalar = Option::<pallas::Scalar>::from(pallas::Scalar::from_repr(ivk.to_repr()))
        .expect("p < q, every base element is a scalar");
    (!bool::from(scalar.is_zero())).then_some(scalar)
}

/// Length of an encoded full viewing key: `ak | nk | rivk | ovk`, 32 bytes each.
pub const FULL_VIEWING_KEY_BYTES: usize = 128;

impl FullViewingKey {
    /// `ak | nk | rivk | ovk`, what a device hands to its community server. `ivk` is derived
    /// again on decoding, so it cannot be inconsistent with the rest.
    pub fn to_bytes(&self) -> [u8; FULL_VIEWING_KEY_BYTES] {
        let mut out = [0u8; FULL_VIEWING_KEY_BYTES];
        out[..32].copy_from_slice(&self.ak.to_bytes());
        out[32..64].copy_from_slice(&self.nk.to_repr());
        out[64..96].copy_from_slice(&self.rivk.to_repr());
        out[96..].copy_from_slice(&self.ovk);
        out
    }

    /// Rejects non-canonical encodings, an identity `ak` and keys whose `ivk` would be zero.
    pub fn from_bytes(bytes: &[u8; FULL_VIEWING_KEY_BYTES]) -> Option<Self> {
        let ak = Option::<pallas::Affine>::from(pallas::Affine::from_bytes(bytes[..32].try_into().ok()?))?;
        if bool::from(ak.is_identity()) {
            return None;
        }
        let nk = Option::<pallas::Base>::from(pallas::Base::from_repr(bytes[32..64].try_into().ok()?))?;
        let rivk = Option::<pallas::Base>::from(pallas::Base::from_repr(bytes[64..96].try_into().ok()?))?;
        let ivk = commit_ivk(ak, nk, rivk)?;
        let ovk = bytes[96..].try_into().ok()?;
        Some(Self { ak, nk, rivk, ivk, ovk })
    }

    /// The address for a diversifier: `pk_d = [ivk] g_d`.
    pub fn address(&self, d: Diversifier) -> Address {
        Address { d, pk_d: (diversify_hash(&d) * self.ivk).to_affine() }
    }

    /// The default address of an account, diversifier zero.
    pub fn default_address(&self) -> Address {
        self.address([0u8; 11])
    }

    /// Address for one target month (`month` 1 to 12), so creations do not link across months
    /// (E7, E14). Derived from `ivk`, so the community can compute it and the owner recognises
    /// it. `None` for a month outside 1 to 12, which would otherwise alias another month.
    pub fn creation_address(&self, year: u32, month: u32) -> Option<Address> {
        if !(1..=12).contains(&month) {
            return None;
        }
        let hash = Blake2bParams::new()
            .hash_length(11)
            .personal(MONTHLY_DIVERSIFIER_PERSONALIZATION)
            .to_state()
            .update(&self.ivk.to_repr())
            .update(&year.to_le_bytes())
            .update(&[month as u8])
            .finalize();
        let mut d = [0u8; 11];
        d.copy_from_slice(hash.as_bytes());
        Some(self.address(d))
    }

    /// Does this address belong to the key?
    pub fn owns(&self, address: &Address) -> bool {
        self.address(address.d) == *address
    }
}

impl Address {
    /// 43 bytes: diversifier and the compressed transmission key, as in the address encoding.
    pub fn to_raw(self) -> [u8; 43] {
        let mut out = [0u8; 43];
        out[..11].copy_from_slice(&self.d);
        out[11..].copy_from_slice(&self.pk_d.to_bytes());
        out
    }

    pub fn from_raw(raw: &[u8; 43]) -> Option<Self> {
        let mut d = [0u8; 11];
        d.copy_from_slice(&raw[..11]);
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&raw[11..]);
        let pk_d = Option::<pallas::Affine>::from(pallas::Affine::from_bytes(&pk))?;
        if bool::from(pk_d.is_identity()) {
            return None;
        }
        Some(Self { d, pk_d })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    fn key() -> SpendingKey {
        SpendingKey::from_bytes([7u8; 32])
    }

    #[test]
    fn derivation_is_deterministic() {
        let a = key().full_viewing_key();
        let b = key().full_viewing_key();
        assert_eq!(a.ak, b.ak);
        assert_eq!(a.nk, b.nk);
        assert_eq!(a.ivk, b.ivk);
        assert_eq!(a.rivk, b.rivk);
        assert_eq!(commit_ivk(a.ak, a.nk, a.rivk), Some(a.ivk));
        assert_eq!(a.ovk, b.ovk);
    }

    #[test]
    fn different_keys_differ() {
        let mut rng = StdRng::seed_from_u64(1);
        let one = SpendingKey::random(&mut rng).full_viewing_key();
        let two = SpendingKey::random(&mut rng).full_viewing_key();
        assert_ne!(one.ivk, two.ivk);
        assert_ne!(one.default_address(), two.default_address());
    }

    #[test]
    fn address_is_pk_d_of_ivk() {
        let fvk = key().full_viewing_key();
        let address = fvk.address([3u8; 11]);
        assert_eq!(address.pk_d, (diversify_hash(&[3u8; 11]) * fvk.ivk).to_affine());
        assert!(fvk.owns(&address));
    }

    #[test]
    fn diversifiers_give_unlinkable_addresses() {
        let fvk = key().full_viewing_key();
        assert_ne!(fvk.address([1u8; 11]), fvk.address([2u8; 11]));
        // ... but the owner recognises both
        assert!(fvk.owns(&fvk.address([1u8; 11])));
        assert!(fvk.owns(&fvk.address([2u8; 11])));
    }

    #[test]
    fn creation_addresses_change_every_month() {
        let fvk = key().full_viewing_key();
        let march = fvk.creation_address(2026, 3).unwrap();
        let april = fvk.creation_address(2026, 4).unwrap();
        assert_ne!(march, april);
        assert_eq!(march, fvk.creation_address(2026, 3).unwrap());
        assert!(fvk.owns(&march) && fvk.owns(&april));
        // a different account gets a different address for the same month
        let other = SpendingKey::from_bytes([8u8; 32]).full_viewing_key();
        assert_ne!(other.creation_address(2026, 3).unwrap(), march);
        // no aliasing between December and the January after it
        assert_ne!(fvk.creation_address(2026, 12), fvk.creation_address(2027, 0));
        assert!(fvk.creation_address(2027, 0).is_none() && fvk.creation_address(2026, 13).is_none());
    }

    #[test]
    fn viewing_key_round_trip() {
        let fvk = key().full_viewing_key();
        let decoded = FullViewingKey::from_bytes(&fvk.to_bytes()).unwrap();
        assert_eq!(decoded.ivk, fvk.ivk);
        assert_eq!(decoded.default_address(), fvk.default_address());
        let mut broken = fvk.to_bytes();
        broken[..32].copy_from_slice(&[0u8; 32]);
        assert!(FullViewingKey::from_bytes(&broken).is_none(), "identity ak");
        let mut broken = fvk.to_bytes();
        broken[32..64].copy_from_slice(&[0xff; 32]);
        assert!(FullViewingKey::from_bytes(&broken).is_none(), "non-canonical nk");
    }

    #[test]
    fn raw_encoding_round_trip() {
        let address = key().full_viewing_key().default_address();
        assert_eq!(Address::from_raw(&address.to_raw()), Some(address));
    }
}
