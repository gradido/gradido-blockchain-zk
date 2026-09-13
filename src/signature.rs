//! Value commitment and the two signatures around a shielded transfer, on RedPallas (`reddsa`).
//!
//! * **Spend authorisation.** The proof shows a rerandomised key `rk = ak + [alpha] G`; the
//!   signature under `rsk = ask + alpha` proves that whoever holds `ask` agreed. This is the
//!   custody split of E5: the community server can build the proof from `ak`, only the device
//!   can produce this signature.
//! * **Binding signature.** Every action publishes `cv = [v] V + [rcv] R`. If the values add up,
//!   the sum of all `cv` minus the public value balance is `[sum rcv] R`, so a signature under
//!   `sum rcv` proves the transfer balances — without revealing a single amount.

use ff::PrimeField;
use group::{Curve, Group, GroupEncoding};
use pasta_curves::{arithmetic::CurveExt, pallas};
use rand::{CryptoRng, RngCore};
use reddsa::{
    orchard::{Binding, SpendAuth},
    Signature, SigningKey, VerificationKey,
};

use crate::keys::SpendAuthorizingKey;

pub const VALUE_COMMIT_PERSONALIZATION: &str = "Gradido_cv";

/// Basepoint of the spend authorisation signature. `reddsa` fixes this point for its Orchard
/// `SpendAuth` type, so `ak = [ask] SpendAuthG` and `rk = ak + [alpha] SpendAuthG` have to use
/// it as well — it is a nothing-up-my-sleeve point, hashed from a string.
pub fn spend_auth_base() -> pallas::Point {
    pallas::Point::hash_to_curve("z.cash:Orchard")(b"G")
}

/// Generator for the value in a value commitment.
pub fn value_base() -> pallas::Point {
    pallas::Point::hash_to_curve(VALUE_COMMIT_PERSONALIZATION)(b"v")
}

/// Generator for the randomness; the same point `reddsa` uses for Orchard binding signatures,
/// so its `Binding` type can verify our signatures unchanged.
pub fn randomness_base() -> pallas::Point {
    pallas::Point::hash_to_curve("z.cash:Orchard-cv")(b"r")
}

fn to_scalar(value: i128) -> pallas::Scalar {
    if value < 0 {
        -pallas::Scalar::from(value.unsigned_abs() as u64)
    } else {
        pallas::Scalar::from(value as u64)
    }
}

/// `cv = [value] V + [rcv] R`
pub fn value_commitment(value: i128, rcv: pallas::Scalar) -> pallas::Point {
    value_base() * to_scalar(value) + randomness_base() * rcv
}

// ------------------------------------------------------------------ spend authorisation

/// `rk = ak + [alpha] G`, what the proof exposes and the signature is checked against.
pub fn randomized_verification_key(
    ak: pallas::Affine,
    alpha: pallas::Scalar,
) -> VerificationKey<SpendAuth> {
    let rk = pallas::Point::from(ak) + spend_auth_base() * alpha;
    VerificationKey::try_from(rk.to_affine().to_bytes()).expect("rk is a valid point")
}

/// Signs with `rsk = ask + alpha`. Only the device that holds `ask` can do this.
pub fn sign_spend_auth(
    ask: &SpendAuthorizingKey,
    alpha: pallas::Scalar,
    sighash: &[u8; 32],
    rng: impl RngCore + CryptoRng,
) -> Signature<SpendAuth> {
    let rsk = ask.0 + alpha;
    let key = SigningKey::<SpendAuth>::try_from(<[u8; 32]>::from(rsk.to_repr()))
        .expect("rsk is a valid signing key");
    key.sign(rng, sighash)
}

pub fn verify_spend_auth(
    rk: &VerificationKey<SpendAuth>,
    sighash: &[u8; 32],
    signature: &Signature<SpendAuth>,
) -> bool {
    rk.verify(sighash, signature).is_ok()
}

// ------------------------------------------------------------------------ binding signature

/// `bvk = sum(cv) - [value_balance] V`, which equals `[sum rcv] R` exactly when the values add up.
pub fn binding_verification_key(
    cvs: &[pallas::Point],
    value_balance: i128,
) -> Option<VerificationKey<Binding>> {
    let sum = cvs.iter().fold(pallas::Point::identity(), |acc, cv| acc + cv);
    let bvk = sum - value_base() * to_scalar(value_balance);
    VerificationKey::try_from(bvk.to_affine().to_bytes()).ok()
}

/// Signs with `bsk = sum(rcv)`.
pub fn sign_binding(
    rcvs: &[pallas::Scalar],
    sighash: &[u8; 32],
    rng: impl RngCore + CryptoRng,
) -> Signature<Binding> {
    let bsk = rcvs.iter().fold(pallas::Scalar::zero(), |acc, r| acc + r);
    let key = SigningKey::<Binding>::try_from(<[u8; 32]>::from(bsk.to_repr()))
        .expect("bsk is a valid signing key");
    key.sign(rng, sighash)
}

pub fn verify_binding(
    bvk: &VerificationKey<Binding>,
    sighash: &[u8; 32],
    signature: &Signature<Binding>,
) -> bool {
    bvk.verify(sighash, signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::SpendingKey;
    use ff::Field;
    use rand::{rngs::StdRng, SeedableRng};

    const SIGHASH: [u8; 32] = [0x42; 32];

    /// the point we hash must be the one reddsa hard codes
    #[test]
    fn spend_auth_base_matches_reddsa() {
        let ask = pallas::Scalar::from(12345u64);
        let key = SigningKey::<SpendAuth>::try_from(<[u8; 32]>::from(ask.to_repr())).unwrap();
        let from_reddsa = <[u8; 32]>::from(VerificationKey::from(&key));
        assert_eq!(from_reddsa, (spend_auth_base() * ask).to_affine().to_bytes());
    }

    #[test]
    fn spend_auth_round_trip() {
        let mut rng = StdRng::seed_from_u64(3);
        let sk = SpendingKey::from_bytes([5u8; 32]);
        let ask = sk.spend_authorizing_key();
        let ak = sk.full_viewing_key().ak;
        let alpha = pallas::Scalar::random(&mut rng);

        let signature = sign_spend_auth(&ask, alpha, &SIGHASH, &mut rng);
        let rk = randomized_verification_key(ak, alpha);
        assert!(verify_spend_auth(&rk, &SIGHASH, &signature));

        // the same signature under a different rerandomisation, or another message, must fail
        let other = randomized_verification_key(ak, pallas::Scalar::random(&mut rng));
        assert!(!verify_spend_auth(&other, &SIGHASH, &signature));
        assert!(!verify_spend_auth(&rk, &[0x43; 32], &signature));
    }

    #[test]
    fn rerandomisation_hides_the_key() {
        let mut rng = StdRng::seed_from_u64(4);
        let ak = SpendingKey::from_bytes([6u8; 32]).full_viewing_key().ak;
        let one = randomized_verification_key(ak, pallas::Scalar::random(&mut rng));
        let two = randomized_verification_key(ak, pallas::Scalar::random(&mut rng));
        assert_ne!(<[u8; 32]>::from(one), <[u8; 32]>::from(two));
    }

    #[test]
    fn binding_signature_proves_the_values_add_up() {
        let mut rng = StdRng::seed_from_u64(5);
        // one note of 1000 spent, 400 and 600 created: the balance is zero
        let rcvs = [
            pallas::Scalar::random(&mut rng),
            pallas::Scalar::random(&mut rng),
            pallas::Scalar::random(&mut rng),
        ];
        let cvs = [
            value_commitment(1000, rcvs[0]),
            value_commitment(-400, rcvs[1]),
            value_commitment(-600, rcvs[2]),
        ];
        let signature = sign_binding(&rcvs, &SIGHASH, &mut rng);
        let bvk = binding_verification_key(&cvs, 0).expect("valid bvk");
        assert!(verify_binding(&bvk, &SIGHASH, &signature));
    }

    #[test]
    fn binding_signature_catches_conjured_value() {
        let mut rng = StdRng::seed_from_u64(6);
        let rcvs = [pallas::Scalar::random(&mut rng), pallas::Scalar::random(&mut rng)];
        // 1000 in, 1001 out
        let cvs = [value_commitment(1000, rcvs[0]), value_commitment(-1001, rcvs[1])];
        let signature = sign_binding(&rcvs, &SIGHASH, &mut rng);
        let bvk = binding_verification_key(&cvs, 0).expect("valid bvk");
        assert!(!verify_binding(&bvk, &SIGHASH, &signature));
    }

    #[test]
    fn binding_signature_catches_a_tampered_commitment() {
        let mut rng = StdRng::seed_from_u64(7);
        let rcvs = [pallas::Scalar::random(&mut rng), pallas::Scalar::random(&mut rng)];
        let mut cvs = [value_commitment(500, rcvs[0]), value_commitment(-500, rcvs[1])];
        let signature = sign_binding(&rcvs, &SIGHASH, &mut rng);
        cvs[1] = value_commitment(-499, rcvs[1]);
        let bvk = binding_verification_key(&cvs, 0).expect("valid bvk");
        assert!(!verify_binding(&bvk, &SIGHASH, &signature));
    }
}
