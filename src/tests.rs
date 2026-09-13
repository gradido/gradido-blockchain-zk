use ff::{Field, PrimeField};
use halo2_proofs::circuit::Value;
use halo2_proofs::dev::MockProver;
use pasta_curves::Fp;

use crate::circuit::value_balance::{ValueBalanceCircuit, K, N_IN, N_OUT, VALUE_BITS};
use crate::prover;

fn run_mock(inputs: [Fp; N_IN], outputs: [Fp; N_OUT], sighash: Fp) -> Result<(), ()> {
    let circuit = ValueBalanceCircuit::new(inputs, outputs, sighash);
    let prover = MockProver::run(K, &circuit, vec![vec![sighash]]).map_err(|_| ())?;
    prover.verify().map_err(|_| ())
}

/// 2^VALUE_BITS as a field element — one past the largest legal anchored value.
fn two_pow_value_bits() -> Fp {
    let mut acc = Fp::ONE;
    let two = Fp::from(2u64);
    for _ in 0..VALUE_BITS {
        acc *= two;
    }
    acc
}

#[test]
fn balanced_transfer_satisfies_constraints() {
    let inputs = [Fp::from(700_000u64), Fp::from(300_000u64)];
    let outputs = [Fp::from(999_000u64), Fp::from(1_000u64)];
    assert!(run_mock(inputs, outputs, Fp::from(42u64)).is_ok());
}

#[test]
fn unbalanced_transfer_is_rejected() {
    // one gddCent conjured out of nothing
    let inputs = [Fp::from(700_000u64), Fp::from(300_000u64)];
    let outputs = [Fp::from(999_000u64), Fp::from(1_001u64)];
    assert!(run_mock(inputs, outputs, Fp::from(42u64)).is_err());
}

#[test]
fn value_above_range_is_rejected() {
    // balances in the field, but the values exceed 2^VALUE_BITS, so the range check bites.
    // Without it, a "negative" value could forge money by wrapping around the modulus.
    let big = two_pow_value_bits();
    let inputs = [big, Fp::ZERO];
    let outputs = [big, Fp::ZERO];
    assert!(run_mock(inputs, outputs, Fp::from(7u64)).is_err());
}

#[test]
fn wrong_sighash_is_rejected() {
    let circuit = ValueBalanceCircuit::new(
        [Fp::from(10u64), Fp::from(5u64)],
        [Fp::from(15u64), Fp::ZERO],
        Fp::from(1u64),
    );
    // instance says 2, witness says 1 -> copy constraint fails
    let prover = MockProver::run(K, &circuit, vec![vec![Fp::from(2u64)]]).unwrap();
    assert!(prover.verify().is_err());
}

#[test]
fn missing_witness_shape_matches_keygen() {
    // `without_witnesses` must synthesize with the same shape, or keygen and proving diverge
    let empty = ValueBalanceCircuit::default();
    assert!(matches!(empty.inputs[0], Value { .. }));
}

#[test]
fn real_proof_roundtrip() {
    let inputs = [Fp::from(1_234_567u64), Fp::from(7_654_321u64)];
    let outputs = [Fp::from(8_000_000u64), Fp::from(888_888u64)];
    let sighash = Fp::from(0xdead_beefu64);

    let proof = prover::prove(inputs, outputs, sighash).expect("proving failed");
    assert!(!proof.is_empty());
    println!("proof size: {} bytes", proof.len());
    assert!(prover::verify(&proof, sighash), "verification failed");
    assert!(!prover::verify(&proof, Fp::from(1u64)), "verified under wrong sighash");
}

#[test]
fn ffi_roundtrip() {
    use crate::ffi::*;

    let to_le = |v: u64| Fp::from(v).to_repr();
    let mut ins = Vec::new();
    ins.extend_from_slice(&to_le(500));
    ins.extend_from_slice(&to_le(500));
    let mut outs = Vec::new();
    outs.extend_from_slice(&to_le(999));
    outs.extend_from_slice(&to_le(1));
    let sighash = to_le(0x1234);

    let mut buf = GrdzkBuffer { data: std::ptr::null_mut(), len: 0 };
    let rc = unsafe { grdzk_prove(ins.as_ptr(), 2, outs.as_ptr(), 2, sighash.as_ptr(), &mut buf) };
    assert_eq!(rc, GRDZK_OK, "grdzk_prove returned {rc}");
    assert!(!buf.data.is_null() && buf.len > 0);

    let rc = unsafe { grdzk_verify(buf.data, buf.len, sighash.as_ptr()) };
    assert_eq!(rc, GRDZK_OK, "grdzk_verify returned {rc}");

    unsafe { grdzk_buffer_free(&mut buf) };
    assert!(buf.data.is_null());
}

#[test]
fn prove_rejects_unbalanced_witness() {
    // halo2 itself would emit an unverifiable proof here; our precondition check must catch it
    let err = prover::prove(
        [Fp::from(700_000u64), Fp::from(300_000u64)],
        [Fp::from(999_000u64), Fp::from(1_001u64)],
        Fp::from(1u64),
    );
    assert!(matches!(err, Err(prover::ProveError::Unbalanced)));
}

#[test]
fn prove_rejects_out_of_range_value() {
    let big = two_pow_value_bits();
    let err = prover::prove([big, Fp::ZERO], [big, Fp::ZERO], Fp::from(1u64));
    assert!(matches!(err, Err(prover::ProveError::ValueOutOfRange)));
}

#[test]
fn ffi_rejects_bad_arity_and_null() {
    use crate::ffi::*;
    let v = [0u8; 32];
    let mut buf = GrdzkBuffer { data: std::ptr::null_mut(), len: 0 };
    assert_eq!(
        unsafe { grdzk_prove(v.as_ptr(), 3, v.as_ptr(), 2, v.as_ptr(), &mut buf) },
        GRDZK_ERR_BAD_ARITY
    );
    assert_eq!(
        unsafe { grdzk_prove(std::ptr::null(), 2, v.as_ptr(), 2, v.as_ptr(), &mut buf) },
        GRDZK_ERR_NULL_POINTER
    );
}
