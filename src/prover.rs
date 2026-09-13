//! Thin wrapper around halo2 keygen / prove / verify.
//!
//! Params and keys are built once and cached; building them costs far more than a proof.

use std::sync::OnceLock;

use ff::{Field, PrimeField};

use halo2_proofs::{
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, ProvingKey, SingleVerifier, VerifyingKey},
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use pasta_curves::{EqAffine, Fp};
use rand::rngs::OsRng;

use crate::circuit::value_balance::{ValueBalanceCircuit, K, N_LIMBS};

pub struct Setup {
    pub params: Params<EqAffine>,
    pub pk: ProvingKey<EqAffine>,
    pub vk: VerifyingKey<EqAffine>,
}

static SETUP: OnceLock<Setup> = OnceLock::new();

/// Build (or fetch) the cached proving/verifying keys.
pub fn setup() -> &'static Setup {
    SETUP.get_or_init(|| {
        let params: Params<EqAffine> = Params::new(K);
        let empty = ValueBalanceCircuit::default();
        let vk = keygen_vk(&params, &empty).expect("keygen_vk");
        let pk = keygen_pk(&params, vk.clone(), &empty).expect("keygen_pk");
        Setup { params, pk, vk }
    })
}

#[derive(Debug)]
pub enum ProveError {
    /// A value is >= 2^VALUE_BITS, so the range check cannot be satisfied.
    ValueOutOfRange,
    /// sum(inputs) != sum(outputs).
    Unbalanced,
    Synthesis(halo2_proofs::plonk::Error),
}

/// halo2's `create_proof` does NOT check that the witness satisfies the gates — it will
/// happily emit a proof that simply fails to verify. Witness validation is the caller's
/// job (`MockProver` does it in tests). For a circuit this small the check is a handful of
/// field ops, so we do it exactly, mirroring the in-circuit constraints. A larger circuit
/// should run `MockProver` behind `debug_assertions` instead.
fn check_witness(inputs: &[Fp], outputs: &[Fp]) -> Result<(), ProveError> {
    // range: the circuit decomposes only the low N_LIMBS bytes, so everything above must be 0
    for v in inputs.iter().chain(outputs.iter()) {
        if v.to_repr()[N_LIMBS..].iter().any(|b| *b != 0) {
            return Err(ProveError::ValueOutOfRange);
        }
    }
    let sum = |xs: &[Fp]| xs.iter().fold(Fp::ZERO, |a, b| a + b);
    if sum(inputs) != sum(outputs) {
        return Err(ProveError::Unbalanced);
    }
    Ok(())
}

/// Produce a proof that `sum(inputs) == sum(outputs)`, bound to `sighash`.
pub fn prove(inputs: [Fp; 2], outputs: [Fp; 2], sighash: Fp) -> Result<Vec<u8>, ProveError> {
    check_witness(&inputs, &outputs)?;
    let s = setup();
    let circuit = ValueBalanceCircuit::new(inputs, outputs, sighash);
    let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(vec![]);
    create_proof(
        &s.params,
        &s.pk,
        &[circuit],
        &[&[&[sighash]]],
        OsRng,
        &mut transcript,
    )
    .map_err(ProveError::Synthesis)?;
    Ok(transcript.finalize())
}

/// Verify a proof against the public `sighash`.
pub fn verify(proof: &[u8], sighash: Fp) -> bool {
    let s = setup();
    let strategy = SingleVerifier::new(&s.params);
    let mut transcript = Blake2bRead::<_, EqAffine, Challenge255<_>>::init(proof);
    verify_proof(&s.params, &s.vk, strategy, &[&[&[sighash]]], &mut transcript).is_ok()
}
