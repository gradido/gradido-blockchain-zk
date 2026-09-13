//! Rough cost measurement: `cargo run --release --example timing`

use std::time::Instant;

use pasta_curves::Fp;

use gradido_blockchain_zk::circuit::value_balance::{K, N_LIMBS, VALUE_BITS};
use gradido_blockchain_zk::prover;

fn main() {
    println!("k = {K}, value bits = {VALUE_BITS}, limbs per value = {N_LIMBS}");

    let t = Instant::now();
    prover::setup();
    println!("setup (params + keygen): {:?}", t.elapsed());

    let inputs = [Fp::from(1_234_567u64), Fp::from(7_654_321u64)];
    let outputs = [Fp::from(8_000_000u64), Fp::from(888_888u64)];
    let sighash = Fp::from(0xdead_beefu64);

    let t = Instant::now();
    let proof = prover::prove(inputs, outputs, sighash).expect("prove");
    let prove_time = t.elapsed();

    let t = Instant::now();
    let ok = prover::verify(&proof, sighash);
    let verify_time = t.elapsed();

    println!("prove:  {prove_time:?}");
    println!("verify: {verify_time:?} (ok = {ok})");
    println!("proof:  {} bytes", proof.len());
}
