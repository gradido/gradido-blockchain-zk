//! What decay costs inside a full action circuit:
//! `cargo run --release --example action_timing`
//!
//! Proves one shielded action (note commitment, Merkle path of depth 32, nullifier, value
//! conservation) with and without the exact decay of unit.c, at the smallest k that fits.

use std::time::{Duration, Instant};

use halo2_proofs::{
    dev::CircuitCost,
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, Error, SingleVerifier},
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use pasta_curves::{pallas, vesta};
use rand::rngs::OsRng;

use gradido_blockchain_zk::circuit::action_slice::sample;
use gradido_blockchain_zk::decay::SECONDS_PER_YEAR;

const PROVE_RUNS: usize = 5;

fn median(mut xs: Vec<Duration>) -> Duration {
    xs.sort();
    xs[xs.len() / 2]
}

fn run<const WITH_DECAY: bool, const WINDOWED: bool>(label: &str, age: u64) {
    let f = sample::fixture::<WITH_DECAY, WINDOWED>(1_000_0000, age, None);

    // the smallest k the circuit fits into: keygen fails with NotEnoughRowsAvailable below it
    let keygen_start = Instant::now();
    let mut k = 11;
    let (params, pk, vk) = loop {
        let params: Params<vesta::Affine> = Params::new(k);
        match keygen_vk(&params, &f.circuit.without_witnesses()) {
            Ok(vk) => {
                let pk = keygen_pk(&params, vk.clone(), &f.circuit.without_witnesses()).expect("keygen_pk");
                break (params, pk, vk);
            }
            Err(Error::NotEnoughRowsAvailable { .. }) => k += 1,
            Err(e) => panic!("keygen failed: {e:?}"),
        }
    };

    let keygen = keygen_start.elapsed();

    let mut times = Vec::new();
    let mut proof = Vec::new();
    for _ in 0..PROVE_RUNS {
        let t = Instant::now();
        let mut transcript = Blake2bWrite::<_, vesta::Affine, Challenge255<_>>::init(vec![]);
        create_proof(&params, &pk, &[f.circuit.clone()], &[&[&f.instance]], OsRng, &mut transcript).expect("prove");
        proof = transcript.finalize();
        times.push(t.elapsed());
    }

    let t = Instant::now();
    let strategy = SingleVerifier::new(&params);
    let mut transcript = Blake2bRead::<_, vesta::Affine, Challenge255<_>>::init(&proof[..]);
    verify_proof(&params, &vk, strategy, &[&[&f.instance]], &mut transcript).expect("verify");
    let verify = t.elapsed();

    // rows the layout actually uses, out of 2^k
    let cost = format!("{:?}", CircuitCost::<vesta::Point, _>::measure(k, &f.circuit));
    let field = |name: &str| -> String {
        cost.split(&format!("{name}: "))
            .nth(1)
            .and_then(|rest| rest.split(&[',', ' '][..]).next())
            .unwrap_or("?")
            .to_string()
    };
    println!(
        "{label:<34} k={k}  rows {:>4}/{}  keygen {:>8.2?}  prove {:>8.2?}  verify {:>7.2?}  proof {} B",
        field("max_rows"),
        1 << k,
        keygen,
        median(times),
        verify,
        proof.len()
    );
}

fn main() {
    let _ = pallas::Base::default();
    println!("one action: note commitment + Merkle path (depth 32) + nullifier + balance");
    println!("prove = median of {PROVE_RUNS} runs, threads = {}", std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1));
    println!();
    run::<false, false>("without decay", 3 * SECONDS_PER_YEAR);
    run::<true, false>("exact decay (unit.c bit chain)", 3 * SECONDS_PER_YEAR);
    run::<true, true>("windowed decay (5 windows)", 3 * SECONDS_PER_YEAR);
    run::<true, true>("windowed decay, note 70 years old", 70 * SECONDS_PER_YEAR);
}
