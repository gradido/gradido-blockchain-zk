//! Cost of three decay strategies in halo2: `cargo run --release --example decay_timing`
//!
//! For each strategy and bundle size: smallest k that fits, keygen, prove (median of runs),
//! verify, proof size. The exact strategy is then proven with very different durations to show
//! that the cost does not depend on them (the circuit shape is fixed).

use std::time::{Duration, Instant};

use ff::PrimeField;
use halo2_proofs::{
    dev::MockProver,
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, ConstraintSystem, SingleVerifier},
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use pasta_curves::{EqAffine, Fp};
use rand::rngs::OsRng;

use gradido_blockchain_zk::circuit::decay_bench::{
    effective_value, mode_name, rows_per_input, DecayBenchCircuit, MODE_ANCHORED, MODE_EPOCH,
    MODE_EXACT,
};
use gradido_blockchain_zk::decay::SECONDS_PER_YEAR;

const PROVE_RUNS: usize = 5;
// far enough in the future for notes of 70 years
const NOW: u64 = 10_000_000_000;
const SIGHASH: u64 = 0xdead_beef;

struct Row {
    label: String,
    k: u32,
    degree: usize,
    keygen: Duration,
    prove: Duration,
    verify: Duration,
    proof_len: usize,
}

fn median(mut xs: Vec<Duration>) -> Duration {
    xs.sort();
    xs[xs.len() / 2]
}

fn min_k<C: Circuit<Fp>>(circuit: &C, instance: &[Fp]) -> u32 {
    for k in 7..=16 {
        if let Ok(prover) = MockProver::run(k, circuit, vec![instance.to_vec()]) {
            prover.verify().expect("witness does not satisfy the circuit");
            return k;
        }
    }
    panic!("circuit needs k > 16");
}

/// `k = None` picks the smallest k that fits.
fn measure<C: Circuit<Fp> + Clone>(label: String, circuit: C, instance: Vec<Fp>, k: Option<u32>) -> Row {
    let k = k.unwrap_or_else(|| min_k(&circuit, &instance));
    let mut cs = ConstraintSystem::<Fp>::default();
    C::configure(&mut cs);

    let t = Instant::now();
    let params: Params<EqAffine> = Params::new(k);
    let vk = keygen_vk(&params, &circuit.without_witnesses()).expect("keygen_vk");
    let pk = keygen_pk(&params, vk.clone(), &circuit.without_witnesses()).expect("keygen_pk");
    let keygen = t.elapsed();

    let mut times = Vec::with_capacity(PROVE_RUNS);
    let mut proof = Vec::new();
    for _ in 0..PROVE_RUNS {
        let t = Instant::now();
        let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(vec![]);
        create_proof(&params, &pk, &[circuit.clone()], &[&[&instance]], OsRng, &mut transcript).expect("prove");
        proof = transcript.finalize();
        times.push(t.elapsed());
    }

    let t = Instant::now();
    let strategy = SingleVerifier::new(&params);
    let mut transcript = Blake2bRead::<_, EqAffine, Challenge255<_>>::init(&proof[..]);
    verify_proof(&params, &vk, strategy, &[&[&instance]], &mut transcript).expect("verify");
    let verify = t.elapsed();

    Row { label, k, degree: cs.degree(), keygen, prove: median(times), verify, proof_len: proof.len() }
}

/// A balanced bundle: NI notes of different ages, spent into NO outputs.
fn bundle<const MODE: usize, const NI: usize, const NO: usize>(durations: [u64; NI], k: Option<u32>) -> Row {
    let (inputs, tags, now): ([Fp; NI], [u64; NI], u64) = match MODE {
        // anchored values in 2026 are ~2^5 times the nominal amount; use realistic 100 bit values
        MODE_ANCHORED => (
            core::array::from_fn(|i| Fp::from_u128((1u128 << 100) + i as u128 * 12_345)),
            [0; NI],
            NOW,
        ),
        // epoch values below 2^96, notes 0..NI years old
        MODE_EPOCH => (
            core::array::from_fn(|i| Fp::from_u128((1u128 << 90) + i as u128 * 777)),
            core::array::from_fn(|i| 10 - (i as u64 % 3)),
            10,
        ),
        // nominal values (GDD * 10^4) and note timestamps
        _ => (
            core::array::from_fn(|i| Fp::from(1_000_0000u64 + i as u64 * 1_2345)),
            core::array::from_fn(|i| NOW - durations[i]),
            NOW,
        ),
    };
    let mut total = Fp::zero();
    for i in 0..NI {
        total += effective_value(MODE, inputs[i], tags[i], now);
    }
    // everything into the first output, the others stay 0
    let outputs: [Fp; NO] = core::array::from_fn(|j| if j == 0 { total } else { Fp::zero() });
    let circuit = DecayBenchCircuit::<MODE, NI, NO>::new(inputs, tags, outputs, now);
    let instance = DecayBenchCircuit::<MODE, NI, NO>::instance(Fp::from(SIGHASH), now);
    measure(format!("{:<12} {NI} in / {NO} out", mode_name(MODE)), circuit, instance, k)
}

fn print(rows: &[Row]) {
    println!(
        "{:<28} {:>3} {:>6} {:>10} {:>10} {:>10} {:>8}",
        "variant", "k", "degree", "keygen", "prove", "verify", "proof"
    );
    for r in rows {
        println!(
            "{:<28} {:>3} {:>6} {:>10.1?} {:>10.1?} {:>10.1?} {:>7}B",
            r.label, r.k, r.degree, r.keygen, r.prove, r.verify, r.proof_len
        );
    }
}

fn main() {
    let y = SECONDS_PER_YEAR;
    let mixed2 = [400 * 86_400, 3 * y + 17];
    let mixed4 = [3600, 400 * 86_400, 3 * y + 17, 70 * y];

    println!("prove = median of {PROVE_RUNS} runs, threads = {}", std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1));
    println!();
    println!("rows per spent note (arithmetic columns / range check columns):");
    for mode in [MODE_ANCHORED, MODE_EPOCH, MODE_EXACT] {
        let (arith, range) = rows_per_input(mode);
        println!("  {:<12} {arith:>3} / {range:>3}", mode_name(mode));
    }
    println!();

    let rows = vec![
        bundle::<MODE_ANCHORED, 1, 1>([0], None),
        bundle::<MODE_ANCHORED, 2, 2>([0; 2], None),
        bundle::<MODE_ANCHORED, 4, 4>([0; 4], None),
        bundle::<MODE_EPOCH, 1, 1>([0], None),
        bundle::<MODE_EPOCH, 2, 2>([0; 2], None),
        bundle::<MODE_EPOCH, 4, 4>([0; 4], None),
        bundle::<MODE_EXACT, 1, 1>([400 * 86_400], None),
        bundle::<MODE_EXACT, 2, 2>(mixed2, None),
        bundle::<MODE_EXACT, 4, 4>(mixed4, None),
    ];
    print(&rows);

    println!();
    println!("same 2 in / 2 out circuits forced to larger k (Orchard's action circuit is k = 11):");
    let mut rows = Vec::new();
    for k in [11, 12, 13] {
        rows.push(bundle::<MODE_ANCHORED, 2, 2>([0; 2], Some(k)));
        rows.push(bundle::<MODE_EPOCH, 2, 2>([0; 2], Some(k)));
        rows.push(bundle::<MODE_EXACT, 2, 2>(mixed2, Some(k)));
    }
    print(&rows);

    println!();
    println!("way 1 exact, 2 in / 2 out, both notes with the same age:");
    let ages: [(&str, u64); 5] = [
        ("0 s", 0),
        ("1 hour", 3600),
        ("400 days", 400 * 86_400),
        ("10 years + 1 s", 10 * y + 1),
        ("70 years (all gone)", 70 * y),
    ];
    let rows: Vec<Row> = ages
        .iter()
        .map(|(name, d)| {
            let mut r = bundle::<MODE_EXACT, 2, 2>([*d, *d], None);
            r.label = format!("age {name}");
            r
        })
        .collect();
    print(&rows);
}
