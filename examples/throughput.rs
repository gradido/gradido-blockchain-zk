//! Proofs per second on one machine: every proof runs single threaded, many at once.
//! `RAYON_NUM_THREADS=1 cargo run --release --example throughput [threads] [proofs per thread]`

use std::time::Instant;

use halo2_proofs::{
    plonk::{create_proof, keygen_pk, keygen_vk, Circuit, SingleVerifier, verify_proof},
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use pasta_curves::vesta;
use rand::rngs::OsRng;

use gradido_blockchain_zk::circuit::action_slice::sample;
use gradido_blockchain_zk::decay::SECONDS_PER_YEAR;

fn main() {
    let mut args = std::env::args().skip(1);
    let threads: usize = args.next().and_then(|a| a.parse().ok())
        .unwrap_or_else(|| std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1));
    let per_thread: usize = args.next().and_then(|a| a.parse().ok()).unwrap_or(4);

    let f = sample::fixture::<true, true>(1_000_0000, 3 * SECONDS_PER_YEAR, None);
    let params: Params<vesta::Affine> = Params::new(11);
    let vk = keygen_vk(&params, &f.circuit.without_witnesses()).expect("keygen_vk");
    let pk = keygen_pk(&params, vk.clone(), &f.circuit.without_witnesses()).expect("keygen_pk");

    // one proof up front, so the check is done before timing; also the sequential baseline
    let baseline = {
        let t0 = Instant::now();
        let mut t = Blake2bWrite::<_, vesta::Affine, Challenge255<_>>::init(vec![]);
        create_proof(&params, &pk, &[f.circuit.clone()], &[&[&f.instance]], OsRng, &mut t).unwrap();
        let proof = t.finalize();
        let mut t = Blake2bRead::<_, vesta::Affine, Challenge255<_>>::init(&proof[..]);
        verify_proof(&params, &vk, SingleVerifier::new(&params), &[&[&f.instance]], &mut t).unwrap();
        t0.elapsed()
    };
    println!("one proof alone (incl. one verify): {baseline:.2?}");

    println!("{threads} threads x {per_thread} proofs, one action each (windowed decay, k=11)");
    let start = Instant::now();
    std::thread::scope(|scope| {
        for _ in 0..threads {
            let (params, pk, f) = (&params, &pk, &f);
            scope.spawn(move || {
                for _ in 0..per_thread {
                    let mut t = Blake2bWrite::<_, vesta::Affine, Challenge255<_>>::init(vec![]);
                    create_proof(params, pk, &[f.circuit.clone()], &[&[&f.instance]], OsRng, &mut t).unwrap();
                    std::hint::black_box(t.finalize());
                }
            });
        }
    });
    let elapsed = start.elapsed();
    let total = (threads * per_thread) as f64;
    println!(
        "{total} proofs in {elapsed:.2?} = {:.1} proofs/s, {:.0} ms per proof and core",
        total / elapsed.as_secs_f64(),
        elapsed.as_secs_f64() * 1000.0 * threads as f64 / total
    );
}
