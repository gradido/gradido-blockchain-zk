use ff::PrimeField;
use halo2_proofs::dev::MockProver;
use pasta_curves::Fp;

use crate::circuit::decay_bench::{
    effective_value, DecayBenchCircuit, MODE_ANCHORED, MODE_EPOCH, MODE_EXACT,
};
use crate::decay::{decay, SECONDS_PER_YEAR};

/// (value, duration, bit chain, windowed) straight from unit.c, see test/gen_decay_vectors.c
fn all_vectors() -> Vec<(u64, u64, u64, u64)> {
    include_str!("../test/decay_vectors.csv")
        .lines()
        .map(|line| {
            let mut it = line.split(',').map(|x| x.parse::<u64>().unwrap());
            (it.next().unwrap(), it.next().unwrap(), it.next().unwrap(), it.next().unwrap())
        })
        .collect()
}

/// (value, duration, result of grdd_unit_calculate_decay)
fn vectors() -> Vec<(u64, u64, u64)> {
    all_vectors().into_iter().map(|(v, d, bits, _)| (v, d, bits)).collect()
}

const K: u32 = 10;
// far enough in the future for durations of 200 years
const NOW: u64 = 10_000_000_000;
const SIGHASH: u64 = 0xdead_beef;

fn mock<const MODE: usize, const NI: usize, const NO: usize>(
    inputs: [Fp; NI],
    tags: [u64; NI],
    outputs: [Fp; NO],
    now: u64,
) -> bool {
    let circuit = DecayBenchCircuit::<MODE, NI, NO>::new(inputs, tags, outputs, now);
    let instance = DecayBenchCircuit::<MODE, NI, NO>::instance(Fp::from(SIGHASH), now);
    let prover = MockProver::run(K, &circuit, vec![instance]).unwrap();
    match prover.verify() {
        Ok(()) => true,
        Err(errors) => {
            if std::env::var("DECAY_DEBUG").is_ok() {
                for e in errors.iter().take(4) {
                    eprintln!("{e:?}");
                }
            }
            false
        }
    }
}

#[test]
fn native_decay_matches_unit_c() {
    let vs = vectors();
    assert!(vs.len() > 4000);
    for (value, duration, expected) in vs {
        assert_eq!(decay(value, duration), expected, "value {value}, duration {duration}");
    }
}

#[test]
fn exact_circuit_matches_unit_c() {
    // every 60th vector through the MockProver: one input, output = unit.c result
    for (value, duration, expected) in vectors().into_iter().step_by(60) {
        let ok = mock::<MODE_EXACT, 1, 1>([Fp::from(value)], [NOW - duration], [Fp::from(expected)], NOW);
        assert!(ok, "value {value}, duration {duration}");
    }
}

/// All 4252 vectors through the MockProver: `cargo test --release -- --ignored`
#[test]
#[ignore]
fn exact_circuit_matches_all_unit_c_vectors() {
    for (value, duration, expected) in vectors() {
        let ok = mock::<MODE_EXACT, 1, 1>([Fp::from(value)], [NOW - duration], [Fp::from(expected)], NOW);
        assert!(ok, "value {value}, duration {duration}");
    }
}

#[test]
fn exact_circuit_rejects_off_by_one() {
    for (value, duration, expected) in vectors().into_iter().step_by(400) {
        if expected == 0 {
            continue;
        }
        let bad = Fp::from(expected - 1);
        assert!(!mock::<MODE_EXACT, 1, 1>([Fp::from(value)], [NOW - duration], [bad], NOW));
        let bad = Fp::from(expected + 1);
        assert!(!mock::<MODE_EXACT, 1, 1>([Fp::from(value)], [NOW - duration], [bad], NOW));
    }
}

#[test]
fn exact_transfer_two_in_two_out() {
    let values = [Fp::from(1_000_0000u64), Fp::from(250_1234u64)];
    let tags = [NOW - 400 * 86_400, NOW - 3 * SECONDS_PER_YEAR - 17];
    let total = effective_value(MODE_EXACT, values[0], tags[0], NOW)
        + effective_value(MODE_EXACT, values[1], tags[1], NOW);
    let pay = Fp::from(300_0000u64);
    assert!(mock::<MODE_EXACT, 2, 2>(values, tags, [pay, total - pay], NOW));
    // one unit too much for the change
    assert!(!mock::<MODE_EXACT, 2, 2>(values, tags, [pay, total - pay + Fp::from(1)], NOW));
}

#[test]
fn exact_rejects_note_from_the_future() {
    // a note dated after `now` would need a negative duration; the prover cannot build one,
    // so claim the undecayed value with a duration of 0 but a later t_note via a lying now
    let circuit = DecayBenchCircuit::<MODE_EXACT, 1, 1>::new([Fp::from(5000u64)], [NOW], [Fp::from(5000u64)], NOW);
    let instance = DecayBenchCircuit::<MODE_EXACT, 1, 1>::instance(Fp::from(SIGHASH), NOW - 10);
    let prover = MockProver::run(K, &circuit, vec![instance]).unwrap();
    assert!(prover.verify().is_err());
}

#[test]
fn epoch_transfer() {
    let values = [Fp::from_u128(1u128 << 90), Fp::from(123_456_789u64)];
    let tags = [5, 9];
    let now = 12;
    let total = effective_value(MODE_EPOCH, values[0], tags[0], now)
        + effective_value(MODE_EPOCH, values[1], tags[1], now);
    assert_eq!(total, Fp::from_u128((1u128 << 83) + (123_456_789u128 >> 3)));
    assert!(mock::<MODE_EPOCH, 2, 2>(values, tags, [total, Fp::from(0u64)], now));
    assert!(!mock::<MODE_EPOCH, 2, 2>(values, tags, [total + Fp::from(1), Fp::from(0u64)], now));
    // after 96 years everything is gone
    assert!(mock::<MODE_EPOCH, 1, 1>([values[0]], [0], [Fp::from(0u64)], 100));
}

#[test]
fn anchored_transfer() {
    let values = [Fp::from_u128(1u128 << 100), Fp::from(7u64)];
    let outputs = [Fp::from_u128((1u128 << 100) + 3), Fp::from(4u64)];
    assert!(mock::<MODE_ANCHORED, 2, 2>(values, [0, 0], outputs, NOW));
    assert!(!mock::<MODE_ANCHORED, 2, 2>(values, [0, 0], [outputs[0], Fp::from(5u64)], NOW));
}

/// The Rust window chain must agree with grdd_unit_calculate_decay_windowed() in C, exactly.
#[test]
fn windowed_decay_matches_unit_c_windowed() {
    for (value, duration, _, expected) in all_vectors() {
        assert_eq!(
            crate::decay::decay_windowed(value, duration),
            expected,
            "value {value}, duration {duration}"
        );
    }
}

#[test]
fn windowed_decay_stays_within_two_units_of_the_bit_chain() {
    use crate::decay::decay_windowed;
    let mut differing = 0usize;
    let mut max_diff = 0i128;
    let vs = vectors();
    for &(value, duration, expected) in vs.iter() {
        let got = decay_windowed(value, duration) as i128;
        let diff = got - expected as i128;
        if diff != 0 {
            differing += 1;
        }
        max_diff = max_diff.max(diff.abs());
    }
    println!(
        "windowed vs unit.c: {differing} of {} vectors differ, largest difference {max_diff} (0.0001 GDD each)",
        vs.len()
    );
    assert!(max_diff <= 2, "windowed decay drifts by more than two units: {max_diff}");
}
