//! Rows per Poseidon hash, to compare a Poseidon note commitment against Sinsemilla.
use halo2_gadgets::poseidon::{
    primitives::{ConstantLength, P128Pow5T3},
    Hash, Pow5Chip, Pow5Config,
};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    dev::CircuitCost,
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error},
};
use pasta_curves::{pallas, vesta};

#[derive(Clone, Debug, Default)]
struct PoseidonCircuit<const HASHES: usize>;

/// same but hashing L field elements at once, like a note commitment would
#[derive(Clone, Debug, Default)]
struct WideCircuit<const L: usize>;

impl<const HASHES: usize> Circuit<pallas::Base> for PoseidonCircuit<HASHES> {
    type Config = (Pow5Config<pallas::Base, 3, 2>, [Column<Advice>; 3]);
    type FloorPlanner = SimpleFloorPlanner;
    fn without_witnesses(&self) -> Self { Self }
    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
        let state = [meta.advice_column(), meta.advice_column(), meta.advice_column()];
        let partial_sbox = meta.advice_column();
        let rc_a = [meta.fixed_column(), meta.fixed_column(), meta.fixed_column()];
        let rc_b = [meta.fixed_column(), meta.fixed_column(), meta.fixed_column()];
        for c in state.iter() { meta.enable_equality(*c); }
        meta.enable_constant(rc_b[0]);
        (Pow5Chip::configure::<P128Pow5T3>(meta, state, partial_sbox, rc_a, rc_b), state)
    }
    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<pallas::Base>) -> Result<(), Error> {
        let (poseidon, advices) = config;
        for i in 0..HASHES {
            let cells = layouter.assign_region(
                || "input",
                |mut region| {
                    let a = region.assign_advice(|| "a", advices[0], 0, || Value::known(pallas::Base::from(i as u64 + 1)))?;
                    let b = region.assign_advice(|| "b", advices[1], 0, || Value::known(pallas::Base::from(7)))?;
                    Ok([a, b])
                },
            )?;
            Hash::<_, _, P128Pow5T3, ConstantLength<2>, 3, 2>::init(
                Pow5Chip::construct(poseidon.clone()),
                layouter.namespace(|| "init"),
            )?
            .hash(layouter.namespace(|| "hash"), cells)?;
        }
        Ok(())
    }
}

impl<const L: usize> Circuit<pallas::Base> for WideCircuit<L>
where
    ConstantLength<L>: halo2_gadgets::poseidon::primitives::Domain<pallas::Base, 2>,
{
    type Config = (Pow5Config<pallas::Base, 3, 2>, [Column<Advice>; 3]);
    type FloorPlanner = SimpleFloorPlanner;
    fn without_witnesses(&self) -> Self { Self }
    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
        <PoseidonCircuit<1> as Circuit<pallas::Base>>::configure(meta)
    }
    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<pallas::Base>) -> Result<(), Error> {
        let (poseidon, advices) = config;
        let cells: [_; L] = {
            let mut v = Vec::with_capacity(L);
            for i in 0..L {
                v.push(layouter.assign_region(
                    || "input",
                    |mut region| region.assign_advice(|| "x", advices[0], 0, || Value::known(pallas::Base::from(i as u64 + 1))),
                )?);
            }
            v.try_into().unwrap()
        };
        Hash::<_, _, P128Pow5T3, ConstantLength<L>, 3, 2>::init(
            Pow5Chip::construct(poseidon),
            layouter.namespace(|| "init"),
        )?
        .hash(layouter.namespace(|| "hash"), cells)?;
        Ok(())
    }
}

fn wide_rows<const L: usize>() -> usize
where
    ConstantLength<L>: halo2_gadgets::poseidon::primitives::Domain<pallas::Base, 2>,
{
    let cost = format!("{:?}", CircuitCost::<vesta::Point, _>::measure(12, &WideCircuit::<L>));
    cost.split("max_rows: ").nth(1).unwrap().split(',').next().unwrap().parse().unwrap()
}

fn rows<const HASHES: usize>() -> usize {
    let cost = format!("{:?}", CircuitCost::<vesta::Point, _>::measure(12, &PoseidonCircuit::<HASHES>));
    cost.split("max_rows: ").nth(1).unwrap().split(',').next().unwrap().parse().unwrap()
}

fn main() {
    let (one, five) = (rows::<1>(), rows::<5>());
    println!("1 hash of 2 field elements: {one} rows");
    println!("5 hashes: {five} rows  ->  {} rows each", (five - one) / 4);
    for (label, r) in [("L=2", wide_rows::<2>()), ("L=4", wide_rows::<4>()), ("L=8", wide_rows::<8>()), ("L=9", wide_rows::<9>())] {
        println!("one hash over {label} field elements: {r} rows");
    }
}
