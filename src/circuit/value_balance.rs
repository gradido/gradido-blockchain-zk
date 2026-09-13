//! Value balance in anchored units — the core of Circuit A (see privacy_todo.md, E2).
//!
//! Proves, without revealing any amount:
//!   1. every input and output value is in `[0, 2^VALUE_BITS)`
//!   2. `sum(inputs) == sum(outputs)`
//!   3. the proof is bound to a public `sighash`
//!
//! Because note values are stored *anchor-normalised*
//! (`u = amount_gddCent * 2^((t - DECAY_START_TIME) / SECONDS_PER_YEAR)`), decay never
//! appears here: conservation stays plain addition. That is the whole point of E2.
//!
//! Soundness note: each value is range-checked below `2^VALUE_BITS` (160), so a sum of
//! `N_IN <= 2^8` such values stays below `2^168`, far below the Pallas modulus (~2^254).
//! Equality in the field therefore implies equality over the integers — no wraparound.

use ff::{Field, PrimeField};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression, Instance, Selector, TableColumn},
    poly::Rotation,
};
use pasta_curves::Fp;

/// Bit width of an anchored value: 64 bit gddCent + 63 doublings + ~32 fractional bits.
pub const VALUE_BITS: usize = 160;
/// Bit width of one range-check limb; the lookup table holds `2^LIMB_BITS` rows.
pub const LIMB_BITS: usize = 8;
/// Limbs needed per value.
pub const N_LIMBS: usize = VALUE_BITS / LIMB_BITS;

/// Shielded inputs per action bundle (padded; see privacy_todo.md §5).
pub const N_IN: usize = 2;
/// Shielded outputs per action bundle.
pub const N_OUT: usize = 2;

/// Rows needed by the circuit; `k` must leave room for the lookup table too.
pub const K: u32 = 11;

#[derive(Clone, Debug)]
pub struct ValueBalanceConfig {
    value: Column<Advice>,
    limb: Column<Advice>,
    instance: Column<Instance>,
    range_table: TableColumn,
    s_balance: Selector,
    s_decompose: Selector,
    s_lookup: Selector,
}

/// Witness: the anchored values. `None` when only the shape is needed (keygen).
#[derive(Clone, Debug, Default)]
pub struct ValueBalanceCircuit {
    pub inputs: [Value<Fp>; N_IN],
    pub outputs: [Value<Fp>; N_OUT],
    /// Mirrors the public instance; copy-constrained to it so the proof cannot be
    /// replayed against a different transaction body.
    pub sighash: Value<Fp>,
}

impl ValueBalanceCircuit {
    pub fn new(inputs: [Fp; N_IN], outputs: [Fp; N_OUT], sighash: Fp) -> Self {
        Self {
            inputs: inputs.map(Value::known),
            outputs: outputs.map(Value::known),
            sighash: Value::known(sighash),
        }
    }
}

/// `2^(LIMB_BITS * j)` as a field element.
fn limb_weight(j: usize) -> Fp {
    let base = Fp::from(1u64 << LIMB_BITS);
    let mut acc = Fp::ONE;
    for _ in 0..j {
        acc *= base;
    }
    acc
}

impl Circuit<Fp> for ValueBalanceCircuit {
    type Config = ValueBalanceConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let value = meta.advice_column();
        let limb = meta.advice_column();
        let instance = meta.instance_column();
        let range_table = meta.lookup_table_column();

        meta.enable_equality(value);
        meta.enable_equality(instance);

        let s_balance = meta.selector();
        let s_decompose = meta.selector();
        // lookups may only be gated by complex selectors
        let s_lookup = meta.complex_selector();

        // sum(inputs) - sum(outputs) == 0, all values laid out in consecutive rows
        meta.create_gate("value balance", |meta| {
            let s = meta.query_selector(s_balance);
            let mut acc = Expression::Constant(Fp::ZERO);
            for i in 0..N_IN {
                acc = acc + meta.query_advice(value, Rotation(i as i32));
            }
            for i in 0..N_OUT {
                acc = acc - meta.query_advice(value, Rotation((N_IN + i) as i32));
            }
            vec![s * acc]
        });

        // value == sum(limb_j * 2^(LIMB_BITS*j))
        meta.create_gate("limb decomposition", |meta| {
            let s = meta.query_selector(s_decompose);
            let v = meta.query_advice(value, Rotation::cur());
            let mut acc = Expression::Constant(Fp::ZERO);
            for j in 0..N_LIMBS {
                let l = meta.query_advice(limb, Rotation(j as i32));
                acc = acc + l * Expression::Constant(limb_weight(j));
            }
            vec![s * (v - acc)]
        });

        // every limb is a byte
        meta.lookup(|meta| {
            let s = meta.query_selector(s_lookup);
            let l = meta.query_advice(limb, Rotation::cur());
            // when the selector is off the expression is 0, which is in the table
            vec![(s * l, range_table)]
        });

        ValueBalanceConfig {
            value,
            limb,
            instance,
            range_table,
            s_balance,
            s_decompose,
            s_lookup,
        }
    }

    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        // the byte table backing the range check
        layouter.assign_table(
            || "range table",
            |mut table| {
                for i in 0..(1usize << LIMB_BITS) {
                    table.assign_cell(|| "byte", config.range_table, i, || Value::known(Fp::from(i as u64)))?;
                }
                Ok(())
            },
        )?;

        let all: Vec<Value<Fp>> = self.inputs.iter().chain(self.outputs.iter()).copied().collect();

        // region 1: the values in consecutive rows, tied together by the balance gate
        let (value_cells, sighash_cell) = layouter.assign_region(
            || "values",
            |mut region| {
                config.s_balance.enable(&mut region, 0)?;
                let mut cells = Vec::with_capacity(all.len());
                for (i, v) in all.iter().enumerate() {
                    cells.push(region.assign_advice(|| "value", config.value, i, || *v)?);
                }
                // one row past the rotations the balance gate reads
                let sighash = region.assign_advice(
                    || "sighash",
                    config.value,
                    N_IN + N_OUT,
                    || self.sighash,
                )?;
                Ok((cells, sighash))
            },
        )?;

        // region 2: one decomposition block per value
        for (i, cell) in value_cells.iter().enumerate() {
            layouter.assign_region(
                || "range check",
                |mut region| {
                    cell.copy_advice(|| "value", &mut region, config.value, 0)?;
                    config.s_decompose.enable(&mut region, 0)?;
                    for j in 0..N_LIMBS {
                        config.s_lookup.enable(&mut region, j)?;
                        let limb = all[i].map(|v| {
                            let bytes = v.to_repr();
                            Fp::from(bytes[j] as u64)
                        });
                        region.assign_advice(|| "limb", config.limb, j, || limb)?;
                    }
                    Ok(())
                },
            )?;
        }

        // bind the proof to the public sighash
        layouter.constrain_instance(sighash_cell.cell(), config.instance, 0)?;
        Ok(())
    }
}
