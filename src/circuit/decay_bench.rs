//! Three ways to handle decay in a shielded transfer, built on the same gadgets so their costs
//! can be compared (`cargo run --release --example decay_timing`).
//!
//! * `MODE_ANCHORED` (E2 in privacy_todo.md): notes store `u = amount * 2^((t - T0) / year)`,
//!   the circuit only adds. Values grow every year, up to 160 bits.
//! * `MODE_EPOCH` (way 2): notes store their value anchored to the start of their own year
//!   (factor in `[1, 2)`, ~96 bits). Spending `k` years later divides by `2^k` in the circuit.
//! * `MODE_EXACT` (way 1): notes store the nominal int64 value and their timestamp. The circuit
//!   recomputes `grdd_unit_calculate_decay` from unit.c bit for bit (see `crate::decay`).
//!
//! Every mode proves `sum(effective inputs) == sum(outputs)` with all values range-checked,
//! bound to a public sighash. Public instance: `[sighash, now]`, where `now` is `created_at`
//! (exact) or the current epoch (epoch).
//!
//! Range checks: one row checks 64 bits with eight byte limbs, each looked up in a 256 row
//! table; wider values chain several rows.

use ff::{Field, PrimeField};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, Instance, Selector,
        TableColumn,
    },
    poly::Rotation,
};
use pasta_curves::Fp;

use crate::decay::{
    self, DecayTrace, ShiftTrace, DECAY_POWERS, REM_BITS, SECONDS_PER_YEAR, W1_SHIFT_LIMIT,
};

pub const MODE_ANCHORED: usize = 0;
pub const MODE_EPOCH: usize = 1;
pub const MODE_EXACT: usize = 2;

/// Epoch values are below `2^96`, so shifting by 96 or more yields 0.
pub const W2_SHIFT_LIMIT: u64 = 96;
/// The power table holds `(s, 2^s)` for `s` in `0..=POW_TABLE_MAX`.
pub const POW_TABLE_MAX: u64 = 127;

type Cell = AssignedCell<Fp, Fp>;

/// 64 bit chunks a value may occupy in each mode.
pub const fn value_chunks(mode: usize) -> usize {
    match mode {
        MODE_ANCHORED => 3,
        MODE_EPOCH => 2,
        _ => 1,
    }
}

pub const fn mode_name(mode: usize) -> &'static str {
    match mode {
        MODE_ANCHORED => "E2 anchored",
        MODE_EPOCH => "way 2 epoch",
        _ => "way 1 exact",
    }
}

fn two_pow(n: u32) -> Fp {
    let mut acc = Fp::ONE;
    for _ in 0..n {
        acc = acc.double();
    }
    acc
}

fn c(v: Fp) -> Expression<Fp> {
    Expression::Constant(v)
}

fn low_u128(v: &Fp) -> u128 {
    u128::from_le_bytes(v.to_repr()[..16].try_into().unwrap())
}

/// `v >> (64 * chunk)` as a field element.
fn chunk_of(v: &Fp, chunk: usize) -> Fp {
    let repr = v.to_repr();
    let mut bytes = [0u8; 32];
    bytes[..32 - 8 * chunk].copy_from_slice(&repr[8 * chunk..]);
    Fp::from_repr(bytes).unwrap()
}

/// Rows one spent note occupies, as laid out by `synthesize`:
/// `(rows in the arithmetic columns, rows in the range check columns)`.
/// The floor planner can put both side by side, so a note costs roughly the larger number.
pub const fn rows_per_input(mode: usize) -> (usize, usize) {
    match mode {
        // value; 3 chained range rows
        MODE_ANCHORED => (1, 3),
        // epoch + shift; k, w and 4 values of 2 chunks
        MODE_EPOCH => (1 + 2, 1 + 1 + 4 * 2),
        // factor chain 26 + duration + shift 2 + round;
        // 25 * 2 chain values, times, rem bound, 4 shift values, w, result, round rem
        _ => (REM_BITS + 1 + 1 + 2 + 1, REM_BITS * 2 + 2 + 4 + 1 + 2),
    }
}

/// Value a note contributes to the balance after decay handling, computed natively.
pub fn effective_value(mode: usize, value: Fp, tag: u64, now: u64) -> Fp {
    match mode {
        MODE_ANCHORED => value,
        MODE_EPOCH => {
            Fp::from_u128(decay::shift_trace(low_u128(&value), now - tag, W2_SHIFT_LIMIT).shifted)
        }
        _ => Fp::from(decay::decay(low_u128(&value) as u64, now - tag)),
    }
}

#[derive(Clone, Debug)]
pub struct DecayBenchConfig {
    a: [Column<Advice>; 5],
    rc_val: Column<Advice>,
    limbs: [Column<Advice>; 8],
    pconst: Column<Fixed>,
    instance: Column<Instance>,
    byte_table: TableColumn,
    pow_s: TableColumn,
    pow_v: TableColumn,
    s_rc_last: Selector,
    s_rc_chain: Selector,
    s_rc_lookup: Selector,
    s_step: Selector,
    s_duration: Selector,
    s_epoch: Selector,
    s_shift: Selector,
    s_pow: Selector,
    s_final: Selector,
    s_balance: Selector,
}

/// Witness. `tags` are the note timestamps (exact) or note epochs (epoch), unused for anchored.
#[derive(Clone, Debug)]
pub struct DecayBenchCircuit<const MODE: usize, const NI: usize, const NO: usize> {
    pub inputs: [Value<Fp>; NI],
    pub tags: [Value<u64>; NI],
    pub outputs: [Value<Fp>; NO],
    pub now: Value<u64>,
}

impl<const MODE: usize, const NI: usize, const NO: usize> DecayBenchCircuit<MODE, NI, NO> {
    pub fn new(inputs: [Fp; NI], tags: [u64; NI], outputs: [Fp; NO], now: u64) -> Self {
        Self {
            inputs: inputs.map(Value::known),
            tags: tags.map(Value::known),
            outputs: outputs.map(Value::known),
            now: Value::known(now),
        }
    }

    pub fn unknown() -> Self {
        Self {
            inputs: [Value::unknown(); NI],
            tags: [Value::unknown(); NI],
            outputs: [Value::unknown(); NO],
            now: Value::unknown(),
        }
    }

    pub fn instance(sighash: Fp, now: u64) -> Vec<Fp> {
        vec![sighash, Fp::from(now)]
    }

    /// Range check `cell < 2^(64 * chunks)`.
    fn range_check(
        config: &DecayBenchConfig,
        layouter: &mut impl Layouter<Fp>,
        cell: &Cell,
        chunks: usize,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "range check",
            |mut region| {
                let value = cell.value().copied();
                for row in 0..chunks {
                    config.s_rc_lookup.enable(&mut region, row)?;
                    if row + 1 < chunks {
                        config.s_rc_chain.enable(&mut region, row)?;
                    } else {
                        config.s_rc_last.enable(&mut region, row)?;
                    }
                    if row == 0 {
                        cell.copy_advice(|| "value", &mut region, config.rc_val, 0)?;
                    } else {
                        region.assign_advice(
                            || "chunk",
                            config.rc_val,
                            row,
                            || value.map(|v| chunk_of(&v, row)),
                        )?;
                    }
                    for j in 0..8 {
                        region.assign_advice(
                            || "limb",
                            config.limbs[j],
                            row,
                            || value.map(|v| Fp::from(v.to_repr()[8 * row + j] as u64)),
                        )?;
                    }
                }
                Ok(())
            },
        )
    }

    /// `value = q * 2^s + r` with `r < 2^s`; result is `q`, or 0 once `k >= limit`.
    /// Returns `(value, shifted)` and range-checks everything with `chunks` chunks.
    fn shift(
        config: &DecayBenchConfig,
        layouter: &mut impl Layouter<Fp>,
        value: Value<Fp>,
        k: &Cell,
        st: &Value<ShiftTrace>,
        limit: u64,
        chunks: usize,
    ) -> Result<(Cell, Cell), Error> {
        let (v, q, r, d, w, shifted) = layouter.assign_region(
            || "shift",
            |mut region| {
                config.s_shift.enable(&mut region, 0)?;
                config.s_pow.enable(&mut region, 0)?;
                let v = region.assign_advice(|| "v", config.a[0], 0, || value)?;
                let q = region.assign_advice(|| "q", config.a[1], 0, || st.as_ref().map(|t| Fp::from_u128(t.q)))?;
                region.assign_advice(|| "pow", config.a[2], 0, || st.as_ref().map(|t| Fp::from_u128(t.pow)))?;
                let r = region.assign_advice(|| "r", config.a[3], 0, || st.as_ref().map(|t| Fp::from_u128(t.r)))?;
                region.assign_advice(|| "big", config.a[4], 0, || st.as_ref().map(|t| Fp::from(t.big as u64)))?;
                region.assign_advice(|| "s", config.a[0], 1, || st.as_ref().map(|t| Fp::from(t.shift)))?;
                k.copy_advice(|| "k", &mut region, config.a[1], 1)?;
                let w = region.assign_advice(
                    || "w",
                    config.a[2],
                    1,
                    || st.as_ref().map(|t| if t.big { Fp::from(t.k - limit) } else { Fp::ZERO }),
                )?;
                let shifted = region.assign_advice(
                    || "shifted",
                    config.a[3],
                    1,
                    || st.as_ref().map(|t| Fp::from_u128(t.shifted)),
                )?;
                let d = region.assign_advice(
                    || "pow - 1 - r",
                    config.a[4],
                    1,
                    || st.as_ref().map(|t| Fp::from_u128(t.pow - 1 - t.r)),
                )?;
                Ok((v, q, r, d, w, shifted))
            },
        )?;
        for cell in [&v, &q, &r, &d] {
            Self::range_check(config, layouter, cell, chunks)?;
        }
        Self::range_check(config, layouter, &w, 1)?;
        Ok((v, shifted))
    }

    /// Way 1: `grdd_unit_calculate_decay(value, now - t_note)` bit for bit.
    fn exact_input(
        &self,
        config: &DecayBenchConfig,
        layouter: &mut impl Layouter<Fp>,
        now: &Cell,
        value: Value<Fp>,
        t_note: Value<u64>,
    ) -> Result<Cell, Error> {
        let trace: Value<DecayTrace> = value
            .zip(t_note)
            .zip(self.now)
            .map(|((v, t), n)| decay::decay_trace(low_u128(&v) as u64, n.checked_sub(t).expect("note from the future")));

        // factor chain: F_{i+1} = bit_i ? floor(F_i * P_i / 2^64) : F_i, and rem = sum bit_i 2^i
        let (rem, f_last, f_next, f_rem) = layouter.assign_region(
            || "decay factor",
            |mut region| {
                let mut f = region.assign_advice_from_constant(|| "F0", config.a[0], 0, two_pow(64))?;
                let mut f_next = Vec::with_capacity(REM_BITS);
                let mut f_rem = Vec::with_capacity(REM_BITS);
                let mut rem = None;
                for i in 0..REM_BITS {
                    config.s_step.enable(&mut region, i)?;
                    region.assign_fixed(|| "P", config.pconst, i, || Value::known(Fp::from(DECAY_POWERS[i])))?;
                    f_next.push(region.assign_advice(|| "F'", config.a[1], i, || trace.as_ref().map(|t| Fp::from(t.f_next[i])))?);
                    f_rem.push(region.assign_advice(|| "F' rem", config.a[2], i, || trace.as_ref().map(|t| Fp::from(t.f_rem[i])))?);
                    region.assign_advice(|| "bit", config.a[3], i, || trace.as_ref().map(|t| Fp::from(t.bits[i] as u64)))?;
                    let acc = region.assign_advice(|| "rem >> i", config.a[4], i, || trace.as_ref().map(|t| Fp::from(t.rem >> i)))?;
                    if i == 0 {
                        rem = Some(acc);
                    }
                    f = region.assign_advice(|| "F", config.a[0], i + 1, || trace.as_ref().map(|t| Fp::from_u128(t.f[i + 1])))?;
                }
                region.assign_advice_from_constant(|| "rem >> 25", config.a[4], REM_BITS, Fp::ZERO)?;
                Ok((rem.unwrap(), f, f_next, f_rem))
            },
        )?;
        for i in 0..REM_BITS {
            Self::range_check(config, layouter, &f_next[i], 1)?;
            Self::range_check(config, layouter, &f_rem[i], 1)?;
        }

        // now - t_note = times * year + rem, rem < year
        let (times, rem_bound) = layouter.assign_region(
            || "duration",
            |mut region| {
                config.s_duration.enable(&mut region, 0)?;
                now.copy_advice(|| "now", &mut region, config.a[0], 0)?;
                region.assign_advice(|| "t_note", config.a[1], 0, || t_note.map(Fp::from))?;
                let times = region.assign_advice(|| "times", config.a[2], 0, || trace.as_ref().map(|t| Fp::from(t.times)))?;
                rem.copy_advice(|| "rem", &mut region, config.a[3], 0)?;
                let bound = region.assign_advice(
                    || "year - 1 - rem",
                    config.a[4],
                    0,
                    || trace.as_ref().map(|t| Fp::from(SECONDS_PER_YEAR - 1 - t.rem)),
                )?;
                Ok((times, bound))
            },
        )?;
        Self::range_check(config, layouter, &times, 1)?;
        Self::range_check(config, layouter, &rem_bound, 1)?;

        // whole years: value >> times
        let st = trace.as_ref().map(|t| t.shift.clone());
        let (_, shifted) = Self::shift(config, layouter, value, &times, &st, W1_SHIFT_LIMIT, 1)?;

        // round half up: shifted * F + 2^63 = result * 2^64 + rem
        let (result, round_rem) = layouter.assign_region(
            || "round",
            |mut region| {
                config.s_final.enable(&mut region, 0)?;
                shifted.copy_advice(|| "shifted", &mut region, config.a[0], 0)?;
                f_last.copy_advice(|| "F", &mut region, config.a[1], 0)?;
                let result = region.assign_advice(|| "result", config.a[2], 0, || trace.as_ref().map(|t| Fp::from(t.result)))?;
                let round_rem = region.assign_advice(|| "round rem", config.a[3], 0, || trace.as_ref().map(|t| Fp::from(t.round_rem)))?;
                Ok((result, round_rem))
            },
        )?;
        Self::range_check(config, layouter, &result, 1)?;
        Self::range_check(config, layouter, &round_rem, 1)?;
        Ok(result)
    }

    /// Way 2: shift by the number of whole years since the note epoch.
    fn epoch_input(
        &self,
        config: &DecayBenchConfig,
        layouter: &mut impl Layouter<Fp>,
        now: &Cell,
        value: Value<Fp>,
        epoch: Value<u64>,
    ) -> Result<Cell, Error> {
        let st: Value<ShiftTrace> = value
            .zip(epoch)
            .zip(self.now)
            .map(|((v, e), n)| decay::shift_trace(low_u128(&v), n.checked_sub(e).expect("note from the future"), W2_SHIFT_LIMIT));
        let k = layouter.assign_region(
            || "epoch",
            |mut region| {
                config.s_epoch.enable(&mut region, 0)?;
                now.copy_advice(|| "now", &mut region, config.a[0], 0)?;
                region.assign_advice(|| "epoch", config.a[1], 0, || epoch.map(Fp::from))?;
                region.assign_advice(|| "k", config.a[2], 0, || st.as_ref().map(|t| Fp::from(t.k)))
            },
        )?;
        Self::range_check(config, layouter, &k, 1)?;
        let (_, shifted) = Self::shift(config, layouter, value, &k, &st, W2_SHIFT_LIMIT, value_chunks(MODE_EPOCH))?;
        Ok(shifted)
    }

    fn anchored_input(
        config: &DecayBenchConfig,
        layouter: &mut impl Layouter<Fp>,
        value: Value<Fp>,
    ) -> Result<Cell, Error> {
        let v = layouter.assign_region(
            || "anchored value",
            |mut region| region.assign_advice(|| "u", config.a[0], 0, || value),
        )?;
        Self::range_check(config, layouter, &v, value_chunks(MODE_ANCHORED))?;
        Ok(v)
    }
}

fn configure_impl(meta: &mut ConstraintSystem<Fp>, mode: usize, ni: usize, no: usize) -> DecayBenchConfig {
    let a = [(); 5].map(|_| meta.advice_column());
    let rc_val = meta.advice_column();
    let limbs = [(); 8].map(|_| meta.advice_column());
    let pconst = meta.fixed_column();
    let constants = meta.fixed_column();
    meta.enable_constant(constants);
    let instance = meta.instance_column();
    for col in a.iter() {
        meta.enable_equality(*col);
    }
    meta.enable_equality(rc_val);
    meta.enable_equality(instance);

    let byte_table = meta.lookup_table_column();
    let pow_s = meta.lookup_table_column();
    let pow_v = meta.lookup_table_column();

    let s_rc_last = meta.selector();
    let s_rc_chain = meta.selector();
    let s_rc_lookup = meta.complex_selector();
    let s_step = meta.selector();
    let s_duration = meta.selector();
    let s_epoch = meta.selector();
    let s_shift = meta.selector();
    let s_pow = meta.complex_selector();
    let s_final = meta.selector();
    let s_balance = meta.selector();

    let one = || c(Fp::ONE);

    // ---- range checks: value = sum(limb_j * 2^(8j)) [+ 2^64 * next chunk]
    let limb_sum = |meta: &mut halo2_proofs::plonk::VirtualCells<'_, Fp>| {
        let mut sum = c(Fp::ZERO);
        for (j, col) in limbs.iter().enumerate() {
            sum = sum + meta.query_advice(*col, Rotation::cur()) * c(two_pow(8 * j as u32));
        }
        sum
    };
    // separate gates: the chained one reads the next row, the last chunk must not
    meta.create_gate("range check last chunk", |meta| {
        let s = meta.query_selector(s_rc_last);
        let v = meta.query_advice(rc_val, Rotation::cur());
        vec![s * (v - limb_sum(meta))]
    });
    meta.create_gate("range check chained chunk", |meta| {
        let s = meta.query_selector(s_rc_chain);
        let v = meta.query_advice(rc_val, Rotation::cur());
        let v_next = meta.query_advice(rc_val, Rotation::next());
        vec![s * (v - limb_sum(meta) - v_next * c(two_pow(64)))]
    });
    for col in limbs.iter() {
        meta.lookup(|meta| {
            let s = meta.query_selector(s_rc_lookup);
            let l = meta.query_advice(*col, Rotation::cur());
            vec![(s * l, byte_table)]
        });
    }

    // ---- shift by a table power of two (epoch and exact)
    if mode != MODE_ANCHORED {
        let limit = if mode == MODE_EXACT { W1_SHIFT_LIMIT } else { W2_SHIFT_LIMIT };
        meta.create_gate("shift", |meta| {
            let s = meta.query_selector(s_shift);
            let v = meta.query_advice(a[0], Rotation::cur());
            let q = meta.query_advice(a[1], Rotation::cur());
            let pow = meta.query_advice(a[2], Rotation::cur());
            let r = meta.query_advice(a[3], Rotation::cur());
            let big = meta.query_advice(a[4], Rotation::cur());
            let sh = meta.query_advice(a[0], Rotation::next());
            let k = meta.query_advice(a[1], Rotation::next());
            let w = meta.query_advice(a[2], Rotation::next());
            let shifted = meta.query_advice(a[3], Rotation::next());
            let d = meta.query_advice(a[4], Rotation::next());
            vec![
                s.clone() * (v - q.clone() * pow.clone() - r.clone()),
                s.clone() * big.clone() * (one() - big.clone()),
                s.clone() * (one() - big.clone()) * (k.clone() - sh.clone()),
                s.clone() * big.clone() * sh,
                s.clone() * (w - big.clone() * (k - c(Fp::from(limit)))),
                s.clone() * (shifted - (one() - big) * q),
                s * (d - (pow - one() - r)),
            ]
        });
        meta.lookup(|meta| {
            let s = meta.query_selector(s_pow);
            let sh = meta.query_advice(a[0], Rotation::next());
            let pow = meta.query_advice(a[2], Rotation::cur());
            // when the selector is off this reads (0, 1), which is in the table
            vec![(s.clone() * sh, pow_s), (s.clone() * pow + (one() - s), pow_v)]
        });
    }

    if mode == MODE_EPOCH {
        meta.create_gate("epoch", |meta| {
            let s = meta.query_selector(s_epoch);
            let now = meta.query_advice(a[0], Rotation::cur());
            let epoch = meta.query_advice(a[1], Rotation::cur());
            let k = meta.query_advice(a[2], Rotation::cur());
            vec![s * (now - epoch - k)]
        });
    }

    if mode == MODE_EXACT {
        meta.create_gate("decay step", |meta| {
            let s = meta.query_selector(s_step);
            let f = meta.query_advice(a[0], Rotation::cur());
            let f_next = meta.query_advice(a[1], Rotation::cur());
            let r = meta.query_advice(a[2], Rotation::cur());
            let bit = meta.query_advice(a[3], Rotation::cur());
            let acc = meta.query_advice(a[4], Rotation::cur());
            let f_row_next = meta.query_advice(a[0], Rotation::next());
            let acc_next = meta.query_advice(a[4], Rotation::next());
            let p = meta.query_fixed(pconst);
            vec![
                s.clone() * (f.clone() * p - f_next.clone() * c(two_pow(64)) - r),
                s.clone() * bit.clone() * (one() - bit.clone()),
                s.clone() * (f_row_next - bit.clone() * f_next - (one() - bit.clone()) * f),
                s * (acc - bit - acc_next * c(Fp::from(2))),
            ]
        });
        meta.create_gate("duration", |meta| {
            let s = meta.query_selector(s_duration);
            let now = meta.query_advice(a[0], Rotation::cur());
            let t_note = meta.query_advice(a[1], Rotation::cur());
            let times = meta.query_advice(a[2], Rotation::cur());
            let rem = meta.query_advice(a[3], Rotation::cur());
            let bound = meta.query_advice(a[4], Rotation::cur());
            let year = c(Fp::from(SECONDS_PER_YEAR));
            vec![
                s.clone() * (now - t_note - times * year - rem.clone()),
                s * (bound - c(Fp::from(SECONDS_PER_YEAR - 1)) + rem),
            ]
        });
        meta.create_gate("round half up", |meta| {
            let s = meta.query_selector(s_final);
            let shifted = meta.query_advice(a[0], Rotation::cur());
            let f = meta.query_advice(a[1], Rotation::cur());
            let result = meta.query_advice(a[2], Rotation::cur());
            let rem = meta.query_advice(a[3], Rotation::cur());
            vec![s * (shifted * f + c(two_pow(63)) - result * c(two_pow(64)) - rem)]
        });
    }

    // ---- sum(effective inputs) == sum(outputs), laid out in consecutive rows
    meta.create_gate("balance", |meta| {
        let s = meta.query_selector(s_balance);
        let mut acc = c(Fp::ZERO);
        for i in 0..ni {
            acc = acc + meta.query_advice(a[0], Rotation(i as i32));
        }
        for j in 0..no {
            acc = acc - meta.query_advice(a[0], Rotation((ni + j) as i32));
        }
        vec![s * acc]
    });

    DecayBenchConfig {
        a,
        rc_val,
        limbs,
        pconst,
        instance,
        byte_table,
        pow_s,
        pow_v,
        s_rc_last,
        s_rc_chain,
        s_rc_lookup,
        s_step,
        s_duration,
        s_epoch,
        s_shift,
        s_pow,
        s_final,
        s_balance,
    }
}

impl<const MODE: usize, const NI: usize, const NO: usize> Circuit<Fp> for DecayBenchCircuit<MODE, NI, NO> {
    type Config = DecayBenchConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::unknown()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        configure_impl(meta, MODE, NI, NO)
    }

    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        layouter.assign_table(
            || "bytes",
            |mut table| {
                for i in 0..256usize {
                    table.assign_cell(|| "byte", config.byte_table, i, || Value::known(Fp::from(i as u64)))?;
                }
                Ok(())
            },
        )?;
        if MODE != MODE_ANCHORED {
            layouter.assign_table(
                || "powers of two",
                |mut table| {
                    for s in 0..=POW_TABLE_MAX {
                        table.assign_cell(|| "s", config.pow_s, s as usize, || Value::known(Fp::from(s)))?;
                        table.assign_cell(|| "2^s", config.pow_v, s as usize, || Value::known(Fp::from_u128(1u128 << s)))?;
                    }
                    Ok(())
                },
            )?;
        }

        // public inputs: sighash binds the proof to the transaction, now drives the decay
        let now = layouter.assign_region(
            || "public",
            |mut region| {
                region.assign_advice_from_instance(|| "sighash", config.instance, 0, config.a[0], 0)?;
                region.assign_advice_from_instance(|| "now", config.instance, 1, config.a[1], 0)
            },
        )?;

        let mut effective = Vec::with_capacity(NI);
        for i in 0..NI {
            let cell = match MODE {
                MODE_ANCHORED => Self::anchored_input(&config, &mut layouter, self.inputs[i])?,
                MODE_EPOCH => self.epoch_input(&config, &mut layouter, &now, self.inputs[i], self.tags[i])?,
                _ => self.exact_input(&config, &mut layouter, &now, self.inputs[i], self.tags[i])?,
            };
            effective.push(cell);
        }

        let outputs = layouter.assign_region(
            || "balance",
            |mut region| {
                config.s_balance.enable(&mut region, 0)?;
                for (i, cell) in effective.iter().enumerate() {
                    cell.copy_advice(|| "input", &mut region, config.a[0], i)?;
                }
                let mut outputs = Vec::with_capacity(NO);
                for j in 0..NO {
                    outputs.push(region.assign_advice(|| "output", config.a[0], NI + j, || self.outputs[j])?);
                }
                Ok(outputs)
            },
        )?;
        for cell in outputs.iter() {
            Self::range_check(&config, &mut layouter, cell, value_chunks(MODE))?;
        }
        Ok(())
    }
}
