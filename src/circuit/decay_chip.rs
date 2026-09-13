//! Decay exactly as `grdd_unit_calculate_decay` in unit.c, as a chip that fits next to the
//! Orchard gadgets: its range checks go through the same 10-bit lookup that the Sinsemilla
//! table already provides, so it needs no table of its own.
//!
//! Per spent note it proves `decayed = decay(value, now - t_note)`:
//! 1. `now - t_note = times * year + rem`, `rem < year`
//! 2. `shifted = value >> times` (0 once `times >= 63`), the shift from a `(s, 2^s)` table
//! 3. factor chain over the 25 bits of `rem`: `F = floor(F * DECAY_POWERS[i] / 2^64)`
//! 4. `decayed = floor((shifted * F + 2^63) / 2^64)`, the round-half-up of r128Round
//!
//! The chip works on the caller's cells: `value` and `t_note` are copied from the cells the note
//! commitment binds, and the caller has to guarantee `value < 2^63` (the note chip does).
//!
//! See `crate::decay` for the same computation in Rust and `test/decay_vectors.csv` for the
//! vectors taken from the C implementation.

use ff::{Field, PrimeField};
use halo2_gadgets::utilities::lookup_range_check::PallasLookupRangeCheck;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, Selector, TableColumn},
    poly::Rotation,
};
use pasta_curves::pallas;

use crate::decay::{
    self, DecayTrace, WindowedTrace, DECAY_POWERS, REM_BITS, SECONDS_PER_YEAR, WINDOWS,
    WINDOW_BITS, WINDOW_SIZE, W1_SHIFT_LIMIT,
};

type Base = pallas::Base;
type Cell = AssignedCell<Base, Base>;

/// Words of the 10-bit lookup per range check: 7 words cover the 64 bit values with room to
/// spare. Every checked value stays below 2^70, far below the field modulus. That is enough
/// for cells that are pinned by an equation anyway; the remainders of the divisions by 2^64
/// need the exact bound (`EXACT_REM_BITS`), or the quotient could be chosen smaller.
const RANGE_WORDS: usize = 7;
const EXACT_REM_BITS: u32 = 64;
/// Largest shift in the `(s, 2^s)` part of the table.
const POW_TABLE_MAX: u64 = 127;
/// Tag of the `(s, 2^s)` rows; window rows carry their window index as tag.
const SHIFT_TAG: u64 = 32;

fn c(v: Base) -> Expression<Base> {
    Expression::Constant(v)
}

fn two_pow(n: u32) -> Base {
    let mut acc = Base::ONE;
    for _ in 0..n {
        acc = acc.double();
    }
    acc
}

fn low_u64(v: &Base) -> u64 {
    u64::from_le_bytes(v.to_repr()[..8].try_into().unwrap())
}

#[derive(Clone, Debug)]
pub struct DecayConfig<Lookup: PallasLookupRangeCheck, const WINDOWED: bool> {
    a: [Column<Advice>; 6],
    pconst: Column<Fixed>,
    /// one table for both uses: `(tag, x, y)` with `tag = SHIFT_TAG` for `(s, 2^s)` and
    /// `tag = window index` for the window factors
    tab_t: TableColumn,
    tab_x: TableColumn,
    tab_y: TableColumn,
    s_step: Selector,
    s_window: Selector,
    s_duration: Selector,
    s_shift: Selector,
    s_lookup: Selector,
    s_final: Selector,
    pub lookup: Lookup,
}

impl<Lookup: PallasLookupRangeCheck, const WINDOWED: bool> DecayConfig<Lookup, WINDOWED> {
    /// `a` needs equality enabled; `pconst` carries the per-row constant of the factor chain
    /// (the bit factor, or the window index for the lookup).
    #[allow(clippy::too_many_arguments)]
    pub fn configure(
        meta: &mut ConstraintSystem<Base>,
        a: [Column<Advice>; 6],
        pconst: Column<Fixed>,
        tab_t: TableColumn,
        tab_x: TableColumn,
        tab_y: TableColumn,
        lookup: Lookup,
    ) -> Self {
        for col in a.iter() {
            meta.enable_equality(*col);
        }
        let s_step = meta.selector();
        let s_window = meta.complex_selector();
        let s_duration = meta.selector();
        let s_shift = meta.selector();
        let s_lookup = meta.complex_selector();
        let s_final = meta.selector();
        let one = || c(Base::ONE);

        // F_{j+1} = floor(F_j * W[j][c_j] / 2^64), and rem = sum c_j * 2^(5j).
        // A window digit of 0 has factor 2^64, so no case distinction is needed.
        if WINDOWED {
            meta.create_gate("decay window step", |meta| {
                let s = meta.query_selector(s_window);
                let f = meta.query_advice(a[0], Rotation::cur());
                let f_next = meta.query_advice(a[1], Rotation::cur());
                let r = meta.query_advice(a[2], Rotation::cur());
                let acc = meta.query_advice(a[4], Rotation::cur());
                let factor = meta.query_advice(a[5], Rotation::cur());
                let digit = meta.query_advice(a[3], Rotation::cur());
                let f_row_next = meta.query_advice(a[0], Rotation::next());
                let acc_next = meta.query_advice(a[4], Rotation::next());
                vec![
                    s.clone() * (f * factor - f_next.clone() * c(two_pow(64)) - r),
                    s.clone() * (f_row_next - f_next),
                    s * (acc - digit - acc_next * c(Base::from(WINDOW_SIZE as u64))),
                ]
            });
        }

        // F_{i+1} = bit_i ? floor(F_i * P_i / 2^64) : F_i, and rem = sum bit_i 2^i
        if !WINDOWED {
        meta.create_gate("decay factor step", |meta| {
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
                s * (acc - bit - acc_next * c(Base::from(2))),
            ]
        });
        }

        // now - t_note = times * year + rem, with the witness for rem < year
        meta.create_gate("duration", |meta| {
            let s = meta.query_selector(s_duration);
            let now = meta.query_advice(a[0], Rotation::cur());
            let t_note = meta.query_advice(a[1], Rotation::cur());
            let times = meta.query_advice(a[2], Rotation::cur());
            let rem = meta.query_advice(a[3], Rotation::cur());
            let bound = meta.query_advice(a[4], Rotation::cur());
            vec![
                s.clone() * (now - t_note - times * c(Base::from(SECONDS_PER_YEAR)) - rem.clone()),
                s * (bound - c(Base::from(SECONDS_PER_YEAR - 1)) + rem),
            ]
        });

        // value = q * 2^s + r, shifted = 0 once times >= 63
        meta.create_gate("year shift", |meta| {
            let s = meta.query_selector(s_shift);
            let v = meta.query_advice(a[0], Rotation::cur());
            let q = meta.query_advice(a[1], Rotation::cur());
            let r = meta.query_advice(a[2], Rotation::cur());
            let sh = meta.query_advice(a[3], Rotation::cur());
            let big = meta.query_advice(a[4], Rotation::cur());
            let pow = meta.query_advice(a[5], Rotation::cur());
            let times = meta.query_advice(a[1], Rotation::next());
            let w = meta.query_advice(a[2], Rotation::next());
            let shifted = meta.query_advice(a[3], Rotation::next());
            let d = meta.query_advice(a[4], Rotation::next());
            vec![
                s.clone() * (v - q.clone() * pow.clone() - r.clone()),
                s.clone() * big.clone() * (one() - big.clone()),
                s.clone() * (one() - big.clone()) * (times.clone() - sh.clone()),
                s.clone() * big.clone() * sh,
                s.clone() * (w - big.clone() * (times - c(Base::from(W1_SHIFT_LIMIT)))),
                s.clone() * (shifted - (one() - big) * q),
                s * (d - (pow - one() - r)),
            ]
        });

        // One lookup for both uses: the window rows read (window index, digit, factor), the
        // shift row reads (SHIFT_TAG, s, 2^s). Both live in `pconst`, `a[3]` and `a[5]`, so a
        // single lookup argument serves them. With the selector off it reads the neutral row
        // (0, 0, 2^64).
        meta.lookup(|meta| {
            let s = meta.query_selector(s_lookup);
            let tag = meta.query_fixed(pconst);
            let x = meta.query_advice(a[3], Rotation::cur());
            let y = meta.query_advice(a[5], Rotation::cur());
            vec![
                (s.clone() * tag, tab_t),
                (s.clone() * x, tab_x),
                (s.clone() * y + (one() - s) * c(two_pow(64)), tab_y),
            ]
        });

        // decayed = floor((shifted * F + 2^63) / 2^64)
        meta.create_gate("round half up", |meta| {
            let s = meta.query_selector(s_final);
            let shifted = meta.query_advice(a[0], Rotation::cur());
            let f = meta.query_advice(a[1], Rotation::cur());
            let decayed = meta.query_advice(a[2], Rotation::cur());
            let rem = meta.query_advice(a[3], Rotation::cur());
            vec![s * (shifted * f + c(two_pow(63)) - decayed * c(two_pow(64)) - rem)]
        });

        Self { a, pconst, tab_t, tab_x, tab_y, s_step, s_window, s_duration, s_shift, s_lookup, s_final, lookup }
    }

    /// Load the table this chip owns. The 10-bit lookup table comes from the Sinsemilla chip.
    pub fn load(&self, layouter: &mut impl Layouter<Base>) -> Result<(), Error> {
        layouter.assign_table(
            || "decay table",
            |mut table| {
                let mut row = 0;
                let put = |table: &mut halo2_proofs::circuit::Table<'_, Base>, row: usize, t: u64, x: u64, y: Base| -> Result<(), Error> {
                    table.assign_cell(|| "tag", self.tab_t, row, || Value::known(Base::from(t)))?;
                    table.assign_cell(|| "x", self.tab_x, row, || Value::known(Base::from(x)))?;
                    table.assign_cell(|| "y", self.tab_y, row, || Value::known(y))?;
                    Ok(())
                };
                // neutral row, also what the lookup reads when its selector is off
                put(&mut table, row, 0, 0, two_pow(64))?;
                row += 1;
                // powers of two for the whole-year shift
                for shift in 0..=POW_TABLE_MAX {
                    put(&mut table, row, SHIFT_TAG, shift, Base::from_u128(1u128 << shift))?;
                    row += 1;
                }
                if WINDOWED {
                    for (j, factors) in decay::window_table().iter().enumerate() {
                        for (digit, factor) in factors.iter().enumerate() {
                            put(&mut table, row, j as u64, digit as u64, Base::from_u128(*factor))?;
                            row += 1;
                        }
                    }
                }
                Ok(())
            },
        )
    }

    fn range_check(&self, layouter: &mut impl Layouter<Base>, cell: &Cell) -> Result<(), Error> {
        self.lookup
            .copy_check(layouter.namespace(|| "range check"), cell.clone(), RANGE_WORDS, true)
            .map(|_| ())
    }

    /// `x * y = q * 2^64 + rem` fixes `q` only with `rem < 2^64` exactly.
    fn remainder_check(&self, layouter: &mut impl Layouter<Base>, cell: &Cell) -> Result<(), Error> {
        super::range::check_bits(&self.lookup, layouter, cell, EXACT_REM_BITS)
    }

    /// Proves `decayed = decay(value, now - t_note)` on the given cells and returns `decayed`.
    /// `value` must already be constrained below 2^63. With `WINDOWED` the factor chain runs
    /// over five 5-bit windows instead of 25 bits.
    pub fn decay(
        &self,
        layouter: &mut impl Layouter<Base>,
        now: &Cell,
        value: &Cell,
        t_note: &Cell,
    ) -> Result<Cell, Error> {
        let value_cell = value;
        let value: Value<Base> = value_cell.value().copied();
        let t_note_cell = t_note;
        let t_note: Value<u64> = t_note_cell.value().map(low_u64);
        // a note from the future has no valid witness: `now - t_note` cannot be written as
        // `times * year + rem` with small parts, so the gate fails. The builder rejects it first.
        let duration = now.value().copied().zip(t_note).map(|(n, t)| low_u64(&n).saturating_sub(t));
        let tail: Value<Tail> = value.zip(duration).map(|(v, d)| {
            if WINDOWED {
                Tail::of_windowed(&decay::windowed_trace(low_u64(&v), d))
            } else {
                Tail::of_exact(&decay::decay_trace(low_u64(&v), d))
            }
        });

        let (rem, f_last) = if WINDOWED {
            self.assign_window_chain(layouter, value.zip(duration).map(|(v, d)| decay::windowed_trace(low_u64(&v), d)))?
        } else {
            self.assign_bit_chain(layouter, value.zip(duration).map(|(v, d)| decay::decay_trace(low_u64(&v), d)))?
        };

        // now - t_note = times * year + rem, with the witness for rem < year
        let (times, bound) = layouter.assign_region(
            || "duration",
            |mut region| {
                self.s_duration.enable(&mut region, 0)?;
                now.copy_advice(|| "now", &mut region, self.a[0], 0)?;
                t_note_cell.copy_advice(|| "t_note", &mut region, self.a[1], 0)?;
                let times = region.assign_advice(|| "times", self.a[2], 0, || tail.as_ref().map(|t| Base::from(t.times)))?;
                rem.copy_advice(|| "rem", &mut region, self.a[3], 0)?;
                let bound = region.assign_advice(
                    || "year - 1 - rem",
                    self.a[4],
                    0,
                    || tail.as_ref().map(|t| Base::from(SECONDS_PER_YEAR - 1 - t.rem)),
                )?;
                Ok((times, bound))
            },
        )?;
        self.range_check(layouter, &times)?;
        self.range_check(layouter, &bound)?;

        // whole years: value >> times
        let (q, r, d, w, shifted) = layouter.assign_region(
            || "year shift",
            |mut region| {
                self.s_shift.enable(&mut region, 0)?;
                self.s_lookup.enable(&mut region, 0)?;
                region.assign_fixed(|| "shift tag", self.pconst, 0, || Value::known(Base::from(SHIFT_TAG)))?;
                value_cell.copy_advice(|| "value", &mut region, self.a[0], 0)?;
                let q = region.assign_advice(|| "q", self.a[1], 0, || tail.as_ref().map(|t| Base::from_u128(t.shift.q)))?;
                let r = region.assign_advice(|| "r", self.a[2], 0, || tail.as_ref().map(|t| Base::from_u128(t.shift.r)))?;
                region.assign_advice(|| "s", self.a[3], 0, || tail.as_ref().map(|t| Base::from(t.shift.shift)))?;
                region.assign_advice(|| "big", self.a[4], 0, || tail.as_ref().map(|t| Base::from(t.shift.big as u64)))?;
                region.assign_advice(|| "2^s", self.a[5], 0, || tail.as_ref().map(|t| Base::from_u128(t.shift.pow)))?;
                times.copy_advice(|| "times", &mut region, self.a[1], 1)?;
                let w = region.assign_advice(
                    || "w",
                    self.a[2],
                    1,
                    || tail.as_ref().map(|t| if t.shift.big { Base::from(t.times - W1_SHIFT_LIMIT) } else { Base::ZERO }),
                )?;
                let shifted = region.assign_advice(|| "shifted", self.a[3], 1, || tail.as_ref().map(|t| Base::from_u128(t.shift.shifted)))?;
                let d = region.assign_advice(|| "2^s - 1 - r", self.a[4], 1, || tail.as_ref().map(|t| Base::from_u128(t.shift.pow - 1 - t.shift.r)))?;
                Ok((q, r, d, w, shifted))
            },
        )?;
        for cell in [&q, &r, &d, &w] {
            self.range_check(layouter, cell)?;
        }

        // decayed = floor((shifted * F + 2^63) / 2^64)
        let (decayed, round_rem) = layouter.assign_region(
            || "round half up",
            |mut region| {
                self.s_final.enable(&mut region, 0)?;
                shifted.copy_advice(|| "shifted", &mut region, self.a[0], 0)?;
                f_last.copy_advice(|| "F", &mut region, self.a[1], 0)?;
                let decayed = region.assign_advice(|| "decayed", self.a[2], 0, || tail.as_ref().map(|t| Base::from(t.result)))?;
                let round_rem = region.assign_advice(|| "round rem", self.a[3], 0, || tail.as_ref().map(|t| Base::from(t.round_rem)))?;
                Ok((decayed, round_rem))
            },
        )?;
        self.range_check(layouter, &decayed)?;
        self.remainder_check(layouter, &round_rem)?;
        Ok(decayed)
    }

    /// 25 steps, one per bit of `rem`, exactly as unit.c. Returns `(rem, final factor)`.
    fn assign_bit_chain(
        &self,
        layouter: &mut impl Layouter<Base>,
        trace: Value<DecayTrace>,
    ) -> Result<(Cell, Cell), Error> {
        let (rem, f_last, f_next, f_rem) = layouter.assign_region(
            || "decay factor",
            |mut region| {
                let mut f = region.assign_advice_from_constant(|| "F0", self.a[0], 0, two_pow(64))?;
                let mut f_next = Vec::with_capacity(REM_BITS);
                let mut f_rem = Vec::with_capacity(REM_BITS);
                let mut rem = None;
                for i in 0..REM_BITS {
                    self.s_step.enable(&mut region, i)?;
                    region.assign_fixed(|| "P", self.pconst, i, || Value::known(Base::from(DECAY_POWERS[i])))?;
                    f_next.push(region.assign_advice(|| "F'", self.a[1], i, || trace.as_ref().map(|t| Base::from(t.f_next[i])))?);
                    f_rem.push(region.assign_advice(|| "F' rem", self.a[2], i, || trace.as_ref().map(|t| Base::from(t.f_rem[i])))?);
                    region.assign_advice(|| "bit", self.a[3], i, || trace.as_ref().map(|t| Base::from(t.bits[i] as u64)))?;
                    let acc = region.assign_advice(|| "rem >> i", self.a[4], i, || trace.as_ref().map(|t| Base::from(t.rem >> i)))?;
                    if i == 0 {
                        rem = Some(acc);
                    }
                    f = region.assign_advice(|| "F", self.a[0], i + 1, || trace.as_ref().map(|t| Base::from_u128(t.f[i + 1])))?;
                }
                region.assign_advice_from_constant(|| "rem >> 25", self.a[4], REM_BITS, Base::ZERO)?;
                Ok((rem.unwrap(), f, f_next, f_rem))
            },
        )?;
        for i in 0..REM_BITS {
            self.range_check(layouter, &f_next[i])?;
            self.remainder_check(layouter, &f_rem[i])?;
        }
        Ok((rem, f_last))
    }

    /// Five steps, one per 5-bit window of `rem`, each factor from the table.
    fn assign_window_chain(
        &self,
        layouter: &mut impl Layouter<Base>,
        trace: Value<WindowedTrace>,
    ) -> Result<(Cell, Cell), Error> {
        let (rem, f_last, f_next, f_rem) = layouter.assign_region(
            || "decay windows",
            |mut region| {
                let mut f = region.assign_advice_from_constant(|| "F0", self.a[0], 0, two_pow(64))?;
                let mut f_next = Vec::with_capacity(WINDOWS);
                let mut f_rem = Vec::with_capacity(WINDOWS);
                let mut rem = None;
                for j in 0..WINDOWS {
                    self.s_window.enable(&mut region, j)?;
                    self.s_lookup.enable(&mut region, j)?;
                    region.assign_fixed(|| "window", self.pconst, j, || Value::known(Base::from(j as u64)))?;
                    f_next.push(region.assign_advice(|| "F'", self.a[1], j, || trace.as_ref().map(|t| Base::from_u128(t.f[j + 1])))?);
                    f_rem.push(region.assign_advice(|| "F' rem", self.a[2], j, || trace.as_ref().map(|t| Base::from(t.f_rem[j])))?);
                    region.assign_advice(|| "digit", self.a[3], j, || trace.as_ref().map(|t| Base::from(t.digits[j])))?;
                    region.assign_advice(|| "factor", self.a[5], j, || trace.as_ref().map(|t| Base::from_u128(t.factors[j])))?;
                    let acc = region.assign_advice(
                        || "rem >> 5j",
                        self.a[4],
                        j,
                        || trace.as_ref().map(|t| Base::from(t.rem >> (j * WINDOW_BITS))),
                    )?;
                    if j == 0 {
                        rem = Some(acc);
                    }
                    f = region.assign_advice(|| "F", self.a[0], j + 1, || trace.as_ref().map(|t| Base::from_u128(t.f[j + 1])))?;
                }
                region.assign_advice_from_constant(|| "rem >> 25", self.a[4], WINDOWS, Base::ZERO)?;
                Ok((rem.unwrap(), f, f_next, f_rem))
            },
        )?;
        for j in 0..WINDOWS {
            self.range_check(layouter, &f_next[j])?;
            self.remainder_check(layouter, &f_rem[j])?;
        }
        Ok((rem, f_last))
    }
}

/// The parts of both traces the shared regions need.
struct Tail {
    times: u64,
    rem: u64,
    shift: decay::ShiftTrace,
    result: u64,
    round_rem: u64,
}

impl Tail {
    fn of_exact(t: &DecayTrace) -> Self {
        Self { times: t.times, rem: t.rem, shift: t.shift.clone(), result: t.result, round_rem: t.round_rem }
    }
    fn of_windowed(t: &WindowedTrace) -> Self {
        Self { times: t.times, rem: t.rem, shift: t.shift.clone(), result: t.result, round_rem: t.round_rem }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_gadgets::utilities::lookup_range_check::{LookupRangeCheck, PallasLookupRangeCheckConfig};
    use halo2_proofs::{
        circuit::SimpleFloorPlanner,
        dev::MockProver,
        plonk::{Circuit, Instance},
    };

    /// Smallest circuit around the chip: `now` public, one note, the decayed value public.
    #[derive(Clone, Debug, Default)]
    struct DecayTestCircuit<const WINDOWED: bool> {
        value: Value<Base>,
        t_note: Value<u64>,
    }

    #[derive(Clone, Debug)]
    struct TestConfig<const WINDOWED: bool> {
        decay: DecayConfig<PallasLookupRangeCheckConfig, WINDOWED>,
        advices: [Column<Advice>; 6],
        instance: Column<Instance>,
        /// in the action circuit this table comes from the Sinsemilla chip
        table_idx: TableColumn,
    }

    impl<const WINDOWED: bool> Circuit<Base> for DecayTestCircuit<WINDOWED> {
        type Config = TestConfig<WINDOWED>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<Base>) -> Self::Config {
            let advices = [
                meta.advice_column(), meta.advice_column(), meta.advice_column(),
                meta.advice_column(), meta.advice_column(), meta.advice_column(),
            ];
            let running_sum = meta.advice_column();
            meta.enable_equality(running_sum);
            let instance = meta.instance_column();
            meta.enable_equality(instance);
            let constants = meta.fixed_column();
            meta.enable_constant(constants);
            let table_idx = meta.lookup_table_column();
            let range_check = PallasLookupRangeCheckConfig::configure(meta, running_sum, table_idx);
            let pconst = meta.fixed_column();
            let tab_t = meta.lookup_table_column();
            let tab_x = meta.lookup_table_column();
            let tab_y = meta.lookup_table_column();
            let decay = DecayConfig::configure(meta, advices, pconst, tab_t, tab_x, tab_y, range_check);
            TestConfig { decay, advices, instance, table_idx }
        }

        fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<Base>) -> Result<(), Error> {
            // the 10-bit table the range check needs
            layouter.assign_table(
                || "10 bit table",
                |mut table| {
                    for i in 0..(1usize << 10) {
                        table.assign_cell(|| "idx", config.table_idx, i, || Value::known(Base::from(i as u64)))?;
                    }
                    Ok(())
                },
            )?;
            config.decay.load(&mut layouter)?;
            let now = layouter.assign_region(
                || "now",
                |mut region| region.assign_advice_from_instance(|| "now", config.instance, 0, config.advices[0], 0),
            )?;
            let value = layouter.assign_region(
                || "value",
                |mut region| region.assign_advice(|| "value", config.advices[1], 0, || self.value),
            )?;
            let t_note = layouter.assign_region(
                || "t_note",
                |mut region| region.assign_advice(|| "t_note", config.advices[2], 0, || self.t_note.map(Base::from)),
            )?;
            // the chip's precondition, which the note chip provides in the action circuit
            super::super::range::check_bits(&config.decay.lookup, &mut layouter, &value, 63)?;
            let decayed = config.decay.decay(&mut layouter, &now, &value, &t_note)?;
            layouter.constrain_instance(decayed.cell(), config.instance, 1)
        }
    }

    const K: u32 = 11;
    const NOW: u64 = 10_000_000_000;

    /// (value, duration, bit chain, windowed), both columns straight from unit.c
    fn vectors() -> Vec<(u64, u64, u64, u64)> {
        include_str!("../../test/decay_vectors.csv")
            .lines()
            .map(|line| {
                let mut it = line.split(',').map(|x| x.parse::<u64>().unwrap());
                (it.next().unwrap(), it.next().unwrap(), it.next().unwrap(), it.next().unwrap())
            })
            .collect()
    }

    fn check<const WINDOWED: bool>(value: u64, duration: u64, expected: u64) -> bool {
        let circuit = DecayTestCircuit::<WINDOWED> {
            value: Value::known(Base::from(value)),
            t_note: Value::known(NOW - duration),
        };
        let instance = vec![Base::from(NOW), Base::from(expected)];
        MockProver::run(K, &circuit, vec![instance]).unwrap().verify().is_ok()
    }

    #[test]
    fn bit_chain_chip_matches_unit_c() {
        for (value, duration, expected, _) in vectors().into_iter().step_by(30) {
            assert!(check::<false>(value, duration, expected), "value {value}, duration {duration}");
            if expected > 0 {
                assert!(!check::<false>(value, duration, expected - 1));
            }
        }
    }

    #[test]
    fn window_chip_matches_unit_c_windowed() {
        // the fourth column comes from grdd_unit_calculate_decay_windowed() in C
        for (value, duration, _, expected) in vectors().into_iter().step_by(30) {
            assert!(check::<true>(value, duration, expected), "value {value}, duration {duration}");
            if expected > 0 {
                assert!(!check::<true>(value, duration, expected - 1));
            }
        }
    }

    /// All 4252 vectors through both chips: `cargo test --release -- --ignored`
    #[test]
    #[ignore]
    fn both_chips_match_all_vectors() {
        for (value, duration, expected, windowed) in vectors() {
            assert!(check::<false>(value, duration, expected), "bit chain: {value}, {duration}");
            assert!(check::<true>(value, duration, windowed), "windows: {value}, {duration}");
        }
    }
}
