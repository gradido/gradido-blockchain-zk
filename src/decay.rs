//! Native mirror of `grdd_unit_calculate_decay` from gradido-blockchain-core (`src/data/unit.c`),
//! restricted to what a spend needs: non-negative value, non-negative duration.
//!
//! The circuit in `circuit::decay_bench` re-computes exactly these steps, so this module is
//! both the witness generator and the reference the tests compare against. The test vectors in
//! `test/decay_vectors.csv` come from the real C implementation (`test/gen_decay_vectors.c`).
//!
//! The C code, step by step:
//! 1. whole years become a right shift: `gdd >> times`, and more than 63 years yield 0
//! 2. the remaining seconds `rem < SECONDS_PER_YEAR < 2^25` select factors from `DECAY_POWERS`:
//!    `F = 2^64; for each set bit i of rem: F = floor(F * DECAY_POWERS[i] / 2^64)` (Q64.64)
//! 3. `result = round_half_up(shifted * F / 2^64)` = `floor((shifted * F + 2^63) / 2^64)`
//!
//! For `rem == 0` the C code returns `shifted` early; the formula above gives the same, because
//! `F` stays `2^64`.

pub const SECONDS_PER_YEAR: u64 = 31_556_952;
pub const DECAY_START_TIME: u64 = 1_620_927_991;

/// Bits of the remaining seconds: `SECONDS_PER_YEAR < 2^25`.
pub const REM_BITS: usize = 25;

/// Values are int64 and non-negative, so a shift by 63 or more always yields 0.
pub const W1_SHIFT_LIMIT: u64 = 63;

/// First `REM_BITS` entries of `DECAY_POWERS` in unit.c: `2^64 * 2^(-2^i / SECONDS_PER_YEAR)`.
pub const DECAY_POWERS: [u64; REM_BITS] = [
    18446743668527564940,
    18446743263345587163,
    18446742452981658309,
    18446740832253907398,
    18446737590798832767,
    18446731107890392267,
    18446718142080346313,
    18446692210487594564,
    18446640347411451525,
    18446536621696605848,
    18446329172016664620,
    18445914279655690837,
    18445084522928643346,
    18443425121448271984,
    18440106766335414243,
    18433471847125226169,
    18420209169759874097,
    18393712435208807257,
    18340833254760868098,
    18235530516106764452,
    18026735334708307356,
    17616289656815978922,
    16823221487369777986,
    15342587292489394070,
    12760787697116905635,
];

/// Every intermediate value the circuit needs as witness.
#[derive(Clone, Debug)]
pub struct DecayTrace {
    pub times: u64,
    pub rem: u64,
    pub shift: ShiftTrace,
    pub bits: [bool; REM_BITS],
    /// `f[0] = 2^64`, `f[i + 1]` after step `i`
    pub f: [u128; REM_BITS + 1],
    /// `floor(f[i] * DECAY_POWERS[i] / 2^64)` and its remainder, whether or not bit `i` is set
    pub f_next: [u64; REM_BITS],
    pub f_rem: [u64; REM_BITS],
    /// `shifted * f[REM_BITS] + 2^63 = result * 2^64 + round_rem`
    pub result: u64,
    pub round_rem: u64,
}

/// `value = q * 2^shift + r`, with `shift = 0` and result 0 once `k >= limit`.
#[derive(Clone, Debug)]
pub struct ShiftTrace {
    pub k: u64,
    pub big: bool,
    pub shift: u64,
    pub pow: u128,
    pub q: u128,
    pub r: u128,
    pub shifted: u128,
}

pub fn shift_trace(value: u128, k: u64, limit: u64) -> ShiftTrace {
    let big = k >= limit;
    let shift = if big { 0 } else { k };
    let pow = 1u128 << shift;
    let q = value >> shift;
    let r = value - q * pow;
    let shifted = if big { 0 } else { q };
    ShiftTrace { k, big, shift, pow, q, r, shifted }
}

pub fn decay_trace(value: u64, duration: u64) -> DecayTrace {
    assert!(value < 1 << 63, "grdd_unit is a non-negative int64");
    let times = duration / SECONDS_PER_YEAR;
    let rem = duration % SECONDS_PER_YEAR;
    let shift = shift_trace(value as u128, times, W1_SHIFT_LIMIT);

    let mut bits = [false; REM_BITS];
    let mut f = [0u128; REM_BITS + 1];
    let mut f_next = [0u64; REM_BITS];
    let mut f_rem = [0u64; REM_BITS];
    f[0] = 1u128 << 64;
    for i in 0..REM_BITS {
        bits[i] = (rem >> i) & 1 == 1;
        // f[i] <= 2^64 and DECAY_POWERS[i] < 2^64, so the product fits in u128
        let product = f[i] * DECAY_POWERS[i] as u128;
        f_next[i] = (product >> 64) as u64;
        f_rem[i] = product as u64;
        f[i + 1] = if bits[i] { f_next[i] as u128 } else { f[i] };
    }

    // shifted < 2^63 and f <= 2^64, so the product stays below 2^127
    let x = (shift.shifted as u128) * f[REM_BITS] + (1u128 << 63);
    DecayTrace {
        times,
        rem,
        shift,
        bits,
        f,
        f_next,
        f_rem,
        result: (x >> 64) as u64,
        round_rem: x as u64,
    }
}

/// Same result as `grdd_unit_calculate_decay(value, duration)` for `value, duration >= 0`.
pub fn decay(value: u64, duration: u64) -> u64 {
    decay_trace(value, duration).result
}

// ------------------------------------------------------------------ windowed decay factor
//
// The bit chain above truncates 25 times, once per bit of `rem`. Grouping the bits into five
// windows of five bits turns that into five multiplications, which is what the circuit pays
// for. The window factors come from the *same* chain, so no new constants and no floating
// point: `WINDOW_TABLE[j][c]` is the factor of `c * 2^(5j)` seconds.
//
// Fewer truncations mean the result is slightly closer to the ideal `2^(-x/year)` than the bit
// chain, so it is not bit-identical to today's unit.c; `tests_decay` measures the difference.

pub const WINDOW_BITS: usize = 5;
pub const WINDOWS: usize = REM_BITS.div_ceil(WINDOW_BITS);
pub const WINDOW_SIZE: usize = 1 << WINDOW_BITS;

/// One Q64.64 step: `floor(a * b / 2^64)`, where either factor may be exactly `2^64`.
fn mul_q64(a: u128, b: u128) -> u128 {
    const ONE: u128 = 1u128 << 64;
    if a == ONE {
        b
    } else if b == ONE {
        a
    } else {
        (a * b) >> 64
    }
}

/// `WINDOW_TABLE[j][c]` = decay factor of `c * 2^(WINDOW_BITS * j)` seconds, in Q64.64.
pub fn window_table() -> &'static [[u128; WINDOW_SIZE]; WINDOWS] {
    static TABLE: std::sync::OnceLock<[[u128; WINDOW_SIZE]; WINDOWS]> = std::sync::OnceLock::new();
    TABLE.get_or_init(|| {
        let mut table = [[0u128; WINDOW_SIZE]; WINDOWS];
        for (j, row) in table.iter_mut().enumerate() {
            for (c, entry) in row.iter_mut().enumerate() {
                let mut f = 1u128 << 64;
                for bit in 0..WINDOW_BITS {
                    if (c >> bit) & 1 == 1 {
                        f = mul_q64(f, DECAY_POWERS[bit + j * WINDOW_BITS] as u128);
                    }
                }
                *entry = f;
            }
        }
        table
    })
}

/// Witness for the windowed variant; same shape as [`DecayTrace`], five steps instead of 25.
#[derive(Clone, Debug)]
pub struct WindowedTrace {
    pub times: u64,
    pub rem: u64,
    pub shift: ShiftTrace,
    /// window digits, least significant first
    pub digits: [u64; WINDOWS],
    /// factor of each window from the table
    pub factors: [u128; WINDOWS],
    /// `f[0] = 2^64`, `f[j + 1]` after step `j`
    pub f: [u128; WINDOWS + 1],
    pub f_rem: [u64; WINDOWS],
    pub result: u64,
    pub round_rem: u64,
}

pub fn windowed_trace(value: u64, duration: u64) -> WindowedTrace {
    assert!(value < 1 << 63, "grdd_unit is a non-negative int64");
    let times = duration / SECONDS_PER_YEAR;
    let rem = duration % SECONDS_PER_YEAR;
    let shift = shift_trace(value as u128, times, W1_SHIFT_LIMIT);
    let table = window_table();

    let mut digits = [0u64; WINDOWS];
    let mut factors = [0u128; WINDOWS];
    let mut f = [0u128; WINDOWS + 1];
    let mut f_rem = [0u64; WINDOWS];
    f[0] = 1u128 << 64;
    for j in 0..WINDOWS {
        digits[j] = (rem >> (j * WINDOW_BITS)) & (WINDOW_SIZE as u64 - 1);
        factors[j] = table[j][digits[j] as usize];
        f[j + 1] = mul_q64(f[j], factors[j]);
        // the remainder the circuit needs: f[j] * factor = f[j+1] * 2^64 + f_rem[j]
        f_rem[j] = if f[j] == 1u128 << 64 || factors[j] == 1u128 << 64 {
            0
        } else {
            (f[j] * factors[j]) as u64
        };
    }

    let x = (shift.shifted as u128) * f[WINDOWS] + (1u128 << 63);
    WindowedTrace {
        times,
        rem,
        shift,
        digits,
        factors,
        f,
        f_rem,
        result: (x >> 64) as u64,
        round_rem: x as u64,
    }
}

/// Decay with the windowed factor chain.
pub fn decay_windowed(value: u64, duration: u64) -> u64 {
    windowed_trace(value, duration).result
}
