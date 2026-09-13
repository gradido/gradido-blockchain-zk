//! Exact range checks on top of the 10-bit lookup the Sinsemilla chip already loads.

use halo2_gadgets::utilities::lookup_range_check::PallasLookupRangeCheck;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter},
    plonk::Error,
};
use pasta_curves::pallas;

type Base = pallas::Base;

/// Word size of the lookup.
const WORD_BITS: u32 = 10;

/// `cell < 2^bits`, exactly.
///
/// Whole 10-bit words go through the running sum; for the bits that do not fill a word, the
/// running sum stops early and its last element — `(x - low words) / 2^(10 * words)` — gets a
/// short check on the remaining bits. That pins `x` to `bits` bits without a second decomposition.
pub fn check_bits<Lookup: PallasLookupRangeCheck>(
    lookup: &Lookup,
    layouter: &mut impl Layouter<Base>,
    cell: &AssignedCell<Base, Base>,
    bits: u32,
) -> Result<(), Error> {
    let words = (bits / WORD_BITS) as usize;
    let extra = (bits % WORD_BITS) as usize;
    if words == 0 {
        return lookup.copy_short_check(layouter.namespace(|| "short range"), cell.clone(), extra);
    }
    let zs = lookup.copy_check(layouter.namespace(|| "range"), cell.clone(), words, extra == 0)?;
    if extra == 0 {
        return Ok(());
    }
    lookup.copy_short_check(layouter.namespace(|| "range top"), zs[words].clone(), extra)
}
