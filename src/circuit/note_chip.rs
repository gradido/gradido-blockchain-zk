//! Note commitment, nullifier and incoming viewing key in circuit, over the note of `crate::note`.
//!
//! Everything the commitment binds is passed in as an already assigned cell, so the value the
//! decay gadget works with and the value inside the commitment are literally the same cell.
//! That is the whole reason for hashing field elements with Poseidon instead of bits with
//! Sinsemilla — no decomposition, no canonicity chip, nothing that can drift apart.
//!
//! Exact widths matter for two reasons: the parts that sit *below* another part in a packed
//! element (`value` under `t_note`, `kind` under `expiry`) must have their exact width, or two
//! different notes could pack to the same element; and `value` must be the 63 bits of a
//! non-negative int64, because the decay and the value commitment rely on that bound.

use halo2_gadgets::{
    poseidon::{
        primitives::{ConstantLength, P128Pow5T3},
        Hash as PoseidonHash, Pow5Chip as PoseidonChip, Pow5Config as PoseidonConfig,
    },
    utilities::lookup_range_check::PallasLookupRangeCheck,
};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
    poly::Rotation,
};
use pasta_curves::pallas;

use super::range;
use crate::note::{EXPIRY_BITS, NOTE_KIND_BITS, TIMESTAMP_BITS, VALUE_BITS};

type Base = pallas::Base;
type Cell = AssignedCell<Base, Base>;

pub use crate::note::COMMIT_ELEMENTS;

fn two_pow(bits: u32) -> Base {
    Base::from_u128(1u128 << bits)
}

use ff::PrimeField;

#[derive(Clone, Debug)]
pub struct NoteChipConfig<Lookup: PallasLookupRangeCheck> {
    a: [Column<Advice>; 5],
    s_pack: Selector,
    poseidon: PoseidonConfig<Base, 3, 2>,
    lookup: Lookup,
}

/// The cells a note is built from. All of them are bound by the commitment.
#[derive(Clone, Debug)]
pub struct NoteCells {
    pub community: Cell,
    pub coin_community: Cell,
    /// nominal value, exactly 63 bits
    pub value: Cell,
    /// timestamp the value refers to
    pub t_note: Cell,
    pub kind: Cell,
    pub expiry_epoch: Cell,
    /// `g_d` of the address; committed so that `pk_d = [ivk] g_d` cannot be met with a made-up base
    pub g_d_x: Cell,
    pub g_d_y: Cell,
    pub pk_d_x: Cell,
    pub pk_d_y: Cell,
    pub rho: Cell,
    pub psi: Cell,
    pub memo_cm: Cell,
    pub rcm: Cell,
}

impl<Lookup: PallasLookupRangeCheck> NoteChipConfig<Lookup> {
    pub fn configure(
        meta: &mut ConstraintSystem<Base>,
        a: [Column<Advice>; 5],
        poseidon: PoseidonConfig<Base, 3, 2>,
        lookup: Lookup,
    ) -> Self {
        for col in a.iter() {
            meta.enable_equality(*col);
        }
        let s_pack = meta.selector();

        // value, t_note, amount, kind, expiry, meta — all in one row
        meta.create_gate("pack note fields", |meta| {
            let s = meta.query_selector(s_pack);
            let value = meta.query_advice(a[0], Rotation::cur());
            let t_note = meta.query_advice(a[1], Rotation::cur());
            let amount = meta.query_advice(a[2], Rotation::cur());
            let kind = meta.query_advice(a[3], Rotation::cur());
            let expiry = meta.query_advice(a[4], Rotation::cur());
            let meta_elem = meta.query_advice(a[2], Rotation::next());
            vec![
                s.clone() * (amount - value - t_note * Expression::Constant(two_pow(VALUE_BITS))),
                s * (meta_elem - kind - expiry * Expression::Constant(two_pow(NOTE_KIND_BITS))),
            ]
        });

        Self { a, s_pack, poseidon, lookup }
    }

    /// Range checks and packs the parts, then returns `cm = Poseidon(...)`.
    pub fn commit(
        &self,
        layouter: &mut impl Layouter<Base>,
        note: &NoteCells,
    ) -> Result<Cell, Error> {
        range::check_bits(&self.lookup, layouter, &note.value, VALUE_BITS)?;
        range::check_bits(&self.lookup, layouter, &note.t_note, TIMESTAMP_BITS)?;
        range::check_bits(&self.lookup, layouter, &note.kind, NOTE_KIND_BITS)?;
        range::check_bits(&self.lookup, layouter, &note.expiry_epoch, EXPIRY_BITS)?;

        let (amount, meta_elem) = layouter.assign_region(
            || "pack note",
            |mut region| {
                self.s_pack.enable(&mut region, 0)?;
                note.value.copy_advice(|| "value", &mut region, self.a[0], 0)?;
                note.t_note.copy_advice(|| "t_note", &mut region, self.a[1], 0)?;
                let amount = region.assign_advice(
                    || "value | t_note",
                    self.a[2],
                    0,
                    || {
                        note.value
                            .value()
                            .zip(note.t_note.value())
                            .map(|(v, t)| *v + *t * two_pow(VALUE_BITS))
                    },
                )?;
                note.kind.copy_advice(|| "kind", &mut region, self.a[3], 0)?;
                note.expiry_epoch.copy_advice(|| "expiry", &mut region, self.a[4], 0)?;
                let meta_elem = region.assign_advice(
                    || "kind | expiry",
                    self.a[2],
                    1,
                    || {
                        note.kind
                            .value()
                            .zip(note.expiry_epoch.value())
                            .map(|(k, e)| *k + *e * two_pow(NOTE_KIND_BITS))
                    },
                )?;
                Ok((amount, meta_elem))
            },
        )?;

        let elements: [Cell; COMMIT_ELEMENTS] = [
            note.community.clone(),
            note.coin_community.clone(),
            amount,
            meta_elem,
            note.g_d_x.clone(),
            note.g_d_y.clone(),
            note.pk_d_x.clone(),
            note.pk_d_y.clone(),
            note.rho.clone(),
            note.psi.clone(),
            note.memo_cm.clone(),
            note.rcm.clone(),
        ];
        PoseidonHash::<_, _, P128Pow5T3, ConstantLength<COMMIT_ELEMENTS>, 3, 2>::init(
            PoseidonChip::construct(self.poseidon.clone()),
            layouter.namespace(|| "note commit init"),
        )?
        .hash(layouter.namespace(|| "note commit"), elements)
    }

    /// `nf = Poseidon(nk, rho, cm)`
    pub fn nullifier(
        &self,
        layouter: &mut impl Layouter<Base>,
        nk: &Cell,
        rho: &Cell,
        cm: &Cell,
    ) -> Result<Cell, Error> {
        self.hash3(layouter, "nullifier", [nk.clone(), rho.clone(), cm.clone()])
    }

    /// `ivk = Poseidon(ak_x, nk, rivk)`, see `crate::keys::commit_ivk`. Ties the key that
    /// opens the address to the `nk` of the nullifier and the `ak` of the spend authorisation.
    pub fn commit_ivk(
        &self,
        layouter: &mut impl Layouter<Base>,
        ak_x: &Cell,
        nk: &Cell,
        rivk: &Cell,
    ) -> Result<Cell, Error> {
        self.hash3(layouter, "commit ivk", [ak_x.clone(), nk.clone(), rivk.clone()])
    }

    fn hash3(&self, layouter: &mut impl Layouter<Base>, name: &'static str, message: [Cell; 3]) -> Result<Cell, Error> {
        PoseidonHash::<_, _, P128Pow5T3, ConstantLength<3>, 3, 2>::init(
            PoseidonChip::construct(self.poseidon.clone()),
            layouter.namespace(|| name),
        )?
        .hash(layouter.namespace(|| name), message)
    }
}

// the native counterparts live in `crate::note` (Note::commitment, Note::nullifier) and
// `crate::keys` (commit_ivk)
