//! One shielded action: spend one note, create one note. A transfer consists of several actions
//! in one proof (`crate::bundle`); the values balance across them through the value commitments
//! and the binding signature, not inside a single action.
//!
//! Per action it proves:
//! * the note commitment of the spent note (Poseidon over the note fields, `super::note_chip`)
//! * that its commitment sits in the note commitment tree (Sinsemilla Merkle path, depth 32)
//! * the key: `ivk = Poseidon(ak_x, nk, rivk)`, so the `ak` of the spend authorisation, the `nk`
//!   of the nullifier and the `ivk` of the address all belong to one key
//! * the address: `pk_d = [ivk] g_d`, with `g_d` and `pk_d` bound into the commitment
//! * its nullifier `Poseidon(nk, rho, cm)`
//! * the created note, whose timestamp is the public `now` and whose `rho` is the nullifier
//!   just derived
//! * the net value commitment `cv_net = [decayed(v_old) - v_new] V + [rcv] R`, public, with the
//!   spent value — the committed cell itself — decayed to `now` exactly like unit.c
//!   (`super::decay_chip`)
//! * the rerandomised spend authorisation key `rk = ak + [alpha] G`, public
//! * a dummy spend (value 0) may use any tree position: `v_old = 0 or root = anchor`
//! * both notes belong to the public community and carry its coin
//!
//! Everything the commitment binds is passed as an assigned cell, so value, timestamp and
//! address inside the note are the very cells the decay gadget, the key derivation and the
//! address check use. Sinsemilla is only used for the Merkle path.
//!
//! Public inputs per action: `[anchor, nf, rk_x, rk_y, cm_new, cv_net_x, cv_net_y, now, community]`.
//!
//! Not enforced yet: the time lock of deferred notes (E8) and note expiry (E10). `kind` and
//! `expiry_epoch` are committed and range checked, nothing more.

use std::sync::OnceLock;

use group::{Curve, GroupEncoding};
use halo2_gadgets::{
    ecc::{
        chip::{BaseFieldElem, EccChip, EccConfig, FixedPoint, FullScalar, ShortScalar, H},
        CircuitVersion, FixedPoint as EccFixedPoint, FixedPointShort, FixedPoints,
        NonIdentityPoint, ScalarFixed, ScalarFixedShort, ScalarVar,
    },
    poseidon::{primitives::P128Pow5T3, Pow5Chip as PoseidonChip},
    sinsemilla::{
        chip::{SinsemillaChip, SinsemillaConfig},
        merkle::{
            chip::{MerkleChip, MerkleConfig},
            MerklePath,
        },
        primitives as sinsemilla,
        CommitDomains, HashDomains,
    },
    utilities::lookup_range_check::{LookupRangeCheck, PallasLookupRangeCheckConfig},
};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance, Selector},
    poly::Rotation,
};
use pasta_curves::pallas;

use super::decay_chip::DecayConfig;
use super::note_chip::{NoteCells, NoteChipConfig};
use crate::keys::FullViewingKey;
use crate::note::Note;

pub const MERKLE_DEPTH: usize = 32;
/// Same as orchard's action circuit.
pub const K: u32 = 11;
/// 10 bit words per message piece; the pieces below add up to ~1100 bits, like orchard's
/// note commitment input.
pub const PIECE_WORDS: [usize; 5] = [11, 25, 25, 25, 25];

type Base = pallas::Base;
type Cell = AssignedCell<Base, Base>;
type Lookup = PallasLookupRangeCheckConfig;
type SliceSinsemillaChip = SinsemillaChip<GradidoHashDomains, GradidoCommitDomains, GradidoFixedBases, Lookup>;
type SliceMerkleChip = MerkleChip<GradidoHashDomains, GradidoCommitDomains, GradidoFixedBases, Lookup>;

// ---------------------------------------------------------------- fixed bases and domains
//
// Every fixed base the circuit multiplies has a window table. They are precomputed constants in
// `fixed_bases_generated.rs` (see examples/gen_fixed_bases.rs), as Orchard does it; searching
// them at runtime took minutes. The points are the ones `crate::signature` uses, so the
// commitments and keys the circuit exposes are exactly what the signatures are checked against.

use super::fixed_bases_generated as tables;

fn point_from(bytes: &[u8; 32]) -> pallas::Affine {
    Option::<pallas::Affine>::from(pallas::Affine::from_bytes(bytes)).expect("generated point")
}

fn merkle_crh_domain() -> &'static sinsemilla::CommitDomain {
    static D: OnceLock<sinsemilla::CommitDomain> = OnceLock::new();
    D.get_or_init(|| sinsemilla::CommitDomain::new("gradido:MerkleCRH"))
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct GradidoFixedBases;

/// Bases for full width scalar multiplication.
#[derive(Debug, Eq, PartialEq, Clone)]
pub enum FullWidth {
    /// `R`, the randomness base of the value commitment
    ValueRandomness,
    /// `G`, the basepoint of the spend authorisation signature
    SpendAuth,
}

/// Base for base field element multiplication. Nothing uses it since the nullifier became a
/// Poseidon hash, but the gadget needs one; it shares the spend authorisation table.
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct NullifierK;

/// `V`, the value base of the value commitment, multiplied by a signed 64 bit value.
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct ShortBase;

impl FixedPoint<pallas::Affine> for FullWidth {
    type FixedScalarKind = FullScalar;
    fn generator(&self) -> pallas::Affine {
        match self {
            Self::ValueRandomness => point_from(&tables::RANDOMNESS_R_POINT),
            Self::SpendAuth => point_from(&tables::SPEND_AUTH_G_POINT),
        }
    }
    fn u(&self) -> Vec<[[u8; 32]; H]> {
        match self {
            Self::ValueRandomness => tables::RANDOMNESS_R_U.to_vec(),
            Self::SpendAuth => tables::SPEND_AUTH_G_U.to_vec(),
        }
    }
    fn z(&self) -> Vec<u64> {
        match self {
            Self::ValueRandomness => tables::RANDOMNESS_R_Z.to_vec(),
            Self::SpendAuth => tables::SPEND_AUTH_G_Z.to_vec(),
        }
    }
}

impl FixedPoint<pallas::Affine> for NullifierK {
    type FixedScalarKind = BaseFieldElem;
    fn generator(&self) -> pallas::Affine {
        point_from(&tables::SPEND_AUTH_G_POINT)
    }
    fn u(&self) -> Vec<[[u8; 32]; H]> {
        tables::SPEND_AUTH_G_U.to_vec()
    }
    fn z(&self) -> Vec<u64> {
        tables::SPEND_AUTH_G_Z.to_vec()
    }
}

impl FixedPoint<pallas::Affine> for ShortBase {
    type FixedScalarKind = ShortScalar;
    fn generator(&self) -> pallas::Affine {
        point_from(&tables::VALUE_V_POINT)
    }
    fn u(&self) -> Vec<[[u8; 32]; H]> {
        tables::VALUE_V_U.to_vec()
    }
    fn z(&self) -> Vec<u64> {
        tables::VALUE_V_Z.to_vec()
    }
}

impl FixedPoints<pallas::Affine> for GradidoFixedBases {
    type FullScalar = FullWidth;
    type ShortScalar = ShortBase;
    type Base = NullifierK;
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum GradidoHashDomains {
    NoteCommit,
    MerkleCrh,
}

impl HashDomains<pallas::Affine> for GradidoHashDomains {
    #[allow(non_snake_case)]
    fn Q(&self) -> pallas::Affine {
        // the note commitment is Poseidon (`note_chip`); only the Merkle path hashes with Sinsemilla
        merkle_crh_domain().Q().to_affine()
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum GradidoCommitDomains {
    NoteCommit,
}

impl CommitDomains<pallas::Affine, GradidoFixedBases, GradidoHashDomains> for GradidoCommitDomains {
    fn r(&self) -> FullWidth {
        FullWidth::ValueRandomness
    }
    fn hash_domain(&self) -> GradidoHashDomains {
        GradidoHashDomains::NoteCommit
    }
}

// ------------------------------------------------------------------------------- circuit

pub const INSTANCE_ANCHOR: usize = 0;
pub const INSTANCE_NF: usize = 1;
pub const INSTANCE_RK_X: usize = 2;
pub const INSTANCE_RK_Y: usize = 3;
pub const INSTANCE_CM_NEW: usize = 4;
pub const INSTANCE_CV_X: usize = 5;
pub const INSTANCE_CV_Y: usize = 6;
pub const INSTANCE_NOW: usize = 7;
pub const INSTANCE_COMMUNITY: usize = 8;

fn low_u64(v: &Base) -> u64 {
    use ff::PrimeField;
    u64::from_le_bytes(v.to_repr()[..8].try_into().unwrap())
}

/// One witnessed field element in its own row.
fn witness_cell(
    layouter: &mut impl Layouter<Base>,
    name: &'static str,
    column: Column<Advice>,
    value: Value<Base>,
) -> Result<Cell, Error> {
    layouter.assign_region(|| name, |mut region| region.assign_advice(|| name, column, 0, || value))
}

#[derive(Clone, Debug)]
pub struct ActionSliceConfig<const WINDOWED: bool> {
    primary: Column<Instance>,
    advices: [Column<Advice>; 10],
    q_action: Selector,
    ecc: EccConfig<GradidoFixedBases, Lookup>,
    merkle_1: MerkleConfig<GradidoHashDomains, GradidoCommitDomains, GradidoFixedBases, Lookup>,
    merkle_2: MerkleConfig<GradidoHashDomains, GradidoCommitDomains, GradidoFixedBases, Lookup>,
    sinsemilla_1: SinsemillaConfig<GradidoHashDomains, GradidoCommitDomains, GradidoFixedBases, Lookup>,
    note: NoteChipConfig<Lookup>,
    /// only configured when the circuit uses it, so the baseline pays nothing for it
    decay: Option<DecayConfig<Lookup, WINDOWED>>,
}

/// Everything the prover knows. `community` and `now` are public inputs, so they are not
/// witnessed; the created note takes its timestamp and `rho` from the circuit.
#[derive(Clone, Debug, Default)]
pub struct ActionSliceCircuit<const WITH_DECAY: bool, const WINDOWED: bool> {
    // the spent note
    pub value: Value<u64>,
    pub t_note: Value<u64>,
    pub kind: Value<u64>,
    pub expiry: Value<u64>,
    pub g_d: Value<pallas::Affine>,
    pub rho: Value<Base>,
    pub psi: Value<Base>,
    pub memo_cm: Value<Base>,
    pub rcm: Value<Base>,
    // the key that owns it: pk_d = [ivk] g_d with ivk = Poseidon(ak_x, nk, rivk)
    pub ak: Value<pallas::Affine>,
    pub nk: Value<Base>,
    pub rivk: Value<Base>,
    // its place in the tree
    pub leaf_pos: Value<u32>,
    pub path: Value<[Base; MERKLE_DEPTH]>,
    // the created note
    pub new_value: Value<u64>,
    pub new_g_d: Value<pallas::Affine>,
    pub new_pk_d: Value<pallas::Affine>,
    pub new_kind: Value<u64>,
    pub new_expiry: Value<u64>,
    pub new_psi: Value<Base>,
    pub new_memo_cm: Value<Base>,
    pub new_rcm: Value<Base>,
    // value commitment and spend authorisation
    pub rcv: Value<pallas::Scalar>,
    pub alpha: Value<pallas::Scalar>,
}

fn affine(x: Base, y: Base) -> pallas::Affine {
    use pasta_curves::arithmetic::CurveAffine;
    Option::from(pallas::Affine::from_xy(x, y)).expect("note points are on the curve")
}

impl<const WITH_DECAY: bool, const WINDOWED: bool> ActionSliceCircuit<WITH_DECAY, WINDOWED> {
    /// The witness for spending `spent`, owned by `fvk`, into `created`.
    pub fn new(
        spent: &Note,
        fvk: &FullViewingKey,
        leaf_pos: u32,
        path: [Base; MERKLE_DEPTH],
        created: &Note,
        rcv: pallas::Scalar,
        alpha: pallas::Scalar,
    ) -> Self {
        Self {
            value: Value::known(spent.value),
            t_note: Value::known(spent.t_note),
            kind: Value::known(spent.kind as u64),
            expiry: Value::known(spent.expiry_epoch),
            g_d: Value::known(affine(spent.g_d_x, spent.g_d_y)),
            rho: Value::known(spent.rho),
            psi: Value::known(spent.psi),
            memo_cm: Value::known(spent.memo_cm),
            rcm: Value::known(spent.rcm),
            ak: Value::known(fvk.ak),
            nk: Value::known(fvk.nk),
            rivk: Value::known(fvk.rivk),
            leaf_pos: Value::known(leaf_pos),
            path: Value::known(path),
            new_value: Value::known(created.value),
            new_g_d: Value::known(affine(created.g_d_x, created.g_d_y)),
            new_pk_d: Value::known(affine(created.pk_d_x, created.pk_d_y)),
            new_kind: Value::known(created.kind as u64),
            new_expiry: Value::known(created.expiry_epoch),
            new_psi: Value::known(created.psi),
            new_memo_cm: Value::known(created.memo_cm),
            new_rcm: Value::known(created.rcm),
            rcv: Value::known(rcv),
            alpha: Value::known(alpha),
        }
    }

    /// `[anchor, nf, rk_x, rk_y, cm_new, cv_net_x, cv_net_y, now, community]`
    pub fn instance(
        community: Base,
        anchor: Base,
        nullifier: Base,
        rk: pallas::Affine,
        cm_new: Base,
        cv_net: pallas::Affine,
        now: u64,
    ) -> Vec<Base> {
        let (rk_x, rk_y) = native::coordinates(rk);
        let (cv_x, cv_y) = native::coordinates(cv_net);
        vec![anchor, nullifier, rk_x, rk_y, cm_new, cv_x, cv_y, Base::from(now), community]
    }
}

impl<const WITH_DECAY: bool, const WINDOWED: bool> Circuit<Base> for ActionSliceCircuit<WITH_DECAY, WINDOWED> {
    type Config = ActionSliceConfig<WINDOWED>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Base>) -> Self::Config {
        let advices = [
            meta.advice_column(), meta.advice_column(), meta.advice_column(), meta.advice_column(),
            meta.advice_column(), meta.advice_column(), meta.advice_column(), meta.advice_column(),
            meta.advice_column(), meta.advice_column(),
        ];
        for advice in advices.iter() {
            meta.enable_equality(*advice);
        }
        let primary = meta.instance_column();
        meta.enable_equality(primary);

        // the two rules that tie an action together, as in orchard:
        //   decayed(v_old) - v_new = magnitude * sign
        //   v_old = 0 or root = anchor
        let q_action = meta.selector();
        meta.create_gate("action", |meta| {
            let q = meta.query_selector(q_action);
            let decayed = meta.query_advice(advices[0], Rotation::cur());
            let v_new = meta.query_advice(advices[1], Rotation::cur());
            let magnitude = meta.query_advice(advices[2], Rotation::cur());
            let sign = meta.query_advice(advices[3], Rotation::cur());
            let v_old = meta.query_advice(advices[4], Rotation::cur());
            let root = meta.query_advice(advices[5], Rotation::cur());
            let anchor = meta.query_advice(advices[6], Rotation::cur());
            vec![
                q.clone() * (decayed - v_new - magnitude * sign),
                q * v_old * (root - anchor),
            ]
        });

        let table_idx = meta.lookup_table_column();
        let lookup = (table_idx, meta.lookup_table_column(), meta.lookup_table_column());
        let lagrange_coeffs = [
            meta.fixed_column(), meta.fixed_column(), meta.fixed_column(), meta.fixed_column(),
            meta.fixed_column(), meta.fixed_column(), meta.fixed_column(), meta.fixed_column(),
        ];
        meta.enable_constant(lagrange_coeffs[0]);
        let rc_a = lagrange_coeffs[2..5].try_into().unwrap();
        let rc_b = lagrange_coeffs[5..8].try_into().unwrap();

        let range_check = Lookup::configure(meta, advices[9], table_idx);
        let ecc = EccChip::<GradidoFixedBases, Lookup>::configure(meta, advices, lagrange_coeffs, range_check);
        let poseidon = PoseidonChip::configure::<P128Pow5T3>(
            meta,
            advices[6..9].try_into().unwrap(),
            advices[5],
            rc_a,
            rc_b,
        );

        // Sinsemilla is only needed for the Merkle path now
        let sinsemilla_1 = SliceSinsemillaChip::configure(
            meta,
            advices[..5].try_into().unwrap(),
            advices[6],
            lagrange_coeffs[0],
            lookup,
            range_check,
            false,
        );
        let merkle_1 = SliceMerkleChip::configure(meta, sinsemilla_1.clone());
        let sinsemilla_2 = SliceSinsemillaChip::configure(
            meta,
            advices[5..].try_into().unwrap(),
            advices[7],
            lagrange_coeffs[1],
            lookup,
            range_check,
            false,
        );
        let merkle_2 = SliceMerkleChip::configure(meta, sinsemilla_2);

        let note = NoteChipConfig::configure(
            meta,
            advices[..5].try_into().unwrap(),
            poseidon,
            range_check,
        );

        let decay = if WITH_DECAY {
            let decay_pconst = meta.fixed_column();
            let decay_tab_t = meta.lookup_table_column();
            let decay_tab_x = meta.lookup_table_column();
            let decay_tab_y = meta.lookup_table_column();
            Some(DecayConfig::configure(
                meta,
                advices[..6].try_into().unwrap(),
                decay_pconst,
                decay_tab_t,
                decay_tab_x,
                decay_tab_y,
                range_check,
            ))
        } else {
            None
        };

        ActionSliceConfig { primary, advices, q_action, ecc, merkle_1, merkle_2, sinsemilla_1, note, decay }
    }

    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<Base>) -> Result<(), Error> {
        SliceSinsemillaChip::load(config.sinsemilla_1.clone(), &mut layouter)?;
        if let Some(decay) = config.decay.as_ref() {
            decay.load(&mut layouter)?;
        }
        let ecc_chip = EccChip::construct(config.ecc.clone(), CircuitVersion::AnchoredBase);
        let a = config.advices;

        // public `now` and community; the notes of every action belong to this community and
        // carry its own coin (cross community coins are not supported yet, see privacy_todo.md)
        let now = layouter.assign_region(
            || "now",
            |mut region| region.assign_advice_from_instance(|| "now", config.primary, INSTANCE_NOW, a[0], 0),
        )?;
        let community = layouter.assign_region(
            || "community",
            |mut region| {
                region.assign_advice_from_instance(|| "community", config.primary, INSTANCE_COMMUNITY, a[1], 0)
            },
        )?;

        // witnesses of the spent note, one row each so the layout stays readable
        let value = witness_cell(&mut layouter, "value", a[2], self.value.map(Base::from))?;
        let t_note = witness_cell(&mut layouter, "t_note", a[3], self.t_note.map(Base::from))?;
        let kind = witness_cell(&mut layouter, "kind", a[0], self.kind.map(Base::from))?;
        let expiry = witness_cell(&mut layouter, "expiry", a[1], self.expiry.map(Base::from))?;
        let rho = witness_cell(&mut layouter, "rho", a[2], self.rho)?;
        let psi = witness_cell(&mut layouter, "psi", a[3], self.psi)?;
        let memo_cm = witness_cell(&mut layouter, "memo_cm", a[4], self.memo_cm)?;
        let rcm = witness_cell(&mut layouter, "rcm", a[0], self.rcm)?;
        let nk = witness_cell(&mut layouter, "nk", a[1], self.nk)?;
        let rivk = witness_cell(&mut layouter, "rivk", a[2], self.rivk)?;

        // the key: ivk is derived from the same ak the spend authorisation uses and the same nk
        // the nullifier uses, so a note opens only for the key that also signs and nullifies it
        let ak = NonIdentityPoint::new(ecc_chip.clone(), layouter.namespace(|| "ak"), self.ak)?;
        let ivk = config.note.commit_ivk(&mut layouter, &ak.inner().x(), &nk, &rivk)?;

        // the address of the spent note: pk_d = [ivk] g_d, with g_d bound by the commitment
        let g_d = NonIdentityPoint::new(ecc_chip.clone(), layouter.namespace(|| "g_d"), self.g_d)?;
        let ivk_scalar = ScalarVar::from_base(ecc_chip.clone(), layouter.namespace(|| "ivk scalar"), &ivk)?;
        let (pk_d, _) = g_d.mul(layouter.namespace(|| "[ivk] g_d"), ivk_scalar)?;

        let old_note = NoteCells {
            community: community.clone(),
            coin_community: community.clone(),
            value: value.clone(),
            t_note: t_note.clone(),
            kind,
            expiry_epoch: expiry,
            g_d_x: g_d.inner().x(),
            g_d_y: g_d.inner().y(),
            pk_d_x: pk_d.inner().x(),
            pk_d_y: pk_d.inner().y(),
            rho: rho.clone(),
            psi,
            memo_cm,
            rcm,
        };
        let cm_old = config.note.commit(&mut layouter, &old_note)?;

        // the spent note is in the tree — unless it is a dummy of value 0
        let merkle_path = MerklePath::construct(
            [
                SliceMerkleChip::construct(config.merkle_1.clone()),
                SliceMerkleChip::construct(config.merkle_2.clone()),
            ],
            GradidoHashDomains::MerkleCrh,
            self.leaf_pos,
            self.path,
        );
        let root = merkle_path.calculate_root(layouter.namespace(|| "merkle root"), cm_old.clone())?;

        // its nullifier
        let nf = config.note.nullifier(&mut layouter, &nk, &rho, &cm_old)?;
        layouter.constrain_instance(nf.cell(), config.primary, INSTANCE_NF)?;

        // spend authorisation: rk = ak + [alpha] G
        let alpha_scalar = ScalarFixed::new(ecc_chip.clone(), layouter.namespace(|| "alpha"), self.alpha)?;
        let (alpha_g, _) = EccFixedPoint::from_inner(ecc_chip.clone(), FullWidth::SpendAuth)
            .mul(layouter.namespace(|| "[alpha] G"), alpha_scalar)?;
        let rk = alpha_g.add(layouter.namespace(|| "rk"), &ak)?;
        layouter.constrain_instance(rk.inner().x().cell(), config.primary, INSTANCE_RK_X)?;
        layouter.constrain_instance(rk.inner().y().cell(), config.primary, INSTANCE_RK_Y)?;

        // the spent value at `now`, computed on the very cells the commitment holds
        let decayed = if WITH_DECAY {
            config.decay.as_ref().expect("decay config").decay(&mut layouter, &now, &value, &t_note)?
        } else {
            value.clone()
        };

        // the created note, dated now, with rho = nf
        let new_value = witness_cell(&mut layouter, "new value", a[3], self.new_value.map(Base::from))?;
        let new_g_d = NonIdentityPoint::new(ecc_chip.clone(), layouter.namespace(|| "new g_d"), self.new_g_d)?;
        let new_pk_d = NonIdentityPoint::new(ecc_chip.clone(), layouter.namespace(|| "new pk_d"), self.new_pk_d)?;
        let new_note = NoteCells {
            community: community.clone(),
            coin_community: community,
            value: new_value.clone(),
            t_note: now.clone(),
            kind: witness_cell(&mut layouter, "new kind", a[0], self.new_kind.map(Base::from))?,
            expiry_epoch: witness_cell(&mut layouter, "new expiry", a[1], self.new_expiry.map(Base::from))?,
            g_d_x: new_g_d.inner().x(),
            g_d_y: new_g_d.inner().y(),
            pk_d_x: new_pk_d.inner().x(),
            pk_d_y: new_pk_d.inner().y(),
            rho: nf,
            psi: witness_cell(&mut layouter, "new psi", a[2], self.new_psi)?,
            memo_cm: witness_cell(&mut layouter, "new memo_cm", a[3], self.new_memo_cm)?,
            rcm: witness_cell(&mut layouter, "new rcm", a[4], self.new_rcm)?,
        };
        let cm_new = config.note.commit(&mut layouter, &new_note)?;
        layouter.constrain_instance(cm_new.cell(), config.primary, INSTANCE_CM_NEW)?;

        // decayed(v_old) - v_new = magnitude * sign, and v_old = 0 or root = anchor
        let (magnitude, sign) = layouter.assign_region(
            || "action checks",
            |mut region| {
                config.q_action.enable(&mut region, 0)?;
                decayed.copy_advice(|| "decayed", &mut region, a[0], 0)?;
                new_value.copy_advice(|| "v_new", &mut region, a[1], 0)?;
                let net = decayed.value().zip(new_value.value()).map(|(d, n)| {
                    let (d, n) = (low_u64(d), low_u64(n));
                    if d >= n { (Base::from(d - n), Base::one()) } else { (Base::from(n - d), -Base::one()) }
                });
                let magnitude = region.assign_advice(|| "magnitude", a[2], 0, || net.map(|(m, _)| m))?;
                let sign = region.assign_advice(|| "sign", a[3], 0, || net.map(|(_, s)| s))?;
                value.copy_advice(|| "v_old", &mut region, a[4], 0)?;
                root.copy_advice(|| "root", &mut region, a[5], 0)?;
                region.assign_advice_from_instance(|| "anchor", config.primary, INSTANCE_ANCHOR, a[6], 0)?;
                Ok((magnitude, sign))
            },
        )?;

        // cv_net = [magnitude * sign] V + [rcv] R
        let v_scalar = ScalarFixedShort::new(ecc_chip.clone(), layouter.namespace(|| "v_net"), (magnitude, sign))?;
        let (v_commit, _) = FixedPointShort::from_inner(ecc_chip.clone(), ShortBase)
            .mul(layouter.namespace(|| "[v_net] V"), v_scalar)?;
        let rcv_scalar = ScalarFixed::new(ecc_chip.clone(), layouter.namespace(|| "rcv"), self.rcv)?;
        let (blind, _) = EccFixedPoint::from_inner(ecc_chip.clone(), FullWidth::ValueRandomness)
            .mul(layouter.namespace(|| "[rcv] R"), rcv_scalar)?;
        let cv_net = v_commit.add(layouter.namespace(|| "cv_net"), &blind)?;
        layouter.constrain_instance(cv_net.inner().x().cell(), config.primary, INSTANCE_CV_X)?;
        layouter.constrain_instance(cv_net.inner().y().cell(), config.primary, INSTANCE_CV_Y)?;
        Ok(())
    }
}

// ----------------------------------------------------------------- native reference values

pub mod native {
    use super::*;
    use ff::PrimeFieldBits;
    use halo2_gadgets::utilities::i2lebsp;

    /// Root of the Sinsemilla Merkle path, as `MerklePath` computes it in circuit.
    pub fn merkle_root(leaf: Base, pos: u32, path: &[Base; MERKLE_DEPTH]) -> Base {
        let domain = sinsemilla::HashDomain::from_Q(GradidoHashDomains::MerkleCrh.Q().into());
        path.iter().enumerate().fold(leaf, |node, (l, sibling)| {
            let (left, right) = if pos & (1 << l) == 0 { (node, *sibling) } else { (*sibling, node) };
            domain
                .hash(
                    i2lebsp::<10>(l as u64)
                        .iter()
                        .copied()
                        .chain(left.to_le_bits().iter().by_vals().take(255))
                        .chain(right.to_le_bits().iter().by_vals().take(255)),
                )
                .unwrap()
        })
    }

    /// `x` and `y` of an affine point.
    pub fn coordinates(p: pallas::Affine) -> (Base, Base) {
        use pasta_curves::arithmetic::CurveAffine;
        let c = p.coordinates().unwrap();
        (*c.x(), *c.y())
    }
}

/// A consistent witness plus the public inputs.
pub mod sample {
    use super::*;
    use crate::decay;
    use crate::keys::{Address, FullViewingKey, SpendingKey};
    use crate::note::{from_parts, Note, NoteKind, RandomSeed};
    use rand::{rngs::StdRng, RngCore, SeedableRng};

    /// The keys of the two sides, so the sample uses real addresses.
    pub struct Parties {
        pub spender: FullViewingKey,
        pub spender_address: Address,
        pub recipient: FullViewingKey,
        pub recipient_address: Address,
    }

    pub fn parties() -> Parties {
        let spender = SpendingKey::from_bytes([11u8; 32]).full_viewing_key();
        let recipient = SpendingKey::from_bytes([12u8; 32]).full_viewing_key();
        Parties {
            spender_address: spender.address([3u8; 11]),
            recipient_address: recipient.address([4u8; 11]),
            spender,
            recipient,
        }
    }

    /// Far enough in the future for notes of any age used here.
    pub const NOW: u64 = 1_000_000_000_000;

    fn random_base(rng: &mut StdRng) -> Base {
        let mut wide = [0u8; 64];
        rng.fill_bytes(&mut wide);
        <Base as ff::FromUniformBytes<64>>::from_uniform_bytes(&wide)
    }

    #[derive(Clone, Debug)]
    pub struct Fixture<const WITH_DECAY: bool, const WINDOWED: bool> {
        pub circuit: ActionSliceCircuit<WITH_DECAY, WINDOWED>,
        pub instance: Vec<Base>,
        pub community: Base,
        pub spent: Note,
        pub created: Note,
        pub path: [Base; MERKLE_DEPTH],
        pub leaf_pos: u32,
        pub alpha: pallas::Scalar,
    }

    /// Spends the whole note into one new note. `claimed` overrides the value the *public*
    /// `cv_net` assumes for the spent note, to test that a prover cannot skip the decay.
    pub fn fixture<const WITH_DECAY: bool, const WINDOWED: bool>(
        value: u64,
        age: u64,
        claimed: Option<u64>,
    ) -> Fixture<WITH_DECAY, WINDOWED> {
        let mut rng = StdRng::seed_from_u64(7);
        let p = parties();
        let community = random_base(&mut rng);
        let spent = from_parts(
            community,
            community,
            value,
            NOW - age,
            NoteKind::Normal,
            5,
            &p.spender_address,
            random_base(&mut rng),
            random_base(&mut rng),
            RandomSeed::random(&mut rng),
        )
        .expect("valid note");
        let nf = spent.nullifier(p.spender.nk);

        let leaf_pos = 0x1234_5678u32;
        let mut path = [Base::zero(); MERKLE_DEPTH];
        for node in path.iter_mut() {
            *node = random_base(&mut rng);
        }
        let anchor = native::merkle_root(spent.commitment(), leaf_pos, &path);

        let decayed = match (WITH_DECAY, WINDOWED) {
            (false, _) => value,
            (true, false) => decay::decay(value, age),
            (true, true) => decay::decay_windowed(value, age),
        };
        let created = from_parts(
            community,
            community,
            decayed,
            NOW,
            NoteKind::Normal,
            9,
            &p.recipient_address,
            nf,
            random_base(&mut rng),
            RandomSeed::random(&mut rng),
        )
        .expect("valid note");

        let alpha = pallas::Scalar::from(rng.next_u64());
        let rcv = pallas::Scalar::from(rng.next_u64());
        let rk = (pallas::Point::from(p.spender.ak) + crate::signature::spend_auth_base() * alpha).to_affine();
        let spent_value = claimed.unwrap_or(decayed);
        let cv_net = crate::signature::value_commitment(spent_value as i128 - decayed as i128, rcv).to_affine();

        Fixture {
            circuit: ActionSliceCircuit::new(&spent, &p.spender, leaf_pos, path, &created, rcv, alpha),
            instance: ActionSliceCircuit::<WITH_DECAY, WINDOWED>::instance(
                community,
                anchor,
                nf,
                rk,
                created.commitment(),
                cv_net,
                NOW,
            ),
            community,
            spent,
            created,
            path,
            leaf_pos,
            alpha,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::sample::{fixture, parties};
    use super::*;
    use crate::decay;
    use crate::keys::SpendingKey;
    use halo2_proofs::dev::MockProver;

    fn verifies<const WITH_DECAY: bool, const WINDOWED: bool>(
        circuit: &ActionSliceCircuit<WITH_DECAY, WINDOWED>,
        instance: Vec<Base>,
    ) -> bool {
        MockProver::run(K, circuit, vec![instance]).unwrap().verify().is_ok()
    }

    fn run<const WITH_DECAY: bool, const WINDOWED: bool>(value: u64, age: u64, created: Option<u64>) -> bool {
        let f = fixture::<WITH_DECAY, WINDOWED>(value, age, created);
        verifies(&f.circuit, f.instance)
    }

    #[test]
    fn action_without_decay() {
        assert!(run::<false, false>(1_000_0000, 3 * decay::SECONDS_PER_YEAR, None));
    }

    #[test]
    fn action_with_windowed_decay() {
        assert!(run::<true, true>(1_000_0000, 3 * decay::SECONDS_PER_YEAR, None));
    }

    #[test]
    fn largest_value_and_oldest_note() {
        assert!(run::<true, true>(i64::MAX as u64, 0, None));
        assert!(run::<true, true>(i64::MAX as u64, 70 * decay::SECONDS_PER_YEAR + 12_345, None));
    }

    /// The public cv_net claims the note did not decay; the circuit computes the decay itself.
    #[test]
    fn rejects_undecayed_value() {
        let value = 1_000_0000;
        assert!(!run::<true, true>(value, 3 * decay::SECONDS_PER_YEAR, Some(value)));
    }

    #[test]
    fn rejects_one_unit_too_much() {
        let (value, age) = (1_000_0000, 400 * 86_400);
        assert!(!run::<true, true>(value, age, Some(decay::decay_windowed(value, age) + 1)));
    }

    /// A dummy spend of value 0 needs no real tree position: its root may differ from the anchor.
    #[test]
    fn dummy_spend_ignores_the_anchor() {
        let mut f = fixture::<true, true>(0, 400 * 86_400, None);
        f.instance[INSTANCE_ANCHOR] += Base::one();
        assert!(verifies(&f.circuit, f.instance));
    }

    /// ... but a real spend cannot.
    #[test]
    fn real_spend_needs_the_anchor() {
        let mut f = fixture::<true, true>(1_000_0000, 400 * 86_400, None);
        f.instance[INSTANCE_ANCHOR] += Base::one();
        assert!(!verifies(&f.circuit, f.instance));
    }

    /// rk is what the spend authorisation signature is checked against, so it must be the one
    /// derived from the spender's ak.
    #[test]
    fn rejects_a_foreign_rk() {
        let mut f = fixture::<true, true>(1_000_0000, 400 * 86_400, None);
        f.instance[INSTANCE_RK_X] += Base::one();
        assert!(!verifies(&f.circuit, f.instance));
    }

    /// The value in the commitment is the cell the decay works on, so a note cannot claim one
    /// value and be spent as another.
    #[test]
    fn rejects_commitment_with_another_value() {
        let (value, age) = (1_000_0000, 400 * 86_400);
        let mut f = fixture::<true, true>(value, age, None);
        f.circuit.value = Value::known(value * 2);
        assert!(!verifies(&f.circuit, f.instance));
    }

    /// Same for the timestamp: a note cannot be made younger to escape its decay.
    #[test]
    fn rejects_younger_timestamp() {
        let mut f = fixture::<true, true>(1_000_0000, 3 * decay::SECONDS_PER_YEAR, None);
        f.circuit.t_note = Value::known(sample::NOW);
        assert!(!verifies(&f.circuit, f.instance));
    }

    /// Whoever knows a note's plaintext (its sender, or everybody for a public creation) must
    /// not be able to spend it with their own key: with `g_d := pk_d` the attacker's own ivk
    /// would have to be 1, and ivk is a hash of the attacker's key.
    #[test]
    fn rejects_spend_by_someone_who_knows_the_note() {
        let f = fixture::<true, true>(1_000_0000, 400 * 86_400, None);
        let attacker = SpendingKey::from_bytes([99u8; 32]).full_viewing_key();
        let pk_d = parties().spender_address.pk_d;
        for g_d in [pk_d, crate::keys::diversify_hash(&[3u8; 11]).to_affine()] {
            let mut c = f.circuit.clone();
            c.g_d = Value::known(g_d);
            c.ak = Value::known(attacker.ak);
            c.nk = Value::known(attacker.nk);
            c.rivk = Value::known(attacker.rivk);
            let mut instance = f.instance.clone();
            // everything public the attacker would publish for their own key
            let nf = f.spent.nullifier(attacker.nk);
            instance[INSTANCE_NF] = nf;
            let mut created = f.created;
            created.rho = nf;
            instance[INSTANCE_CM_NEW] = created.commitment();
            let rk = (pallas::Point::from(attacker.ak) + crate::signature::spend_auth_base() * f.alpha).to_affine();
            let (rk_x, rk_y) = native::coordinates(rk);
            instance[INSTANCE_RK_X] = rk_x;
            instance[INSTANCE_RK_Y] = rk_y;
            assert!(!verifies(&c, instance));
        }
    }

    /// Another nk would give the same note a second nullifier: a double spend.
    #[test]
    fn rejects_another_nullifier_key() {
        let f = fixture::<true, true>(1_000_0000, 400 * 86_400, None);
        let mut c = f.circuit.clone();
        let nk = f.spent.rho + Base::one();
        c.nk = Value::known(nk);
        let mut instance = f.instance.clone();
        instance[INSTANCE_NF] = f.spent.nullifier(nk);
        assert!(!verifies(&c, instance));
    }

    /// The owner's viewing key holder (the community server under E5) cannot swap in its own ak
    /// and spend without the device's signature.
    #[test]
    fn rejects_another_ak() {
        let f = fixture::<true, true>(1_000_0000, 400 * 86_400, None);
        let other = SpendingKey::from_bytes([98u8; 32]).full_viewing_key();
        let mut c = f.circuit.clone();
        c.ak = Value::known(other.ak);
        let mut instance = f.instance.clone();
        let rk = (pallas::Point::from(other.ak) + crate::signature::spend_auth_base() * f.alpha).to_affine();
        let (rk_x, rk_y) = native::coordinates(rk);
        instance[INSTANCE_RK_X] = rk_x;
        instance[INSTANCE_RK_Y] = rk_y;
        assert!(!verifies(&c, instance));
    }

    /// The notes belong to the community the node verifies for.
    #[test]
    fn rejects_another_community() {
        let mut f = fixture::<true, true>(1_000_0000, 400 * 86_400, None);
        f.instance[INSTANCE_COMMUNITY] += Base::one();
        assert!(!verifies(&f.circuit, f.instance));
    }

    /// A dummy (value 0) can pick any tree position, but its notes are still of this community.
    #[test]
    fn dummy_cannot_change_the_community() {
        let mut f = fixture::<true, true>(0, 400 * 86_400, None);
        f.instance[INSTANCE_ANCHOR] += Base::one();
        f.instance[INSTANCE_COMMUNITY] += Base::one();
        assert!(!verifies(&f.circuit, f.instance));
    }

    #[test]
    fn rejects_kind_outside_normal_and_deferred() {
        let mut f = fixture::<true, true>(1_000_0000, 400 * 86_400, None);
        f.circuit.new_kind = Value::known(2);
        assert!(!verifies(&f.circuit, f.instance));
    }
}
