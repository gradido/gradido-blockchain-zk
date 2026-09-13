//! The ledger state a node keeps for shielded transfers (privacy_todo.md E4):
//! the note commitment tree, the history of its roots, and the nullifier set.
//!
//! The tree is a `bridgetree::BridgeTree` with the same Sinsemilla MerkleCRH the circuit uses,
//! so a witness taken from it is exactly the path `MerklePath` recomputes in the proof. The
//! node only needs the root and the frontier; a wallet additionally marks its own notes to
//! keep their witnesses up to date.

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet, VecDeque};

use bridgetree::BridgeTree;
use ff::{PrimeField, PrimeFieldBits};
use incrementalmerkletree::{Hashable, Level, Position};
use pasta_curves::pallas;

use crate::circuit::action_slice::{GradidoHashDomains, MERKLE_DEPTH};
use halo2_gadgets::sinsemilla::{primitives as sinsemilla, HashDomains};
use halo2_gadgets::utilities::i2lebsp;

pub type Base = pallas::Base;

/// A node of the commitment tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MerkleNode(pub Base);

impl Ord for MerkleNode {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.to_repr().cmp(&other.0.to_repr())
    }
}

impl PartialOrd for MerkleNode {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn merkle_crh() -> &'static sinsemilla::HashDomain {
    static DOMAIN: std::sync::OnceLock<sinsemilla::HashDomain> = std::sync::OnceLock::new();
    DOMAIN.get_or_init(|| sinsemilla::HashDomain::from_Q(GradidoHashDomains::MerkleCrh.Q().into()))
}

impl Hashable for MerkleNode {
    /// Value of an empty leaf. Not a valid note commitment in practice, as in Orchard.
    fn empty_leaf() -> Self {
        MerkleNode(Base::from(2))
    }

    /// Root of an empty subtree of height `level`, from a table. The default implementation
    /// rehashes all the way up on every call, and `root()` asks for it at every level — about
    /// 500 Sinsemilla hashes per root instead of 32.
    fn empty_root(level: Level) -> Self {
        empty_roots()[usize::from(u8::from(level))]
    }

    /// `MerkleCRH(level, left, right)`, exactly what `MerklePath` computes in circuit.
    fn combine(level: Level, left: &Self, right: &Self) -> Self {
        let hash = merkle_crh()
            .hash(
                i2lebsp::<10>(u8::from(level) as u64)
                    .iter()
                    .copied()
                    .chain(left.0.to_le_bits().iter().by_vals().take(255))
                    .chain(right.0.to_le_bits().iter().by_vals().take(255)),
            )
            // Sinsemilla fails only on an exceptional case of incomplete addition, which no one
            // can steer into; the circuit would reject the same path
            .expect("MerkleCRH hit an exceptional case");
        MerkleNode(hash)
    }
}

/// `EMPTY_ROOTS[l]` is the root of an empty subtree of height `l`.
fn empty_roots() -> &'static [MerkleNode; MERKLE_DEPTH + 1] {
    static ROOTS: std::sync::OnceLock<[MerkleNode; MERKLE_DEPTH + 1]> = std::sync::OnceLock::new();
    ROOTS.get_or_init(|| {
        let mut roots = [MerkleNode::empty_leaf(); MERKLE_DEPTH + 1];
        for level in 0..MERKLE_DEPTH {
            roots[level + 1] = MerkleNode::combine(Level::from(level as u8), &roots[level], &roots[level]);
        }
        roots
    })
}

/// The note commitment tree with checkpoints, one per confirmed transaction.
pub struct CommitmentTree {
    inner: BridgeTree<MerkleNode, u64, MERKLE_DEPTH_U8>,
    checkpoints: u64,
}

const MERKLE_DEPTH_U8: u8 = MERKLE_DEPTH as u8;

impl Default for CommitmentTree {
    fn default() -> Self {
        Self::new(100)
    }
}

impl CommitmentTree {
    /// `max_checkpoints` bounds how far back witnesses can be rewound.
    pub fn new(max_checkpoints: usize) -> Self {
        Self { inner: BridgeTree::new(max_checkpoints), checkpoints: 0 }
    }

    /// Appends a note commitment, `None` when the tree is full. `keep_witness` is for wallets:
    /// mark the notes you own.
    pub fn append(&mut self, cm: Base, keep_witness: bool) -> Option<Position> {
        if !self.has_room_for(1) || !self.inner.append(MerkleNode(cm)) {
            return None;
        }
        if keep_witness {
            self.inner.mark()
        } else {
            self.inner.current_position()
        }
    }

    /// Number of notes in the tree.
    pub fn size(&self) -> u64 {
        self.inner.current_position().map_or(0, |p| u64::from(p) + 1)
    }

    /// Whether `notes` more commitments fit, so a transaction can be rejected before any of its
    /// state is written.
    pub fn has_room_for(&self, notes: usize) -> bool {
        self.size() + notes as u64 <= 1u64 << MERKLE_DEPTH
    }

    /// Seals the state after a transaction; its root becomes an acceptable anchor.
    pub fn checkpoint(&mut self) {
        self.checkpoints += 1;
        self.inner.checkpoint(self.checkpoints);
    }

    /// Current root. For an empty tree this is the root of empty leaves.
    pub fn root(&self) -> Base {
        self.inner
            .root(0)
            .unwrap_or_else(|| MerkleNode::empty_root(Level::from(MERKLE_DEPTH_U8)))
            .0
    }

    /// Siblings from the leaf up to the root, for the current root.
    pub fn witness(&self, position: Position) -> Option<[Base; MERKLE_DEPTH]> {
        let path = self.inner.witness(position, 0).ok()?;
        let mut out = [Base::zero(); MERKLE_DEPTH];
        for (slot, node) in out.iter_mut().zip(path) {
            *slot = node.0;
        }
        Some(out)
    }
}

/// Roots a transaction may use as its anchor: the most recent ones. Lookups are hashed, so a
/// long history costs memory (32 bytes per root) but no verification time.
#[derive(Debug)]
pub struct AnchorHistory {
    roots: VecDeque<[u8; 32]>,
    /// how often each root is in `roots`; the same root comes back after a transaction that
    /// adds no note
    counts: HashMap<[u8; 32], u32>,
    capacity: usize,
}

impl AnchorHistory {
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "an empty history accepts no anchor");
        Self { roots: VecDeque::with_capacity(capacity), counts: HashMap::with_capacity(capacity), capacity }
    }

    pub fn push(&mut self, root: Base) {
        if self.roots.len() == self.capacity {
            let old = self.roots.pop_front().expect("full");
            if let Some(count) = self.counts.get_mut(&old) {
                *count -= 1;
                if *count == 0 {
                    self.counts.remove(&old);
                }
            }
        }
        let bytes = root.to_repr();
        self.roots.push_back(bytes);
        *self.counts.entry(bytes).or_insert(0) += 1;
    }

    pub fn contains(&self, root: &Base) -> bool {
        self.counts.contains_key(&root.to_repr())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DoubleSpend(pub [u8; 32]);

/// Nullifiers of every spent note. In the node this lives in LMDB; here it is in memory.
#[derive(Debug, Default)]
pub struct NullifierSet {
    spent: HashSet<[u8; 32]>,
}

impl NullifierSet {
    pub fn contains(&self, nf: &Base) -> bool {
        self.spent.contains(&nf.to_repr())
    }

    /// Adds all nullifiers of a transaction, or none: a nullifier that is already spent, or
    /// that appears twice in the same transaction, rejects the whole transaction.
    pub fn insert_all(&mut self, nullifiers: &[Base]) -> Result<(), DoubleSpend> {
        let mut fresh = HashSet::with_capacity(nullifiers.len());
        for nf in nullifiers {
            let bytes = nf.to_repr();
            if self.spent.contains(&bytes) || !fresh.insert(bytes) {
                return Err(DoubleSpend(bytes));
            }
        }
        self.spent.extend(fresh);
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.spent.len()
    }

    pub fn is_empty(&self) -> bool {
        self.spent.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::action_slice::native;
    use ff::Field;
    use rand::{rngs::StdRng, SeedableRng};

    /// A witness from the tree must reproduce the tree's root with the circuit's own hashing.
    #[test]
    fn witnesses_match_the_circuit_hash() {
        let mut rng = StdRng::seed_from_u64(31);
        let mut tree = CommitmentTree::default();
        let mut mine = Vec::new();
        for i in 0..20 {
            let cm = Base::random(&mut rng);
            let keep = i % 5 == 0;
            let position = tree.append(cm, keep).unwrap();
            if keep {
                mine.push((position, cm));
            }
            tree.checkpoint();
        }
        let root = tree.root();
        for (position, cm) in mine {
            let path = tree.witness(position).expect("marked notes have a witness");
            assert_eq!(native::merkle_root(cm, u64::from(position) as u32, &path), root);
        }
    }

    /// The table must agree with the recursive definition it replaces.
    #[test]
    fn empty_roots_match_the_definition() {
        let mut node = MerkleNode::empty_leaf();
        for level in 0..MERKLE_DEPTH {
            assert_eq!(MerkleNode::empty_root(Level::from(level as u8)), node);
            node = MerkleNode::combine(Level::from(level as u8), &node, &node);
        }
        assert_eq!(MerkleNode::empty_root(Level::from(MERKLE_DEPTH as u8)), node);
    }

    /// A root per transaction has to be cheap; it used to cost ~46 ms.
    #[test]
    fn a_root_is_cheap() {
        let mut tree = CommitmentTree::default();
        for i in 0..200u64 {
            tree.append(Base::from(i + 10), false).unwrap();
            tree.checkpoint();
        }
        let start = std::time::Instant::now();
        for _ in 0..20 {
            std::hint::black_box(tree.root());
        }
        let per_root = start.elapsed() / 20;
        if !cfg!(debug_assertions) {
            assert!(per_root < std::time::Duration::from_millis(10), "root took {per_root:?}");
        }
    }

    #[test]
    fn root_changes_with_every_note() {
        let mut tree = CommitmentTree::default();
        let empty = tree.root();
        tree.append(Base::from(123), false);
        assert_ne!(tree.root(), empty);
    }

    #[test]
    fn anchor_history_forgets_old_roots() {
        let mut history = AnchorHistory::new(2);
        history.push(Base::from(1));
        history.push(Base::from(2));
        history.push(Base::from(3));
        assert!(!history.contains(&Base::from(1)));
        assert!(history.contains(&Base::from(2)) && history.contains(&Base::from(3)));
        // a root that is in the history twice stays until its last copy is gone
        history.push(Base::from(3));
        history.push(Base::from(4));
        assert!(!history.contains(&Base::from(2)));
        assert!(history.contains(&Base::from(3)));
        history.push(Base::from(5));
        assert!(!history.contains(&Base::from(3)));
    }

    #[test]
    fn double_spend_is_rejected() {
        let mut set = NullifierSet::default();
        assert!(set.insert_all(&[Base::from(1), Base::from(2)]).is_ok());
        assert!(set.insert_all(&[Base::from(3), Base::from(2)]).is_err());
        // nothing of the rejected transaction was added
        assert!(!set.contains(&Base::from(3)));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn the_same_nullifier_twice_in_one_transaction_is_rejected() {
        let mut set = NullifierSet::default();
        assert!(set.insert_all(&[Base::from(7), Base::from(7)]).is_err());
        assert!(set.is_empty());
    }
}
