//! Shielded transfers through the ledger: pay with change, receive, spend again, and the ways a
//! transfer must fail.

use ff::Field;
use group::Curve;
use pasta_curves::pallas;
use rand::{rngs::StdRng, SeedableRng};

use crate::bundle::{build, sign_spend, BuildError, Bundle, Ledger, OutputInfo, SpendInfo, VerifyError};
use crate::decay;
use crate::keys::{FullViewingKey, SpendingKey};
use crate::note::{from_parts, NoteKind, RandomSeed};
use crate::note_encryption::{decrypt, GradidoDomain, NoteWithSeed};
use crate::tree::CommitmentTree;

type Base = pallas::Base;

const COMMUNITY: u64 = 7;
const NOW: u64 = 1_800_000_000;
const DAY: u64 = 86_400;

struct Wallet {
    sk: SpendingKey,
    fvk: FullViewingKey,
}

impl Wallet {
    fn new(seed: u8) -> Self {
        let sk = SpendingKey::from_bytes([seed; 32]);
        Self { fvk: sk.full_viewing_key(), sk }
    }
}

/// Keeps a copy of the tree with the wallet's own notes marked, as a wallet would.
struct WalletTree {
    tree: CommitmentTree,
}

impl WalletTree {
    fn new() -> Self {
        Self { tree: CommitmentTree::default() }
    }

    /// Mirrors what the ledger appends, marking the positions this wallet cares about.
    fn follow(&mut self, cms: &[Base], mine: &[usize]) -> Vec<u32> {
        let mut positions = Vec::new();
        for (i, cm) in cms.iter().enumerate() {
            let keep = mine.contains(&i);
            let position = self.tree.append(*cm, keep).unwrap();
            if keep {
                positions.push(u64::from(position) as u32);
            }
        }
        self.tree.checkpoint();
        positions
    }
}

/// A ledger in which `owner` already holds a note worth `value`, created `age` seconds ago.
fn ledger_with_note(owner: &Wallet, value: u64, age: u64, rng: &mut StdRng) -> (Ledger, WalletTree, SpendInfo) {
    let community = Base::from(COMMUNITY);
    let diversifier = [9u8; 11];
    let rseed = RandomSeed::random(rng);
    let note = from_parts(
        community,
        community,
        value,
        NOW - age,
        NoteKind::Normal,
        0,
        &owner.fvk.address(diversifier),
        Base::random(&mut *rng),
        Base::zero(),
        rseed,
    )
    .unwrap();
    let mut ledger = Ledger::new();
    ledger.add_note(note.commitment()).unwrap();
    let mut wallet_tree = WalletTree::new();
    let position = wallet_tree.follow(&[note.commitment()], &[0])[0];
    let spend = SpendInfo {
        fvk: owner.fvk,
        note: NoteWithSeed { note, rseed },
        position,
        path: wallet_tree.tree.witness((position as u64).into()).unwrap(),
    };
    (ledger, wallet_tree, spend)
}

/// Builds, lets the owner's device sign the real spends, and authorises.
fn sign_and_authorize(
    unauthorized: crate::bundle::UnauthorizedBundle,
    owner: &Wallet,
    rng: &mut StdRng,
) -> Bundle {
    let sighash = unauthorized.sighash();
    let device_sigs = unauthorized
        .real_spends()
        .into_iter()
        .map(|i| sign_spend(&owner.sk.spend_authorizing_key(), unauthorized.alphas[i], &sighash, &mut *rng))
        .collect();
    unauthorized.authorize(&sighash, device_sigs, rng).unwrap()
}

fn find_notes(bundle: &Bundle, fvk: &FullViewingKey) -> Vec<(usize, NoteWithSeed)> {
    bundle
        .actions
        .iter()
        .enumerate()
        .filter_map(|(i, action)| {
            let domain = GradidoDomain {
                community: bundle.community,
                coin_community: bundle.community,
                rho: action.nullifier,
            };
            decrypt(&domain, fvk.ivk, &action.encrypted)
                .filter(|(note, _, _)| note.note.value > 0)
                .map(|(note, _, _)| (i, note))
        })
        .collect()
}

#[test]
fn pay_with_change_then_the_recipient_spends_it() {
    let mut rng = StdRng::seed_from_u64(77);
    let alice = Wallet::new(1);
    let bob = Wallet::new(2);
    let carol = Wallet::new(3);

    // Alice's note of 1000 GDD is 400 days old
    let (mut ledger, mut bob_tree, alice_note) = ledger_with_note(&alice, 1_000_0000, 400 * DAY, &mut rng);
    let spendable = decay::decay_windowed(1_000_0000, 400 * DAY);

    // she pays Bob 300 GDD and keeps the rest
    let payment = 300_0000;
    let outputs = vec![
        OutputInfo::new(bob.fvk.address([1u8; 11]), payment),
        OutputInfo::new(alice.fvk.address([2u8; 11]), spendable - payment),
    ];
    let anchor = ledger.tree.root();
    let unauthorized = build(
        Base::from(COMMUNITY),
        anchor,
        NOW,
        vec![alice_note],
        outputs,
        Some(alice.fvk.ovk),
        &mut rng,
    )
    .expect("builds");
    let bundle = sign_and_authorize(unauthorized, &alice, &mut rng);
    ledger.apply(&bundle, &bundle.sighash()).expect("valid transfer");

    // Bob finds exactly his payment, Alice exactly her change
    let bobs = find_notes(&bundle, &bob.fvk);
    assert_eq!(bobs.len(), 1);
    assert_eq!(bobs[0].1.note.value, payment);
    let alices = find_notes(&bundle, &alice.fvk);
    assert_eq!(alices.len(), 1);
    assert_eq!(alices[0].1.note.value, spendable - payment);

    // Bob follows the tree and keeps a witness for his note
    let cms: Vec<Base> = bundle.actions.iter().map(|a| a.cm).collect();
    let bob_position = bob_tree.follow(&cms, &[bobs[0].0])[0];
    assert_eq!(bob_tree.tree.root(), ledger.tree.root(), "wallet and ledger agree on the tree");

    // 30 days later Bob passes it on to Carol
    let later = NOW + 30 * DAY;
    let bob_note = bobs[0].1;
    let bob_spend = SpendInfo {
        fvk: bob.fvk,
        note: bob_note,
        position: bob_position,
        path: bob_tree.tree.witness((bob_position as u64).into()).unwrap(),
    };
    let worth = decay::decay_windowed(payment, 30 * DAY);
    let unauthorized = build(
        Base::from(COMMUNITY),
        ledger.tree.root(),
        later,
        vec![bob_spend],
        vec![OutputInfo::new(carol.fvk.address([5u8; 11]), worth)],
        None,
        &mut rng,
    )
    .expect("builds");
    let second = sign_and_authorize(unauthorized, &bob, &mut rng);
    ledger.apply(&second, &second.sighash()).expect("Bob's note is spendable");
    let carols = find_notes(&second, &carol.fvk);
    assert_eq!(carols.len(), 1);
    assert_eq!(carols[0].1.note.value, worth);
}

#[test]
fn the_same_bundle_twice_is_a_double_spend() {
    let mut rng = StdRng::seed_from_u64(78);
    let alice = Wallet::new(1);
    let bob = Wallet::new(2);
    let (mut ledger, _, note) = ledger_with_note(&alice, 500_0000, 10 * DAY, &mut rng);
    let value = decay::decay_windowed(500_0000, 10 * DAY);
    let unauthorized = build(
        Base::from(COMMUNITY),
        ledger.tree.root(),
        NOW,
        vec![note],
        vec![OutputInfo::new(bob.fvk.address([1u8; 11]), value)],
        None,
        &mut rng,
    )
    .unwrap();
    let bundle = sign_and_authorize(unauthorized, &alice, &mut rng);
    ledger.apply(&bundle, &bundle.sighash()).expect("first time is fine");
    assert!(matches!(ledger.apply(&bundle, &bundle.sighash()), Err(VerifyError::DoubleSpend(_))));
}

#[test]
fn building_refuses_what_does_not_balance() {
    let mut rng = StdRng::seed_from_u64(79);
    let alice = Wallet::new(1);
    let bob = Wallet::new(2);
    let (ledger, _, note) = ledger_with_note(&alice, 500_0000, 10 * DAY, &mut rng);
    // the full nominal value, ignoring 10 days of decay
    let result = build(
        Base::from(COMMUNITY),
        ledger.tree.root(),
        NOW,
        vec![note],
        vec![OutputInfo::new(bob.fvk.address([1u8; 11]), 500_0000)],
        None,
        &mut rng,
    );
    assert!(matches!(result, Err(BuildError::Unbalanced { .. })));
}

/// Everything below starts from one valid bundle and breaks one thing.
fn valid_bundle(rng: &mut StdRng) -> (Ledger, Bundle, Wallet) {
    let alice = Wallet::new(1);
    let bob = Wallet::new(2);
    let (ledger, _, note) = ledger_with_note(&alice, 800_0000, 100 * DAY, rng);
    let value = decay::decay_windowed(800_0000, 100 * DAY);
    let unauthorized = build(
        Base::from(COMMUNITY),
        ledger.tree.root(),
        NOW,
        vec![note],
        vec![
            OutputInfo::new(bob.fvk.address([1u8; 11]), value / 2),
            OutputInfo::new(alice.fvk.address([2u8; 11]), value - value / 2),
        ],
        None,
        rng,
    )
    .unwrap();
    let bundle = sign_and_authorize(unauthorized, &alice, rng);
    (ledger, bundle, alice)
}

#[test]
fn a_valid_bundle_verifies() {
    let mut rng = StdRng::seed_from_u64(80);
    let (ledger, bundle, _) = valid_bundle(&mut rng);
    assert_eq!(ledger.verify(&bundle, &bundle.sighash()), Ok(()));
}

/// Trailing bytes would still verify (halo2 does not check that the transcript is used up), so
/// the length is part of the format.
#[test]
fn the_proof_has_a_fixed_size() {
    let mut rng = StdRng::seed_from_u64(86);
    let (ledger, mut bundle, _) = valid_bundle(&mut rng);
    assert_eq!(bundle.proof.len(), crate::bundle::PROOF_SIZE);
    bundle.proof.push(0);
    assert_eq!(ledger.verify(&bundle, &bundle.sighash()), Err(VerifyError::Proof));
}

/// The proof has the community as public input; a node of another community cannot accept it.
#[test]
fn a_bundle_of_another_community_is_rejected() {
    let mut rng = StdRng::seed_from_u64(87);
    let (ledger, mut bundle, _) = valid_bundle(&mut rng);
    let sighash = bundle.sighash();
    bundle.community += Base::one();
    assert_eq!(ledger.verify(&bundle, &sighash), Err(VerifyError::Proof));
}

/// A wrong or missing device signature is reported by `authorize`, not only by the node.
#[test]
fn authorize_checks_the_device_signatures() {
    use crate::bundle::AuthorizeError;
    let mut rng = StdRng::seed_from_u64(88);
    let alice = Wallet::new(1);
    let mallory = SpendingKey::from_bytes([66u8; 32]);
    let build_one = |rng: &mut StdRng| {
        let (ledger, _, note) = ledger_with_note(&alice, 800_0000, 100 * DAY, rng);
        let value = decay::decay_windowed(800_0000, 100 * DAY);
        build(Base::from(COMMUNITY), ledger.tree.root(), NOW, vec![note],
            vec![OutputInfo::new(alice.fvk.address([2u8; 11]), value)], None, rng).unwrap()
    };

    let unauthorized = build_one(&mut rng);
    let sighash = unauthorized.sighash();
    assert_eq!(
        unauthorized.authorize(&sighash, vec![], &mut rng).unwrap_err(),
        AuthorizeError::SignatureCount { expected: 1, got: 0 }
    );

    let unauthorized = build_one(&mut rng);
    let sighash = unauthorized.sighash();
    let i = unauthorized.real_spends()[0];
    let wrong = sign_spend(&mallory.spend_authorizing_key(), unauthorized.alphas[i], &sighash, &mut rng);
    assert_eq!(
        unauthorized.authorize(&sighash, vec![wrong], &mut rng).unwrap_err(),
        AuthorizeError::BadSignature(i)
    );
}

#[test]
fn an_unknown_anchor_is_rejected() {
    let mut rng = StdRng::seed_from_u64(81);
    let (_, bundle, _) = valid_bundle(&mut rng);
    assert_eq!(Ledger::new().verify(&bundle, &bundle.sighash()), Err(VerifyError::UnknownAnchor));
}

#[test]
fn a_swapped_note_commitment_breaks_the_proof() {
    let mut rng = StdRng::seed_from_u64(82);
    let (ledger, mut bundle, _) = valid_bundle(&mut rng);
    let sighash = bundle.sighash();
    bundle.actions[0].cm += Base::one();
    assert!(ledger.verify(&bundle, &sighash).is_err());
}

#[test]
fn a_changed_value_commitment_is_caught() {
    let mut rng = StdRng::seed_from_u64(83);
    let (ledger, mut bundle, _) = valid_bundle(&mut rng);
    // shift one unit of value from one action to the other, keeping the sum
    let v = crate::signature::value_base();
    bundle.actions[0].cv_net = (pallas::Point::from(bundle.actions[0].cv_net) + v).to_affine();
    bundle.actions[1].cv_net = (pallas::Point::from(bundle.actions[1].cv_net) - v).to_affine();
    assert!(ledger.verify(&bundle, &bundle.sighash()).is_err(), "the proof binds every cv_net to its action");
}

#[test]
fn a_spend_signed_by_someone_else_is_rejected() {
    let mut rng = StdRng::seed_from_u64(84);
    let (ledger, mut bundle, _) = valid_bundle(&mut rng);
    let mallory = SpendingKey::from_bytes([66u8; 32]);
    let sighash = bundle.sighash();
    bundle.spend_auth_sigs[0] =
        sign_spend(&mallory.spend_authorizing_key(), pallas::Scalar::random(&mut rng), &sighash, &mut rng);
    assert!(matches!(ledger.verify(&bundle, &sighash), Err(VerifyError::SpendAuth(0))));
}

#[test]
fn a_changed_ciphertext_invalidates_the_signatures() {
    let mut rng = StdRng::seed_from_u64(85);
    let (ledger, mut bundle, _) = valid_bundle(&mut rng);
    let signed_over = bundle.sighash();
    bundle.actions[1].encrypted.enc_ciphertext[3] ^= 1;
    // the node hashes what it received, so the signatures no longer match
    assert_ne!(bundle.sighash(), signed_over);
    assert!(ledger.verify(&bundle, &bundle.sighash()).is_err());
}

// ------------------------------------------------------------------------------ wire format

#[test]
fn a_bundle_survives_the_wire() {
    let mut rng = StdRng::seed_from_u64(90);
    let (ledger, bundle, _) = valid_bundle(&mut rng);
    let (body, auth) = crate::wire::encode(&bundle);
    println!("ShieldedBundle {} bytes, ShieldedAuthorization {} bytes", body.len(), auth.len());

    let decoded = crate::wire::decode(&body, &auth, bundle.community, bundle.now).expect("decodes");
    assert_eq!(decoded.sighash(), bundle.sighash());
    assert_eq!(ledger.verify(&decoded, &decoded.sighash()), Ok(()));
}

#[test]
fn the_wire_decoder_is_strict() {
    use crate::wire::{from_wire, to_wire, WireError};
    let mut rng = StdRng::seed_from_u64(91);
    let (_, bundle, _) = valid_bundle(&mut rng);
    let (shielded, auth) = to_wire(&bundle);
    let (community, now) = (bundle.community, bundle.now);

    let mut short = shielded.clone();
    short.actions[0].cv.pop();
    assert_eq!(from_wire(&short, &auth, community, now).unwrap_err(), WireError::WrongLength("cv"));

    let mut not_canonical = shielded.clone();
    not_canonical.actions[1].nullifier = vec![0xff; 32];
    assert_eq!(
        from_wire(&not_canonical, &auth, community, now).unwrap_err(),
        WireError::NotCanonical("nullifier")
    );

    let mut one_action = shielded.clone();
    one_action.actions.pop();
    assert_eq!(from_wire(&one_action, &auth, community, now).unwrap_err(), WireError::WrongActionCount(1));

    let mut other_version = shielded.clone();
    other_version.circuit_version = 99;
    assert_eq!(
        from_wire(&other_version, &auth, community, now).unwrap_err(),
        WireError::WrongCircuitVersion(99)
    );

    assert_eq!(crate::wire::decode(&[0xff, 0xff], &[], community, now).unwrap_err(), WireError::Protobuf);
}

/// One bundle, one encoding: anything the decoder would accept besides the canonical bytes could
/// be read differently by another parser, or changed by whoever relays the authorisation.
#[test]
fn only_the_canonical_encoding_is_accepted() {
    use crate::wire::{decode, encode, WireError};
    let mut rng = StdRng::seed_from_u64(94);
    let (_, bundle, _) = valid_bundle(&mut rng);
    let (body, auth) = encode(&bundle);
    let (community, now) = (bundle.community, bundle.now);
    assert!(decode(&body, &auth, community, now).is_ok());

    // an unknown field (tag 15, varint 1) appended
    let mut unknown = auth.clone();
    unknown.extend_from_slice(&[0x78, 0x01]);
    assert_eq!(decode(&body, &unknown, community, now).unwrap_err(), WireError::NotCanonical("ShieldedAuthorization"));

    // binding_sig (tag 3) repeated: a zero signature first, the real one last
    let mut duplicate = vec![0x1a, 64];
    duplicate.extend_from_slice(&[0u8; 64]);
    let mut twice = auth.clone();
    let tail = twice.split_off(twice.len() - 66);
    twice.extend_from_slice(&duplicate);
    twice.extend_from_slice(&tail);
    assert_eq!(decode(&body, &twice, community, now).unwrap_err(), WireError::NotCanonical("ShieldedAuthorization"));

    // the anchor sub-message twice, the second without tree_epoch: prost merges, pbtools replaces
    let mut merged = body.clone();
    assert_eq!(&body[..2], &[0x0a, 34], "anchor comes first: root only, tree_epoch 0 is omitted");
    merged.extend_from_slice(&body[..36]);
    assert_eq!(decode(&merged, &auth, community, now).unwrap_err(), WireError::NotCanonical("ShieldedBundle"));

    // trailing bytes inside the proof field
    let (shielded_msg, mut auth_msg) = crate::wire::to_wire(&bundle);
    auth_msg.proof.push(0);
    assert_eq!(
        crate::wire::from_wire(&shielded_msg, &auth_msg, community, now).unwrap_err(),
        WireError::WrongLength("proof")
    );

    // a tree epoch that does not exist yet
    let (mut shielded_msg, auth_msg) = crate::wire::to_wire(&bundle);
    shielded_msg.anchor.as_mut().unwrap().tree_epoch = 7;
    assert_eq!(
        crate::wire::from_wire(&shielded_msg, &auth_msg, community, now).unwrap_err(),
        WireError::UnsupportedTreeEpoch(7)
    );

    // the identity as rk
    let (mut shielded_msg, auth_msg) = crate::wire::to_wire(&bundle);
    shielded_msg.actions[0].rk = vec![0u8; 32];
    assert_eq!(
        crate::wire::from_wire(&shielded_msg, &auth_msg, community, now).unwrap_err(),
        WireError::NotCanonical("rk")
    );

    assert_eq!(decode(&vec![0u8; 100_000], &auth, community, now).unwrap_err(), WireError::TooLarge);
}

#[test]
fn a_bundle_decoded_with_another_time_is_rejected() {
    let mut rng = StdRng::seed_from_u64(92);
    let (ledger, bundle, _) = valid_bundle(&mut rng);
    let (body, auth) = crate::wire::encode(&bundle);
    // `now` comes from the transaction's created_at; a different value changes the decay the
    // proof computed, so the proof no longer fits
    let shifted = crate::wire::decode(&body, &auth, bundle.community, bundle.now + 3600).unwrap();
    assert!(ledger.verify(&shifted, &bundle.sighash()).is_err());
}

// ------------------------------------------------------------------------------ creation

/// A public creation (E7): the node computes the commitment from the published fields through the
/// C ABI, the recipient rebuilds the same note from those fields and can spend it right away.
#[test]
fn a_creation_can_be_spent() {
    use ff::PrimeField;
    let mut rng = StdRng::seed_from_u64(93);
    let community = Base::from(COMMUNITY);
    let member = Wallet::new(4);
    let shop = Wallet::new(5);

    // March creation to the member's monthly creation address
    let address = member.fvk.creation_address(2026, 3).unwrap();
    let created_at = NOW - 20 * DAY;
    let mut ledger = Ledger::new();
    // the creation's rho comes from the leaf position it gets
    let position = ledger.tree.size();
    let rseed = RandomSeed::random(&mut rng);
    let memo_cm = crate::memo::commit(&crate::memo::pad(b"Gartenpflege").unwrap(), Base::from(5));

    let mut cm_bytes = [0u8; 32];
    let rc = unsafe {
        crate::ffi::grdzk_creation_commitment(
            community.to_repr().as_ptr(),
            1_000_0000,
            created_at,
            0,
            address.to_raw().as_ptr(),
            position,
            rseed.to_bytes().as_ptr(),
            memo_cm.to_repr().as_ptr(),
            cm_bytes.as_mut_ptr(),
        )
    };
    assert_eq!(rc, crate::ffi::GRDZK_OK);
    let cm = Base::from_repr(cm_bytes).unwrap();

    // the member rebuilds the note from the public fields
    let rho = crate::note::creation_rho(community, position);
    let note = from_parts(community, community, 1_000_0000, created_at, NoteKind::Normal, 0, &address, rho, memo_cm, rseed)
        .unwrap();
    assert_eq!(note.commitment(), cm, "node and wallet agree on the creation");

    ledger.add_note(cm).unwrap();
    let mut member_tree = WalletTree::new();
    let position = member_tree.follow(&[cm], &[0])[0];

    // 20 days later the member pays everything to a shop
    let worth = decay::decay_windowed(1_000_0000, 20 * DAY);
    let spend = SpendInfo {
        fvk: member.fvk,
        note: NoteWithSeed { note, rseed },
        position,
        path: member_tree.tree.witness((position as u64).into()).unwrap(),
    };
    let unauthorized = build(
        community,
        ledger.tree.root(),
        NOW,
        vec![spend],
        vec![OutputInfo::new(shop.fvk.address([1u8; 11]), worth)],
        None,
        &mut rng,
    )
    .unwrap();
    let bundle = sign_and_authorize(unauthorized, &member, &mut rng);
    assert_eq!(ledger.apply(&bundle, &bundle.sighash()), Ok(()));
    assert_eq!(find_notes(&bundle, &shop.fvk)[0].1.note.value, worth);
}

/// Two creations with the same public fields (same member, month and amount, the same rseed on a
/// repeated migration) still get different commitments, because rho comes from the position.
#[test]
fn identical_creations_stay_distinct() {
    use ff::PrimeField;
    let community = Base::from(COMMUNITY);
    let member = Wallet::new(6);
    let address = member.fvk.creation_address(2026, 4).unwrap().to_raw();
    let zero = [0u8; 32];
    let commitment = |position: u64, value: u64, created_at: u64| {
        let mut cm = [0u8; 32];
        let rc = unsafe {
            crate::ffi::grdzk_creation_commitment(
                community.to_repr().as_ptr(),
                value,
                created_at,
                0,
                address.as_ptr(),
                position,
                zero.as_ptr(),
                zero.as_ptr(),
                cm.as_mut_ptr(),
            )
        };
        (rc, cm)
    };
    let (rc_a, a) = commitment(10, 1_000_0000, NOW);
    let (rc_b, b) = commitment(11, 1_000_0000, NOW);
    assert_eq!((rc_a, rc_b), (crate::ffi::GRDZK_OK, crate::ffi::GRDZK_OK));
    assert_ne!(a, b);

    // fields no proof could open are refused instead of burning the creation
    assert_eq!(commitment(12, 1 << 63, NOW).0, crate::ffi::GRDZK_ERR_BAD_VALUE);
    assert_eq!(commitment(12, 1_000_0000, 1 << 40).0, crate::ffi::GRDZK_ERR_BAD_VALUE);
}
