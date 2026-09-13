//! The signing device against an honest and a malicious community server.

use ff::Field;
use pasta_curves::pallas;
use rand::{rngs::StdRng, SeedableRng};

use crate::bundle::{body_sighash, build, Ledger, OutputInfo, SpendInfo, UnauthorizedBundle};
use crate::decay;
use crate::keys::SpendingKey;
use crate::memo;
use crate::note::{from_parts, NoteKind, RandomSeed};
use crate::note_encryption::NoteWithSeed;
use crate::signer::{self, MemoOpening, ReviewError, SigningRequest};
use crate::tree::CommitmentTree;
use crate::wire::{self, WireError};

type Base = pallas::Base;

const NOW: u64 = 1_800_000_000;
const DAY: u64 = 86_400;
const VALUE: u64 = 1_000_0000;

fn community() -> Base {
    Base::from(7)
}

struct Setup {
    ledger: Ledger,
    alice: SpendingKey,
    spend: SpendInfo,
    spendable: u64,
    rng: StdRng,
}

/// Alice owns one note of 1000 GDD, 100 days old.
fn setup(seed: u64) -> Setup {
    let mut rng = StdRng::seed_from_u64(seed);
    let alice = SpendingKey::from_bytes([1u8; 32]);
    let fvk = alice.full_viewing_key();
    let rseed = RandomSeed::random(&mut rng);
    let note = from_parts(community(), community(), VALUE, NOW - 100 * DAY, NoteKind::Normal, 0,
        &fvk.address([9u8; 11]), Base::random(&mut rng), Base::zero(), rseed).unwrap();
    let mut ledger = Ledger::new();
    ledger.add_note(note.commitment()).unwrap();
    let mut tree = CommitmentTree::default();
    let position = tree.append(note.commitment(), true).unwrap();
    tree.checkpoint();
    let spend = SpendInfo {
        fvk,
        note: NoteWithSeed { note, rseed },
        position: u64::from(position) as u32,
        path: tree.witness(position).unwrap(),
    };
    Setup { ledger, alice, spend, spendable: decay::decay_windowed(VALUE, 100 * DAY), rng }
}

fn bob() -> crate::keys::Address {
    SpendingKey::from_bytes([2u8; 32]).full_viewing_key().address([1u8; 11])
}

fn mallory() -> crate::keys::Address {
    SpendingKey::from_bytes([66u8; 32]).full_viewing_key().address([6u8; 11])
}

/// What an honest server does: build with the owner's ovk, put the bundle into a body.
fn build_request(s: &mut Setup, outputs: Vec<OutputInfo>) -> (UnauthorizedBundle, SigningRequest) {
    let ovk = s.spend.fvk.ovk;
    let unauthorized =
        build(community(), s.ledger.tree.root(), NOW, vec![s.spend.clone()], outputs, Some(ovk), &mut s.rng).unwrap();
    let body = wire::encode_transfer_body(NOW, 4, &unauthorized.shielded_bytes());
    let request = unauthorized.signing_request(body);
    (unauthorized, request)
}

fn pay_bob(s: &Setup, amount: u64) -> Vec<OutputInfo> {
    vec![
        OutputInfo::new(bob(), amount),
        OutputInfo::new(s.spend.fvk.address([2u8; 11]), s.spendable - amount),
    ]
}

#[test]
fn the_device_shows_the_payment_and_its_signature_is_accepted() {
    let mut s = setup(1);
    let outputs = pay_bob(&s, 300_0000);
    let (unauthorized, request) = build_request(&mut s, outputs);

    // the request travels as bytes
    let request = SigningRequest::decode(&request.encode()).expect("decodes");
    let (review, signatures) = signer::sign(&request, &s.alice, community(), &mut s.rng).expect("honest request");
    assert_eq!(review.created_at, NOW);
    assert_eq!(review.payments.len(), 1);
    assert_eq!(review.payments[0].address, bob());
    assert_eq!(review.payments[0].value, 300_0000);
    assert_eq!(review.change, s.spendable - 300_0000);
    assert_eq!(review.spends, 1);

    // the server authorises with the hash of the body, which is what the device signed
    let sighash = body_sighash(&request.body);
    assert_eq!(review.sighash, sighash);
    let bundle = unauthorized.authorize(&sighash, signatures, &mut s.rng).unwrap();
    assert_eq!(s.ledger.apply(&bundle, &sighash), Ok(()));
}

/// The attack the device exists for: the server builds a payment to Mallory and describes it
/// as a payment to Bob.
#[test]
fn a_swapped_recipient_is_caught() {
    let mut s = setup(2);
    let honest_outputs = pay_bob(&s, 300_0000);
    let (_, honest) = build_request(&mut s, honest_outputs);
    let mut evil_outputs = pay_bob(&s, 300_0000);
    evil_outputs[0].address = mallory();
    let (_, evil) = build_request(&mut s, evil_outputs);

    // the real body pays Mallory, the openings claim Bob
    let lie = SigningRequest { body: evil.body.clone(), outputs: honest.outputs.clone(), alphas: evil.alphas.clone() };
    assert!(matches!(signer::review(&lie, &s.alice, community()), Err(ReviewError::CommitmentMismatch(_))));

    // with truthful openings the device shows Mallory, which is the point
    let review = signer::review(&evil, &s.alice, community()).unwrap();
    assert_eq!(review.payments[0].address, mallory());
}

/// Change sent to a foreign address is a payment, and the device shows it as one.
#[test]
fn change_to_a_foreign_address_is_shown_as_payment() {
    let mut s = setup(3);
    let mut outputs = pay_bob(&s, 300_0000);
    outputs[1].address = mallory();
    let (_, request) = build_request(&mut s, outputs);
    let review = signer::review(&request, &s.alice, community()).unwrap();
    assert_eq!(review.change, 0);
    assert_eq!(review.payments.len(), 2);
    assert!(review.payments.iter().any(|p| p.address == mallory() && p.value == s.spendable - 300_0000));
}

/// Garbage for the recipient would burn the payment: Bob could never find his note.
#[test]
fn a_ciphertext_that_does_not_match_the_note_is_caught() {
    let mut s = setup(4);
    let outputs = pay_bob(&s, 300_0000);
    let ovk = s.spend.fvk.ovk;
    let mut unauthorized =
        build(community(), s.ledger.tree.root(), NOW, vec![s.spend.clone()], outputs, Some(ovk), &mut s.rng).unwrap();
    unauthorized.actions[0].encrypted.enc_ciphertext[10] ^= 1;
    let body = wire::encode_transfer_body(NOW, 4, &unauthorized.shielded_bytes());
    let request = unauthorized.signing_request(body);
    assert_eq!(signer::review(&request, &s.alice, community()), Err(ReviewError::CiphertextMismatch(0)));
}

#[test]
fn a_bundle_built_without_the_owners_ovk_is_refused() {
    let mut s = setup(5);
    let outputs = pay_bob(&s, 300_0000);
    let unauthorized =
        build(community(), s.ledger.tree.root(), NOW, vec![s.spend.clone()], outputs, None, &mut s.rng).unwrap();
    let body = wire::encode_transfer_body(NOW, 4, &unauthorized.shielded_bytes());
    let request = unauthorized.signing_request(body);
    assert!(matches!(signer::review(&request, &s.alice, community()), Err(ReviewError::CiphertextMismatch(_))));
}

/// The memo is part of what the device shows, so it has to be the one bound in the note.
#[test]
fn the_memo_is_checked_and_shown() {
    let mut s = setup(6);
    let text = memo::pad(b"Danke fuer die Gartenarbeit").unwrap();
    let r_memo = Base::from(77);
    let mut outputs = pay_bob(&s, 300_0000);
    outputs[0].memo_cm = memo::commit(&text, r_memo);
    outputs[0].memo_opening = Some(MemoOpening { text, r_memo });
    let (_, request) = build_request(&mut s, outputs);
    let review = signer::review(&request, &s.alice, community()).unwrap();
    assert_eq!(review.payments[0].memo, Some(text));

    let mut other = request.clone();
    other.outputs[0].memo.as_mut().unwrap().text = memo::pad(b"Miete").unwrap();
    assert_eq!(signer::review(&other, &s.alice, community()), Err(ReviewError::MemoMismatch(0)));

    let mut missing = request;
    missing.outputs[0].memo = None;
    assert_eq!(signer::review(&missing, &s.alice, community()), Err(ReviewError::MemoMismatch(0)));
}

/// The device signs only spends of its own key.
#[test]
fn an_alpha_for_someone_elses_spend_is_refused() {
    let mut s = setup(7);
    let outputs = pay_bob(&s, 300_0000);
    let (unauthorized, mut request) = build_request(&mut s, outputs);
    let dummy = (0..2).find(|i| !unauthorized.real_spends().contains(i)).unwrap();
    request.alphas[dummy] = Some(pallas::Scalar::from(5u64));
    assert_eq!(signer::review(&request, &s.alice, community()), Err(ReviewError::ForeignSpend(dummy)));

    let mut none = request;
    none.alphas = vec![None, None];
    assert_eq!(signer::review(&none, &s.alice, community()), Err(ReviewError::NothingToSign));
}

/// A body with anything besides a local shielded transfer is not signed: the device cannot
/// vouch for fields it does not understand.
#[test]
fn the_body_holds_a_local_transfer_and_nothing_else() {
    let mut s = setup(8);
    let outputs = pay_bob(&s, 300_0000);
    let (_, request) = build_request(&mut s, outputs);
    let review = |body: Vec<u8>| signer::review(&SigningRequest { body, ..request.clone() }, &s.alice, community());

    // an unknown field
    let mut unknown = request.body.clone();
    unknown.extend_from_slice(&[0xa0, 0x01, 0x01]); // tag 20, varint 1
    assert_eq!(review(unknown), Err(ReviewError::Body(WireError::UnsupportedBody(20))));

    // a creation next to the transfer (tag 7)
    let mut creation = request.body.clone();
    creation.extend_from_slice(&[0x3a, 0x00]);
    assert_eq!(review(creation), Err(ReviewError::Body(WireError::UnsupportedBody(7))));

    // an outbound cross community transfer
    let mut outbound = request.body.clone();
    outbound.extend_from_slice(&[0x20, 0x02]);
    assert_eq!(review(outbound), Err(ReviewError::Body(WireError::CrossCommunityNotSupported)));

    // the bundle twice
    let mut twice = request.body.clone();
    let bundle = wire::parse_transfer_body(&request.body).unwrap().shielded;
    twice.push(0x32);
    twice.extend_from_slice(&prost_len(bundle.len()));
    twice.extend_from_slice(&bundle);
    assert_eq!(review(twice), Err(ReviewError::Body(WireError::NotCanonical("shielded_transfer"))));

    // another time than the one the notes were built for
    let shifted = wire::encode_transfer_body(NOW + 60, 4, &bundle);
    assert!(matches!(review(shifted), Err(ReviewError::CommitmentMismatch(_))));
}

/// A signature over one body is worthless for another.
#[test]
fn signatures_are_bound_to_the_body() {
    let mut s = setup(9);
    let outputs = pay_bob(&s, 300_0000);
    let (unauthorized, request) = build_request(&mut s, outputs);
    let (_, signatures) = signer::sign(&request, &s.alice, community(), &mut s.rng).unwrap();
    let other_body = wire::encode_transfer_body(NOW, 5, &unauthorized.shielded_bytes());
    let bundle = unauthorized.authorize(&body_sighash(&other_body), signatures, &mut s.rng);
    assert!(bundle.is_err(), "authorize checks the device signatures against the sighash");
}

#[test]
fn a_request_decodes_strictly() {
    let mut s = setup(10);
    let outputs = pay_bob(&s, 300_0000);
    let (_, request) = build_request(&mut s, outputs);
    let bytes = request.encode();
    assert_eq!(SigningRequest::decode(&bytes).unwrap(), request);
    let mut trailing = bytes.clone();
    trailing.extend_from_slice(&[0x78, 0x01]);
    assert_eq!(SigningRequest::decode(&trailing), Err(ReviewError::Request));
    assert_eq!(SigningRequest::decode(&bytes[..bytes.len() - 1]), Err(ReviewError::Request));
}

/// Another account's device finds nothing it could vouch for: the outgoing ciphertexts are not
/// under its ovk, and no spend is under its ak.
#[test]
fn another_device_refuses() {
    let mut s = setup(11);
    let outputs = pay_bob(&s, 300_0000);
    let (_, request) = build_request(&mut s, outputs);
    let eve = SpendingKey::from_bytes([5u8; 32]);
    assert!(signer::review(&request, &eve, community()).is_err());
}

fn prost_len(mut len: usize) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (len & 0x7f) as u8;
        len >>= 7;
        if len == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}
