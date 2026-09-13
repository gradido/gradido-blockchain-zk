//! Cost of a real shielded transfer: two actions in one proof.
//! `cargo run --release --example bundle_timing`
use std::time::Instant;

use ff::Field;
use pasta_curves::pallas;
use rand::{rngs::StdRng, SeedableRng};

use gradido_blockchain_zk::bundle::{build, setup, sign_spend, Ledger, OutputInfo, SpendInfo};
use gradido_blockchain_zk::keys::SpendingKey;
use gradido_blockchain_zk::note::{from_parts, NoteKind, RandomSeed};
use gradido_blockchain_zk::note_encryption::NoteWithSeed;
use gradido_blockchain_zk::tree::CommitmentTree;
use gradido_blockchain_zk::{decay, wire};

fn main() {
    let mut rng = StdRng::seed_from_u64(1);
    let community = pallas::Base::from(7);
    let now = 1_800_000_000u64;
    let alice = SpendingKey::from_bytes([1u8; 32]);
    let fvk = alice.full_viewing_key();
    let bob = SpendingKey::from_bytes([2u8; 32]).full_viewing_key();

    let t = Instant::now();
    setup();
    println!("keygen:           {:>8.2?}", t.elapsed());

    let rseed = RandomSeed::random(&mut rng);
    let note = from_parts(community, community, 1_000_0000, now - 400 * 86_400, NoteKind::Normal, 0,
        &fvk.address([9u8; 11]), pallas::Base::random(&mut rng), pallas::Base::zero(), rseed).unwrap();
    let mut ledger = Ledger::new();
    ledger.add_note(note.commitment()).unwrap();
    let mut tree = CommitmentTree::default();
    let position = tree.append(note.commitment(), true).unwrap();
    tree.checkpoint();
    let value = decay::decay_windowed(1_000_0000, 400 * 86_400);

    let mut prove_times = Vec::new();
    let mut verify_times = Vec::new();
    let mut sizes = (0, 0);
    for _ in 0..5 {
        let spend = SpendInfo { fvk, note: NoteWithSeed { note, rseed },
            position: u64::from(position) as u32, path: tree.witness(position).unwrap() };
        let outputs = vec![
            OutputInfo::new(bob.address([1u8; 11]), 300_0000),
            OutputInfo::new(fvk.address([2u8; 11]), value - 300_0000),
        ];
        let t = Instant::now();
        let unauthorized = build(community, ledger.tree.root(), now, vec![spend], outputs, Some(fvk.ovk), &mut rng).unwrap();
        let sighash = unauthorized.sighash();
        let sigs = unauthorized.real_spends().into_iter()
            .map(|i| sign_spend(&alice.spend_authorizing_key(), unauthorized.alphas[i], &sighash, &mut rng)).collect();
        let bundle = unauthorized.authorize(&sighash, sigs, &mut rng).unwrap();
        prove_times.push(t.elapsed());

        let (body, auth) = wire::encode(&bundle);
        sizes = (body.len(), auth.len());
        let t = Instant::now();
        let decoded = wire::decode(&body, &auth, community, now).unwrap();
        ledger.verify(&decoded, &sighash).expect("valid");
        verify_times.push(t.elapsed());
    }
    prove_times.sort();
    verify_times.sort();
    println!("build + prove:    {:>8.2?} (median of 5, 2 actions in one proof)", prove_times[2]);
    println!("decode + verify:  {:>8.2?}", verify_times[2]);
    println!("wire size:        {} B body + {} B authorisation = {} B", sizes.0, sizes.1, sizes.0 + sizes.1);
}
