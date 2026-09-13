//! Writes one shielded bundle to two files, to check that other decoders read the same bytes:
//! `cargo run --release --example wire_sample <dir>`
use ff::Field;
use pasta_curves::pallas;
use rand::{rngs::StdRng, SeedableRng};

use gradido_blockchain_zk::bundle::{build, sign_spend, Ledger, OutputInfo, SpendInfo};
use gradido_blockchain_zk::keys::SpendingKey;
use gradido_blockchain_zk::note::{from_parts, NoteKind, RandomSeed};
use gradido_blockchain_zk::note_encryption::NoteWithSeed;
use gradido_blockchain_zk::tree::CommitmentTree;
use gradido_blockchain_zk::{decay, wire};

fn main() {
    let dir = std::env::args().nth(1).unwrap_or_else(|| ".".into());
    let mut rng = StdRng::seed_from_u64(1);
    let community = pallas::Base::from(7);
    let now = 1_800_000_000u64;
    let alice = SpendingKey::from_bytes([1u8; 32]);
    let fvk = alice.full_viewing_key();
    let bob = SpendingKey::from_bytes([2u8; 32]).full_viewing_key();

    let rseed = RandomSeed::random(&mut rng);
    let note = from_parts(community, community, 1_000_0000, now - 86_400, NoteKind::Normal, 0,
        &fvk.address([9u8; 11]), pallas::Base::random(&mut rng), pallas::Base::zero(), rseed).unwrap();
    let mut ledger = Ledger::new();
    ledger.add_note(note.commitment()).unwrap();
    let mut tree = CommitmentTree::default();
    let position = tree.append(note.commitment(), true).unwrap();
    tree.checkpoint();

    let value = decay::decay_windowed(1_000_0000, 86_400);
    let unauthorized = build(community, ledger.tree.root(), now,
        vec![SpendInfo { fvk, note: NoteWithSeed { note, rseed },
            position: u64::from(position) as u32, path: tree.witness(position).unwrap() }],
        vec![OutputInfo::new(bob.address([1u8; 11]), value)], None, &mut rng).unwrap();
    let sighash = unauthorized.sighash();
    let sigs = unauthorized.real_spends().into_iter()
        .map(|i| sign_spend(&alice.spend_authorizing_key(), unauthorized.alphas[i], &sighash, &mut rng))
        .collect();
    let bundle = unauthorized.authorize(&sighash, sigs, &mut rng).unwrap();
    ledger.verify(&bundle, &bundle.sighash()).expect("valid");

    let (body, auth) = wire::encode(&bundle);
    std::fs::write(format!("{dir}/shielded_bundle.bin"), &body).unwrap();
    std::fs::write(format!("{dir}/shielded_authorization.bin"), &auth).unwrap();
    std::fs::write(format!("{dir}/sighash.bin"), bundle.sighash()).unwrap();
    use ff::PrimeField;
    std::fs::write(format!("{dir}/community.bin"), community.to_repr()).unwrap();
    println!("wrote {} + {} bytes to {dir}", body.len(), auth.len());
}
