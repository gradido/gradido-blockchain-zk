//! One transfer from end to end, with every piece the crate has: keys, address, note,
//! commitment tree, proof, encryption, memo and both signatures.
//!
//! It reads like the walkthrough of a shielded transfer:
//! the spender owns a note, spends it to an address of the recipient, and the recipient finds
//! and rebuilds the note from the transaction alone.

use ff::Field;
use group::{Curve, GroupEncoding};
use halo2_proofs::{
    dev::MockProver,
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, SingleVerifier},
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use pasta_curves::{pallas, vesta};
use rand::{rngs::StdRng, SeedableRng};

use crate::circuit::action_slice::{native, sample, ActionSliceCircuit, K, MERKLE_DEPTH};
use crate::keys::SpendingKey;
use crate::note::{from_parts, NoteKind, RandomSeed};
use crate::note_encryption::{decrypt, encrypt, GradidoDomain, NoteWithSeed};
use crate::{address, decay, memo, signature};

type Base = pallas::Base;

const NOW: u64 = 1_800_000_000;
const AGE: u64 = 400 * 86_400;
const VALUE: u64 = 1_000_0000; // 1000 GDD

#[test]
fn a_transfer_end_to_end() {
    let mut rng = StdRng::seed_from_u64(2026);
    let community = Base::from(7);

    // --- the two sides
    let spender = SpendingKey::from_bytes([21u8; 32]);
    let spender_fvk = spender.full_viewing_key();
    let spender_d = [1u8; 11];
    let recipient = SpendingKey::from_bytes([22u8; 32]).full_viewing_key();
    let recipient_address = recipient.address([2u8; 11]);

    // the recipient hands out an address, the spender reads it back
    let written = address::encode(&recipient_address, &[0xcd; 16]);
    let (parsed, parsed_community) = address::decode(&written).expect("address is readable");
    assert_eq!(parsed, recipient_address);
    assert_eq!(parsed_community, [0xcd; 16]);

    // --- the note the spender owns
    let old_rseed = RandomSeed::random(&mut rng);
    let old_rho = Base::from(4242);
    let old = from_parts(
        community,
        community,
        VALUE,
        NOW - AGE,
        NoteKind::Normal,
        5,
        &spender_fvk.address(spender_d),
        old_rho,
        Base::from(11),
        old_rseed,
    )
    .unwrap();
    let cm_old = old.commitment();
    let nf = old.nullifier(spender_fvk.nk);

    // it sits somewhere in the commitment tree
    let leaf_pos = 0x0badc0de;
    let mut path = [Base::zero(); MERKLE_DEPTH];
    for node in path.iter_mut() {
        *node = Base::random(&mut rng);
    }
    let anchor = native::merkle_root(cm_old, leaf_pos, &path);

    // --- the note the recipient gets: the decayed value, dated now, rho = the nullifier
    let value_now = decay::decay_windowed(VALUE, AGE);
    assert!(value_now < VALUE, "400 days of decay have to cost something");

    let memo_text = memo::pad(b"Danke fuer die Gartenarbeit").unwrap();
    let r_memo = Base::random(&mut rng);
    let memo_cm = memo::commit(&memo_text, r_memo);
    let memo_key = [0x77; 32];
    let sealed_memo = memo::seal(&memo_key, &memo_text, r_memo, &mut rng);

    let new_rseed = RandomSeed::random(&mut rng);
    let new = from_parts(
        community,
        community,
        value_now,
        NOW,
        NoteKind::Normal,
        9,
        &recipient_address,
        nf,
        memo_cm,
        new_rseed,
    )
    .unwrap();
    let cm_new = new.commitment();

    // --- the proof
    let alpha = pallas::Scalar::random(&mut rng);
    let rcv = pallas::Scalar::random(&mut rng);
    let circuit = ActionSliceCircuit::<true, true>::new(&old, &spender_fvk, leaf_pos, path, &new, rcv, alpha);
    // the action exposes rk and the net value commitment; a full transfer nets to zero
    let rk_point = (pallas::Point::from(spender_fvk.ak) + signature::spend_auth_base() * alpha).to_affine();
    let cv_net = signature::value_commitment(value_now as i128 - new.value as i128, rcv);
    let instance =
        ActionSliceCircuit::<true, true>::instance(community, anchor, nf, rk_point, cm_new, cv_net.to_affine(), NOW);

    let params: Params<vesta::Affine> = Params::new(K);
    let vk = keygen_vk(&params, &circuit.without_witnesses()).expect("keygen_vk");
    let pk = keygen_pk(&params, vk.clone(), &circuit.without_witnesses()).expect("keygen_pk");
    let mut transcript = Blake2bWrite::<_, vesta::Affine, Challenge255<_>>::init(vec![]);
    create_proof(&params, &pk, &[circuit], &[&[&instance]], &mut rng, &mut transcript).expect("prove");
    let proof = transcript.finalize();

    // a node checks the proof against the public inputs alone
    let mut transcript = Blake2bRead::<_, vesta::Affine, Challenge255<_>>::init(&proof[..]);
    assert!(verify_proof(
        &params,
        &vk,
        SingleVerifier::new(&params),
        &[&[&instance]],
        &mut transcript
    )
    .is_ok());

    // --- the signatures
    let sighash = [0x5e; 32];
    let spend_auth = signature::sign_spend_auth(
        &spender.spend_authorizing_key(),
        alpha,
        &sighash,
        &mut rng,
    );
    let rk = signature::randomized_verification_key(spender_fvk.ak, alpha);
    assert!(signature::verify_spend_auth(&rk, &sighash, &spend_auth));

    // the rk the proof exposes is the key the signature verifies under
    assert_eq!(<[u8; 32]>::from(rk.clone()), rk_point.to_bytes());

    // the value balance: the proof's cv_net, signed with its randomness, balances to zero
    let binding = signature::sign_binding(&[rcv], &sighash, &mut rng);
    let bvk = signature::binding_verification_key(&[cv_net], 0).unwrap();
    assert!(signature::verify_binding(&bvk, &sighash, &binding));

    // --- the recipient finds the note in the transaction
    let domain = GradidoDomain { community, coin_community: community, rho: nf };
    let output = encrypt(
        domain,
        &NoteWithSeed { note: new, rseed: new_rseed },
        [0u8; crate::note_encryption::FREE_MEMO_SIZE],
        Some(spender_fvk.ovk),
        cv_net,
        &mut rng,
    );
    let (found, address, _) = decrypt(&domain, recipient.ivk, &output).expect("the recipient can read it");

    // it is the very note the proof committed to, and it is worth the decayed amount
    assert_eq!(found.note.commitment(), cm_new);
    assert_eq!(found.note.value, value_now);
    assert_eq!(found.note.t_note, NOW);
    assert!(recipient.owns(&address));

    // --- and the memo, which needs its own key
    let (text, r) = memo::open(&memo_key, &sealed_memo).expect("memo key opens it");
    assert!(memo::verify(&text, r, found.note.memo_cm), "memo is bound to the note");
    assert_eq!(&text[..27], b"Danke fuer die Gartenarbeit");

    // someone with the viewing key but without the memo key sees the note, not the text
    assert!(memo::open(&[0x78; 32], &sealed_memo).is_none());
}

/// The same transfer, but the spender claims the value did not decay.
#[test]
fn a_transfer_that_skips_the_decay_is_rejected() {
    let f = sample::fixture::<true, true>(VALUE, AGE, Some(VALUE));
    assert!(MockProver::run(K, &f.circuit, vec![f.instance]).unwrap().verify().is_err());
}
