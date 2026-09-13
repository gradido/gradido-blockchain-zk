//! The memo of E15: encrypted under its own key, bound by the note.
//!
//! The note carries only `memo_cm = Poseidon(H(memo), r_memo)`. Whoever holds the memo key can
//! read the text and recompute the commitment, and because the commitment sits inside the note
//! commitment, nobody can change the text afterwards. The note itself can be read with the
//! viewing key without revealing the memo — two keys, two levels of insight.
//!
//! The ciphertext has a fixed length, so it leaks nothing about how much was written.

use blake2b_simd::Params as Blake2bParams;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use ff::{FromUniformBytes, PrimeField};
use halo2_gadgets::poseidon::primitives::{ConstantLength, Hash, P128Pow5T3};
use pasta_curves::pallas;
use rand::RngCore;

pub type Base = pallas::Base;

/// Every memo is padded to this length before sealing.
pub const MEMO_LEN: usize = 512;
/// nonce, ciphertext of memo and r_memo, tag
pub const SEALED_LEN: usize = 12 + MEMO_LEN + 32 + 16;

const MEMO_HASH_PERSONALIZATION: &[u8; 16] = b"Gradido_MemoHash";

/// The memo text as one field element.
pub fn memo_hash(memo: &[u8; MEMO_LEN]) -> Base {
    let hash = Blake2bParams::new()
        .hash_length(64)
        .personal(MEMO_HASH_PERSONALIZATION)
        .to_state()
        .update(memo)
        .finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(hash.as_bytes());
    Base::from_uniform_bytes(&wide)
}

/// `memo_cm = Poseidon(H(memo), r_memo)`, the value that goes into the note.
pub fn commit(memo: &[u8; MEMO_LEN], r_memo: Base) -> Base {
    Hash::<_, P128Pow5T3, ConstantLength<2>, 3, 2>::init().hash([memo_hash(memo), r_memo])
}

/// Pads a text to the fixed memo length; longer texts are refused rather than cut.
pub fn pad(text: &[u8]) -> Option<[u8; MEMO_LEN]> {
    if text.len() > MEMO_LEN {
        return None;
    }
    let mut memo = [0u8; MEMO_LEN];
    memo[..text.len()].copy_from_slice(text);
    Some(memo)
}

/// Encrypts memo and opening under the memo key.
pub fn seal(
    key: &[u8; 32],
    memo: &[u8; MEMO_LEN],
    r_memo: Base,
    rng: &mut impl RngCore,
) -> [u8; SEALED_LEN] {
    let mut nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut nonce_bytes);
    let mut plaintext = Vec::with_capacity(MEMO_LEN + 32);
    plaintext.extend_from_slice(memo);
    plaintext.extend_from_slice(&r_memo.to_repr());

    let cipher = ChaCha20Poly1305::new(key.into());
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), Payload { msg: &plaintext, aad: &[] })
        .expect("encryption never fails for a fixed length message");

    let mut sealed = [0u8; SEALED_LEN];
    sealed[..12].copy_from_slice(&nonce_bytes);
    sealed[12..].copy_from_slice(&ciphertext);
    sealed
}

/// Decrypts memo and opening; `None` if the key is wrong or the bytes were touched.
pub fn open(key: &[u8; 32], sealed: &[u8; SEALED_LEN]) -> Option<([u8; MEMO_LEN], Base)> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&sealed[..12]), Payload { msg: &sealed[12..], aad: &[] })
        .ok()?;
    let mut memo = [0u8; MEMO_LEN];
    memo.copy_from_slice(&plaintext[..MEMO_LEN]);
    let mut r_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&plaintext[MEMO_LEN..]);
    let r_memo = Option::<Base>::from(Base::from_repr(r_bytes))?;
    Some((memo, r_memo))
}

/// Does this memo belong to the commitment inside the note?
pub fn verify(memo: &[u8; MEMO_LEN], r_memo: Base, memo_cm: Base) -> bool {
    commit(memo, r_memo) == memo_cm
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;
    use rand::{rngs::StdRng, SeedableRng};

    fn sample() -> ([u8; 32], [u8; MEMO_LEN], Base, [u8; SEALED_LEN]) {
        let mut rng = StdRng::seed_from_u64(21);
        let key = [0x5a; 32];
        let memo = pad(b"Gemeinwohlarbeit im Maerz, 12 Stunden").unwrap();
        let r_memo = Base::random(&mut rng);
        let sealed = seal(&key, &memo, r_memo, &mut rng);
        (key, memo, r_memo, sealed)
    }

    #[test]
    fn the_memo_key_opens_it_and_the_commitment_matches() {
        let (key, memo, r_memo, sealed) = sample();
        let memo_cm = commit(&memo, r_memo);
        let (opened, r) = open(&key, &sealed).expect("opens");
        assert_eq!(opened, memo);
        assert_eq!(r, r_memo);
        assert!(verify(&opened, r, memo_cm));
    }

    #[test]
    fn another_key_does_not_open_it() {
        let (_, _, _, sealed) = sample();
        assert!(open(&[0x5b; 32], &sealed).is_none());
    }

    #[test]
    fn tampering_is_caught() {
        let (key, _, _, mut sealed) = sample();
        sealed[100] ^= 1;
        assert!(open(&key, &sealed).is_none());
    }

    /// The point of the whole construction: the text cannot be swapped afterwards.
    #[test]
    fn a_changed_text_no_longer_matches_the_note() {
        let (_, memo, r_memo, _) = sample();
        let memo_cm = commit(&memo, r_memo);
        let forged = pad(b"Gemeinwohlarbeit im Maerz, 120 Stunden").unwrap();
        assert!(!verify(&forged, r_memo, memo_cm));
    }

    #[test]
    fn the_commitment_hides_the_text() {
        let mut rng = StdRng::seed_from_u64(22);
        let memo = pad(b"ja").unwrap();
        let one = commit(&memo, Base::random(&mut rng));
        let two = commit(&memo, Base::random(&mut rng));
        assert_ne!(one, two, "different openings must give different commitments");
    }

    #[test]
    fn every_memo_has_the_same_length() {
        let short = seal(&[1u8; 32], &pad(b"x").unwrap(), Base::one(), &mut StdRng::seed_from_u64(1));
        let long = seal(&[1u8; 32], &pad(&[b'y'; 400]).unwrap(), Base::one(), &mut StdRng::seed_from_u64(1));
        assert_eq!(short.len(), long.len());
        assert!(pad(&[0u8; MEMO_LEN + 1]).is_none());
    }
}
