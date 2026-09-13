//! Note encryption, on top of `zcash_note_encryption`.
//!
//! The crate brings the whole protocol — key agreement, KDF, AEAD, and the recovery path with
//! the outgoing viewing key — and asks for a `Domain` that says what a note is. That is what
//! this module provides.
//!
//! Plaintext layout, inside the sizes the crate fixes:
//!
//! ```text
//! compact (52 bytes):  version (1) | diversifier (11) | value (8) | rseed (32)
//! memo slot (512):     t_note (8) | kind (1) | expiry (8) | memo_cm (32) | free (463)
//! ```
//!
//! `psi` and `rcm` are derived from `rseed`, `rho` is the nullifier of the note that was spent,
//! and community, coin community and `rho` come from the transaction, so they need not travel.
//!
//! The free part of the memo field is where the memo ciphertext of E15 will live; the memo text
//! itself is sealed under its own key (`crate::memo`), which is why only its commitment
//! `memo_cm` is in the note.
//!
//! Compact decryption (52 bytes only) is not supported: a Gradido note needs its timestamp, and
//! that does not fit into the compact part.

use blake2b_simd::Params as Blake2bParams;
use ff::PrimeField;
use group::{Curve, GroupEncoding};
use pasta_curves::pallas;
use zcash_note_encryption::{
    Domain, EphemeralKeyBytes, NotePlaintextBytes, OutPlaintextBytes, OutgoingCipherKey,
    ShieldedOutput, COMPACT_NOTE_SIZE, ENC_CIPHERTEXT_SIZE, NOTE_PLAINTEXT_SIZE,
};

use pasta_curves::arithmetic::CurveAffine;

use crate::keys::{diversify_hash, Address, Diversifier};
use crate::note::{Note, NoteKind, RandomSeed};

pub type Base = pallas::Base;
pub const PLAINTEXT_VERSION: u8 = 0x01;
const KDF_PERSONALIZATION: &[u8; 16] = b"Gradido_KDF_____";
const OCK_PERSONALIZATION: &[u8; 16] = b"Gradido_Derive_o";
/// The note fields that do not fit into the compact part take the first bytes of the memo slot.
pub const NOTE_TAIL_SIZE: usize = 8 + 1 + 8 + 32;
/// What is left of the memo slot for the caller.
pub const FREE_MEMO_SIZE: usize = 512 - NOTE_TAIL_SIZE;

/// Everything a note needs that the transaction already fixes, so it is not encrypted.
#[derive(Clone, Copy, Debug)]
pub struct GradidoDomain {
    pub community: Base,
    pub coin_community: Base,
    /// nullifier of the spent note, which is the `rho` of the created one
    pub rho: Base,
}

/// One created note as it appears in a transaction.
#[derive(Clone, Debug)]
pub struct EncryptedNote {
    pub epk_bytes: EphemeralKeyBytes,
    pub cm: Base,
    pub enc_ciphertext: [u8; ENC_CIPHERTEXT_SIZE],
    pub out_ciphertext: [u8; zcash_note_encryption::OUT_CIPHERTEXT_SIZE],
}

impl ShieldedOutput<GradidoDomain, ENC_CIPHERTEXT_SIZE> for EncryptedNote {
    fn ephemeral_key(&self) -> EphemeralKeyBytes {
        EphemeralKeyBytes(self.epk_bytes.0)
    }
    fn cmstar_bytes(&self) -> [u8; 32] {
        self.cm.to_repr()
    }
    fn enc_ciphertext(&self) -> &[u8; ENC_CIPHERTEXT_SIZE] {
        &self.enc_ciphertext
    }
}

/// A note together with the seed its randomness comes from; that is what encryption works on,
/// because `psi` and `rcm` inside the note are derived from the seed.
#[derive(Clone, Copy, Debug)]
pub struct NoteWithSeed {
    pub note: Note,
    pub rseed: RandomSeed,
}

fn note_address(note: &Note) -> Address {
    let mut d: Diversifier = [0u8; 11];
    d.copy_from_slice(&note.d.to_le_bytes()[..11]);
    Address {
        d,
        pk_d: Option::<pallas::Affine>::from(pallas::Affine::from_xy(note.pk_d_x, note.pk_d_y))
            .expect("pk_d is on the curve"),
    }
}

impl Domain for GradidoDomain {
    type EphemeralSecretKey = pallas::Scalar;
    type EphemeralPublicKey = pallas::Point;
    type PreparedEphemeralPublicKey = pallas::Point;
    type SharedSecret = pallas::Point;
    type SymmetricKey = [u8; 32];
    type Note = NoteWithSeed;
    type Recipient = Address;
    type DiversifiedTransmissionKey = pallas::Affine;
    type IncomingViewingKey = pallas::Scalar;
    type OutgoingViewingKey = [u8; 32];
    type ValueCommitment = pallas::Point;
    type ExtractedCommitment = Base;
    type ExtractedCommitmentBytes = [u8; 32];
    type Memo = [u8; FREE_MEMO_SIZE];

    fn derive_esk(note: &Self::Note) -> Option<Self::EphemeralSecretKey> {
        Some(note.rseed.esk(note.note.rho))
    }

    fn get_pk_d(note: &Self::Note) -> Self::DiversifiedTransmissionKey {
        note_address(&note.note).pk_d
    }

    fn prepare_epk(epk: Self::EphemeralPublicKey) -> Self::PreparedEphemeralPublicKey {
        epk
    }

    fn ka_derive_public(note: &Self::Note, esk: &Self::EphemeralSecretKey) -> Self::EphemeralPublicKey {
        let mut d: Diversifier = [0u8; 11];
        d.copy_from_slice(&note.note.d.to_le_bytes()[..11]);
        diversify_hash(&d) * esk
    }

    fn ka_agree_enc(
        esk: &Self::EphemeralSecretKey,
        pk_d: &Self::DiversifiedTransmissionKey,
    ) -> Self::SharedSecret {
        pallas::Point::from(*pk_d) * esk
    }

    fn ka_agree_dec(
        ivk: &Self::IncomingViewingKey,
        epk: &Self::PreparedEphemeralPublicKey,
    ) -> Self::SharedSecret {
        epk * ivk
    }

    fn kdf(secret: Self::SharedSecret, ephemeral_key: &EphemeralKeyBytes) -> Self::SymmetricKey {
        let hash = Blake2bParams::new()
            .hash_length(32)
            .personal(KDF_PERSONALIZATION)
            .to_state()
            .update(&secret.to_affine().to_bytes())
            .update(&ephemeral_key.0)
            .finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(hash.as_bytes());
        key
    }

    fn note_plaintext_bytes(note: &Self::Note, memo: &Self::Memo) -> NotePlaintextBytes {
        let n = &note.note;
        let mut plaintext = [0u8; NOTE_PLAINTEXT_SIZE];
        plaintext[0] = PLAINTEXT_VERSION;
        plaintext[1..12].copy_from_slice(&n.d.to_le_bytes()[..11]);
        plaintext[12..20].copy_from_slice(&n.value.to_le_bytes());
        plaintext[20..52].copy_from_slice(&note.rseed.to_bytes());
        // the note fields that do not fit into the compact part come first, then the memo
        plaintext[52..60].copy_from_slice(&n.t_note.to_le_bytes());
        plaintext[60] = n.kind as u8;
        plaintext[61..69].copy_from_slice(&n.expiry_epoch.to_le_bytes());
        plaintext[69..101].copy_from_slice(&n.memo_cm.to_repr());
        plaintext[101..].copy_from_slice(memo);
        NotePlaintextBytes(plaintext)
    }

    fn derive_ock(
        ovk: &Self::OutgoingViewingKey,
        cv: &Self::ValueCommitment,
        cmstar_bytes: &Self::ExtractedCommitmentBytes,
        ephemeral_key: &EphemeralKeyBytes,
    ) -> OutgoingCipherKey {
        let hash = Blake2bParams::new()
            .hash_length(32)
            .personal(OCK_PERSONALIZATION)
            .to_state()
            .update(ovk)
            .update(&cv.to_affine().to_bytes())
            .update(cmstar_bytes)
            .update(&ephemeral_key.0)
            .finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(hash.as_bytes());
        OutgoingCipherKey(key)
    }

    fn outgoing_plaintext_bytes(
        note: &Self::Note,
        esk: &Self::EphemeralSecretKey,
    ) -> OutPlaintextBytes {
        let mut out = [0u8; zcash_note_encryption::OUT_PLAINTEXT_SIZE];
        out[..32].copy_from_slice(&note_address(&note.note).pk_d.to_bytes());
        out[32..].copy_from_slice(&esk.to_repr());
        OutPlaintextBytes(out)
    }

    fn epk_bytes(epk: &Self::EphemeralPublicKey) -> EphemeralKeyBytes {
        EphemeralKeyBytes(epk.to_affine().to_bytes())
    }

    fn epk(ephemeral_key: &EphemeralKeyBytes) -> Option<Self::EphemeralPublicKey> {
        use group::Group;
        let epk = Option::<pallas::Point>::from(pallas::Point::from_bytes(&ephemeral_key.0))?;
        (!bool::from(epk.is_identity())).then_some(epk)
    }

    fn cmstar(note: &Self::Note) -> Self::ExtractedCommitment {
        note.note.commitment()
    }

    fn parse_note_plaintext_without_memo_ivk(
        &self,
        ivk: &Self::IncomingViewingKey,
        plaintext: &[u8],
    ) -> Option<(Self::Note, Self::Recipient)> {
        // the transmission key is not transmitted; the receiver derives it from the
        // diversifier with its own ivk, which is also what makes this note theirs
        let d = diversifier_of(plaintext)?;
        self.parse(plaintext, (diversify_hash(&d) * ivk).to_affine())
    }

    fn parse_note_plaintext_without_memo_ovk(
        &self,
        pk_d: &Self::DiversifiedTransmissionKey,
        plaintext: &NotePlaintextBytes,
    ) -> Option<(Self::Note, Self::Recipient)> {
        self.parse(&plaintext.0, *pk_d)
    }

    fn extract_memo(&self, plaintext: &NotePlaintextBytes) -> Self::Memo {
        let mut memo = [0u8; FREE_MEMO_SIZE];
        memo.copy_from_slice(&plaintext.0[COMPACT_NOTE_SIZE + NOTE_TAIL_SIZE..]);
        memo
    }

    fn extract_pk_d(out_plaintext: &OutPlaintextBytes) -> Option<Self::DiversifiedTransmissionKey> {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&out_plaintext.0[..32]);
        use group::prime::PrimeCurveAffine;
        let pk_d = Option::<pallas::Affine>::from(pallas::Affine::from_bytes(&bytes))?;
        (!bool::from(pk_d.is_identity())).then_some(pk_d)
    }

    fn extract_esk(out_plaintext: &OutPlaintextBytes) -> Option<Self::EphemeralSecretKey> {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&out_plaintext.0[32..]);
        Option::from(pallas::Scalar::from_repr(bytes))
    }
}

/// Diversifier of a plaintext, if it looks like one at all.
fn diversifier_of(plaintext: &[u8]) -> Option<Diversifier> {
    if plaintext.len() < NOTE_PLAINTEXT_SIZE || plaintext[0] != PLAINTEXT_VERSION {
        return None;
    }
    let mut d: Diversifier = [0u8; 11];
    d.copy_from_slice(&plaintext[1..12]);
    Some(d)
}

impl GradidoDomain {
    /// Rebuilds a note from a decrypted plaintext and the transmission key of its address.
    fn parse(&self, plaintext: &[u8], pk_d: pallas::Affine) -> Option<(NoteWithSeed, Address)> {
        let d = diversifier_of(plaintext)?;
        let value = u64::from_le_bytes(plaintext[12..20].try_into().ok()?);
        let mut rseed_bytes = [0u8; 32];
        rseed_bytes.copy_from_slice(&plaintext[20..52]);
        let rseed = RandomSeed::from_bytes(rseed_bytes);

        let t_note = u64::from_le_bytes(plaintext[52..60].try_into().ok()?);
        let kind = match plaintext[60] {
            0 => NoteKind::Normal,
            1 => NoteKind::Deferred,
            _ => return None,
        };
        let expiry_epoch = u64::from_le_bytes(plaintext[61..69].try_into().ok()?);
        let memo_cm = Option::<Base>::from(Base::from_repr(plaintext[69..101].try_into().ok()?))?;

        let address = Address { d, pk_d };
        let note = crate::note::from_parts(
            self.community,
            self.coin_community,
            value,
            t_note,
            kind,
            expiry_epoch,
            &address,
            self.rho,
            memo_cm,
            rseed,
        )
        .ok()?;
        Some((NoteWithSeed { note, rseed }, address))
    }
}

/// Encrypts a note for its recipient, and for the sender's own outgoing viewing key.
pub fn encrypt(
    domain: GradidoDomain,
    note: &NoteWithSeed,
    memo: [u8; FREE_MEMO_SIZE],
    ovk: Option<[u8; 32]>,
    cv: pallas::Point,
    rng: &mut impl rand::RngCore,
) -> EncryptedNote {
    let _ = domain;
    let encryptor = zcash_note_encryption::NoteEncryption::<GradidoDomain>::new(ovk, *note, memo);
    let enc_ciphertext = encryptor.encrypt_note_plaintext();
    let cm = note.note.commitment();
    let out_ciphertext = encryptor.encrypt_outgoing_plaintext(&cv, &cm, rng);
    let epk_bytes = GradidoDomain::epk_bytes(encryptor.epk());
    EncryptedNote { epk_bytes, cm, enc_ciphertext, out_ciphertext }
}

/// The receiver's side: find and rebuild a note with the incoming viewing key.
pub fn decrypt(
    domain: &GradidoDomain,
    ivk: pallas::Scalar,
    output: &EncryptedNote,
) -> Option<(NoteWithSeed, Address, [u8; FREE_MEMO_SIZE])> {
    zcash_note_encryption::try_note_decryption(domain, &ivk, output)
}

/// The sender's side: recover an own outgoing note with the outgoing viewing key.
pub fn recover(
    domain: &GradidoDomain,
    ovk: &[u8; 32],
    cv: pallas::Point,
    output: &EncryptedNote,
) -> Option<(NoteWithSeed, Address, [u8; FREE_MEMO_SIZE])> {
    zcash_note_encryption::try_output_recovery_with_ovk(
        domain,
        ovk,
        output,
        &cv,
        &output.out_ciphertext,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::SpendingKey;
    use crate::note::NoteKind;
    use crate::signature::value_commitment;
    use ff::Field;
    use rand::{rngs::StdRng, SeedableRng};

    struct Setup {
        domain: GradidoDomain,
        note: NoteWithSeed,
        memo: [u8; FREE_MEMO_SIZE],
        cv: pallas::Point,
        output: EncryptedNote,
        recipient_ivk: pallas::Scalar,
        sender_ovk: [u8; 32],
    }

    fn setup() -> Setup {
        let mut rng = StdRng::seed_from_u64(11);
        let recipient = SpendingKey::from_bytes([1u8; 32]).full_viewing_key();
        let sender = SpendingKey::from_bytes([2u8; 32]).full_viewing_key();
        let address = recipient.address([7u8; 11]);

        let domain = GradidoDomain {
            community: Base::from(42),
            coin_community: Base::from(42),
            rho: Base::from(999),
        };
        let rseed = RandomSeed::random(&mut rng);
        let note = NoteWithSeed {
            note: crate::note::from_parts(
                domain.community,
                domain.coin_community,
                1_000_0000,
                1_800_000_000,
                NoteKind::Normal,
                7,
                &address,
                domain.rho,
                Base::from(0x1234),
                rseed,
            )
            .unwrap(),
            rseed,
        };
        let mut memo = [0u8; FREE_MEMO_SIZE];
        memo[..9].copy_from_slice(b"thank you");
        let cv = value_commitment(1_000_0000, pallas::Scalar::random(&mut rng));
        let output = encrypt(domain, &note, memo, Some(sender.ovk), cv, &mut rng);
        Setup {
            domain,
            note,
            memo,
            cv,
            output,
            recipient_ivk: recipient.ivk,
            sender_ovk: sender.ovk,
        }
    }

    #[test]
    fn recipient_can_decrypt_and_rebuild_the_note() {
        let s = setup();
        let (note, address, memo) = decrypt(&s.domain, s.recipient_ivk, &s.output).expect("decrypts");
        // the rebuilt note is the very note the commitment was made over
        assert_eq!(note.note.commitment(), s.note.note.commitment());
        assert_eq!(note.note.value, s.note.note.value);
        assert_eq!(note.note.t_note, s.note.note.t_note);
        assert_eq!(note.note.memo_cm, s.note.note.memo_cm);
        assert_eq!(note.rseed, s.note.rseed);
        assert_eq!(address.pk_d, note_address(&s.note.note).pk_d);
        assert_eq!(&memo[..9], b"thank you");
    }

    #[test]
    fn a_stranger_learns_nothing() {
        let s = setup();
        let stranger = SpendingKey::from_bytes([3u8; 32]).full_viewing_key();
        assert!(decrypt(&s.domain, stranger.ivk, &s.output).is_none());
    }

    #[test]
    fn a_tampered_ciphertext_is_rejected() {
        let mut s = setup();
        s.output.enc_ciphertext[17] ^= 1;
        assert!(decrypt(&s.domain, s.recipient_ivk, &s.output).is_none());
    }

    #[test]
    fn the_sender_can_recover_the_note_afterwards() {
        let s = setup();
        let (note, address, memo) =
            recover(&s.domain, &s.sender_ovk, s.cv, &s.output).expect("recovers");
        assert_eq!(note.note.commitment(), s.note.note.commitment());
        assert_eq!(address.pk_d, note_address(&s.note.note).pk_d);
        assert_eq!(memo, s.memo);
    }

    #[test]
    fn another_sender_cannot_recover_it() {
        let s = setup();
        let other = SpendingKey::from_bytes([4u8; 32]).full_viewing_key();
        assert!(recover(&s.domain, &other.ovk, s.cv, &s.output).is_none());
    }

    /// `rho` comes from the transaction. Pairing a ciphertext with another action rebuilds a
    /// note whose commitment does not match, and the crate rejects exactly that.
    #[test]
    fn a_ciphertext_paired_with_the_wrong_action_is_rejected() {
        let s = setup();
        let other_domain = GradidoDomain { rho: Base::from(1000), ..s.domain };
        assert!(decrypt(&other_domain, s.recipient_ivk, &s.output).is_none());
    }
}
