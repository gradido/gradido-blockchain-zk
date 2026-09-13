//! Address encoding, following ZIP 316 (privacy_todo.md E14).
//!
//! ```text
//! payload = diversifier (11) || pk_d (32) || community id (16)
//!         || HRP padded to 16 bytes
//! address = bech32m(HRP, f4jumble(payload))
//! ```
//!
//! Three things guard against typos, in that order: the Bech32m checksum, the padding that has
//! to reappear after unjumbling, and the check that `pk_d` is a curve point. F4Jumble spreads
//! every change over the whole string, so an attacker cannot craft an address that matches
//! another one at the beginning and the end — the trick people use when they compare addresses
//! by eye.

use bech32::{primitives::decode::CheckedHrpstring, Bech32m, Hrp};

use crate::keys::Address;

pub const HRP: &str = "gdd";
/// diversifier, transmission key, community id
pub const PAYLOAD_LEN: usize = 11 + 32 + 16;
const PADDING_LEN: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressError {
    Bech32,
    WrongHrp,
    Length,
    Jumble,
    Padding,
    NotAPoint,
}

fn padding() -> [u8; PADDING_LEN] {
    let mut out = [0u8; PADDING_LEN];
    out[..HRP.len()].copy_from_slice(HRP.as_bytes());
    out
}

/// Encodes an address of one community.
pub fn encode(address: &Address, community_id: &[u8; 16]) -> String {
    let mut payload = Vec::with_capacity(PAYLOAD_LEN + PADDING_LEN);
    payload.extend_from_slice(&address.to_raw());
    payload.extend_from_slice(community_id);
    payload.extend_from_slice(&padding());
    let jumbled = f4jumble::f4jumble(&payload).expect("payload length is in range");
    bech32::encode::<Bech32m>(Hrp::parse_unchecked(HRP), &jumbled).expect("valid hrp")
}

/// Decodes an address, checking the checksum, the padding and the curve point.
pub fn decode(s: &str) -> Result<(Address, [u8; 16]), AddressError> {
    let checked = CheckedHrpstring::new::<Bech32m>(s).map_err(|_| AddressError::Bech32)?;
    if !checked.hrp().as_str().eq_ignore_ascii_case(HRP) {
        return Err(AddressError::WrongHrp);
    }
    let jumbled: Vec<u8> = checked.byte_iter().collect();
    if jumbled.len() != PAYLOAD_LEN + PADDING_LEN {
        return Err(AddressError::Length);
    }
    let payload = f4jumble::f4jumble_inv(&jumbled).map_err(|_| AddressError::Jumble)?;
    if payload[PAYLOAD_LEN..] != padding() {
        return Err(AddressError::Padding);
    }
    let mut raw = [0u8; 43];
    raw.copy_from_slice(&payload[..43]);
    let address = Address::from_raw(&raw).ok_or(AddressError::NotAPoint)?;
    let mut community_id = [0u8; 16];
    community_id.copy_from_slice(&payload[43..PAYLOAD_LEN]);
    Ok((address, community_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::SpendingKey;

    fn sample() -> (Address, [u8; 16]) {
        let fvk = SpendingKey::from_bytes([9u8; 32]).full_viewing_key();
        (fvk.address([4u8; 11]), [0xab; 16])
    }

    #[test]
    fn round_trip() {
        let (address, community) = sample();
        let encoded = encode(&address, &community);
        assert!(encoded.starts_with("gdd1"));
        assert_eq!(decode(&encoded), Ok((address, community)));
    }

    #[test]
    fn every_single_character_typo_is_caught() {
        let (address, community) = sample();
        let encoded = encode(&address, &community);
        let alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
        let mut checked = 0;
        for (i, original) in encoded.char_indices().skip(HRP.len() + 1) {
            for replacement in alphabet.chars() {
                if replacement == original {
                    continue;
                }
                let mut typo: Vec<char> = encoded.chars().collect();
                typo[i] = replacement;
                let typo: String = typo.into_iter().collect();
                assert!(decode(&typo).is_err(), "typo at {i} slipped through: {typo}");
                checked += 1;
            }
        }
        assert!(checked > 1000, "only {checked} variants tested");
    }

    #[test]
    fn a_swap_of_two_characters_is_caught() {
        let (address, community) = sample();
        let encoded = encode(&address, &community);
        let mut chars: Vec<char> = encoded.chars().collect();
        let (i, j) = (10, 30);
        assert_ne!(chars[i], chars[j]);
        chars.swap(i, j);
        assert!(decode(&chars.into_iter().collect::<String>()).is_err());
    }

    #[test]
    fn wrong_prefix_is_rejected() {
        let (address, community) = sample();
        let encoded = encode(&address, &community);
        let other = encoded.replacen("gdd1", "zzz1", 1);
        assert!(decode(&other).is_err());
    }

    #[test]
    fn addresses_of_the_same_key_look_unrelated() {
        let fvk = SpendingKey::from_bytes([9u8; 32]).full_viewing_key();
        let one = encode(&fvk.address([1u8; 11]), &[0; 16]);
        let two = encode(&fvk.address([2u8; 11]), &[0; 16]);
        let shared_prefix = one.chars().zip(two.chars()).take_while(|(a, b)| a == b).count();
        // only the human readable part and the separator may match
        assert!(shared_prefix <= HRP.len() + 2, "{shared_prefix} characters in common");
    }
}
