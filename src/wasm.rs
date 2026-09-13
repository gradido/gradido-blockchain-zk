//! JavaScript interface of the signing device, for a wallet app or browser extension.
//!
//! Only what the device side of the custody split (E5) needs: keys, addresses, and checking and
//! signing a `SigningRequest` from the community server (`crate::signer`). Proving stays on the
//! server. Byte strings cross the boundary as `Uint8Array`, amounts (GradidoUnit) as `BigInt`.
//!
//! ```js
//! const sk = generateSpendingKey();                        // keep it in the device's key store
//! const fvk = viewingKey(sk);                              // 128 bytes, for the community server
//! const addr = address(sk, diversifier, communityId);      // "gdd1..."
//!
//! const review = reviewSigningRequest(sk, community, communityId, requestBytes);
//! // show review.payments and review.change, ask the owner
//! const { signatures } = signSigningRequest(sk, community, communityId, requestBytes);
//! ```
//!
//! Every function throws an `Error` with the reason when a check fails. The spending key is
//! passed in by the caller; storing it safely is the app's job, this module keeps no copy.
//!
//! Build: `cargo build --release --target wasm32-unknown-unknown --lib`, then
//! `wasm-bindgen --target web` (or `nodejs`) with the wasm-bindgen CLI version of Cargo.lock.

use ff::PrimeField;
use js_sys::{Array, BigInt, Object, Reflect, Uint8Array};
use pasta_curves::pallas;
use rand::rngs::OsRng;
use wasm_bindgen::prelude::*;

use crate::address;
use crate::keys::SpendingKey;
use crate::note::NoteKind;
use crate::signer::{self, Review, SigningRequest};

#[wasm_bindgen(typescript_custom_section)]
const TYPES: &str = r#"
/** A payment to someone else, as the device shows it. */
export interface Payment {
  /** "gdd1..." */
  address: string;
  /** GradidoUnit (GDD * 10^4) at createdAt */
  value: bigint;
  kind: "normal" | "deferred";
  /** memo text (E15) without zero padding, null for none */
  memo: Uint8Array | null;
  /** free part of the memo slot in the note encryption, without zero padding */
  freeMemo: Uint8Array;
}

/** What signing a request means. */
export interface Review {
  /** seconds */
  createdAt: number;
  payments: Payment[];
  /** GradidoUnit that comes back to the owner's own addresses */
  change: bigint;
  /** number of spends the device signs */
  spends: number;
  /** 32 bytes, computed from the transaction body */
  sighash: Uint8Array;
}

export interface Signed {
  review: Review;
  /** 64 bytes each, in action order, for UnauthorizedBundle::authorize on the server */
  signatures: Uint8Array[];
}

export interface DecodedAddress {
  /** 43 bytes: diversifier (11) and pk_d (32) */
  raw: Uint8Array;
  /** 16 bytes */
  communityId: Uint8Array;
}
"#;

fn array<const N: usize>(bytes: &[u8], what: &str) -> Result<[u8; N], JsError> {
    bytes.try_into().map_err(|_| JsError::new(&format!("{what} must be {N} bytes, got {}", bytes.len())))
}

fn spending_key(bytes: &[u8]) -> Result<SpendingKey, JsError> {
    Ok(SpendingKey::from_bytes(array(bytes, "spending key")?))
}

fn community(bytes: &[u8]) -> Result<pallas::Base, JsError> {
    Option::from(pallas::Base::from_repr(array(bytes, "community")?))
        .ok_or_else(|| JsError::new("community is not a canonical field element"))
}

fn set(object: &Object, key: &str, value: impl Into<JsValue>) {
    Reflect::set(object, &JsValue::from_str(key), &value.into()).expect("setting a property of a plain object");
}

fn bytes(data: &[u8]) -> Uint8Array {
    Uint8Array::from(data)
}

/// Memo text without the zero padding.
fn unpadded(data: &[u8]) -> Uint8Array {
    let end = data.iter().rposition(|b| *b != 0).map_or(0, |i| i + 1);
    bytes(&data[..end])
}

fn review_object(review: &Review, community_id: &[u8; 16]) -> Object {
    let payments = Array::new();
    for p in &review.payments {
        let payment = Object::new();
        set(&payment, "address", address::encode(&p.address, community_id));
        set(&payment, "value", BigInt::from(p.value));
        set(&payment, "kind", match p.kind {
            NoteKind::Normal => "normal",
            NoteKind::Deferred => "deferred",
        });
        set(&payment, "memo", p.memo.as_ref().map_or(JsValue::NULL, |m| unpadded(m).into()));
        set(&payment, "freeMemo", unpadded(&p.free_memo));
        payments.push(&payment);
    }
    let object = Object::new();
    set(&object, "createdAt", review.created_at as f64);
    set(&object, "payments", payments);
    set(&object, "change", BigInt::from(review.change));
    set(&object, "spends", review.spends as u32);
    set(&object, "sighash", bytes(&review.sighash));
    object
}

/// A new random spending key, 32 bytes, from the platform's secure random source.
#[wasm_bindgen(js_name = generateSpendingKey)]
pub fn generate_spending_key() -> Uint8Array {
    bytes(&SpendingKey::random(&mut OsRng).to_bytes())
}

/// The full viewing key for the community server, 128 bytes (`ak | nk | rivk | ovk`). With it
/// the server can prove, decrypt and show balances, but not spend.
#[wasm_bindgen(js_name = viewingKey)]
pub fn viewing_key(#[wasm_bindgen(js_name = spendingKey)] spending_key_bytes: &[u8]) -> Result<Uint8Array, JsError> {
    Ok(bytes(&spending_key(spending_key_bytes)?.full_viewing_key().to_bytes()))
}

/// The address for an 11-byte diversifier, encoded for a community (16-byte id).
#[wasm_bindgen]
pub fn address(
    #[wasm_bindgen(js_name = spendingKey)] spending_key_bytes: &[u8],
    diversifier: &[u8],
    #[wasm_bindgen(js_name = communityId)] community_id: &[u8],
) -> Result<String, JsError> {
    let fvk = spending_key(spending_key_bytes)?.full_viewing_key();
    Ok(address::encode(&fvk.address(array(diversifier, "diversifier")?), &array(community_id, "community id")?))
}

/// The creation address for one target month (E7).
#[wasm_bindgen(js_name = creationAddress)]
pub fn creation_address(
    #[wasm_bindgen(js_name = spendingKey)] spending_key_bytes: &[u8],
    year: u32,
    month: u32,
    #[wasm_bindgen(js_name = communityId)] community_id: &[u8],
) -> Result<String, JsError> {
    let fvk = spending_key(spending_key_bytes)?.full_viewing_key();
    let address = fvk.creation_address(year, month).ok_or_else(|| JsError::new("month must be 1 to 12"))?;
    Ok(address::encode(&address, &array(community_id, "community id")?))
}

/// Checks an address someone typed or scanned: `{ raw: Uint8Array(43), communityId: Uint8Array(16) }`.
#[wasm_bindgen(js_name = decodeAddress, unchecked_return_type = "DecodedAddress")]
pub fn decode_address(text: &str) -> Result<Object, JsError> {
    let (address, community_id) = address::decode(text).map_err(|e| JsError::new(&format!("invalid address: {e:?}")))?;
    let object = Object::new();
    set(&object, "raw", bytes(&address.to_raw()));
    set(&object, "communityId", bytes(&community_id));
    Ok(object)
}

/// Checks a signing request against the key without signing:
/// `{ createdAt, payments: [{ address, value, kind, memo, freeMemo }], change, spends, sighash }`.
/// `community` is the 32-byte field element of the community, `communityId` its 16-byte id for
/// the address encoding.
#[wasm_bindgen(js_name = reviewSigningRequest, unchecked_return_type = "Review")]
pub fn review_signing_request(
    #[wasm_bindgen(js_name = spendingKey)] spending_key_bytes: &[u8],
    #[wasm_bindgen(js_name = community)] community_bytes: &[u8],
    #[wasm_bindgen(js_name = communityId)] community_id: &[u8],
    request: &[u8],
) -> Result<Object, JsError> {
    let request = SigningRequest::decode(request).map_err(|e| JsError::new(&format!("{e:?}")))?;
    let review = signer::review(&request, &spending_key(spending_key_bytes)?, community(community_bytes)?)
        .map_err(|e| JsError::new(&format!("{e:?}")))?;
    Ok(review_object(&review, &array(community_id, "community id")?))
}

/// Checks the request and signs it: `{ review, signatures: [Uint8Array(64), ...] }`. The
/// signatures go back to the server only after the owner has seen `review`.
#[wasm_bindgen(js_name = signSigningRequest, unchecked_return_type = "Signed")]
pub fn sign_signing_request(
    #[wasm_bindgen(js_name = spendingKey)] spending_key_bytes: &[u8],
    #[wasm_bindgen(js_name = community)] community_bytes: &[u8],
    #[wasm_bindgen(js_name = communityId)] community_id: &[u8],
    request: &[u8],
) -> Result<Object, JsError> {
    let request = SigningRequest::decode(request).map_err(|e| JsError::new(&format!("{e:?}")))?;
    let (review, signatures) =
        signer::sign(&request, &spending_key(spending_key_bytes)?, community(community_bytes)?, &mut OsRng)
            .map_err(|e| JsError::new(&format!("{e:?}")))?;
    let list = Array::new();
    for signature in &signatures {
        list.push(&bytes(&signer::signature_bytes(signature)));
    }
    let object = Object::new();
    set(&object, "review", review_object(&review, &array(community_id, "community id")?));
    set(&object, "signatures", list);
    Ok(object)
}
