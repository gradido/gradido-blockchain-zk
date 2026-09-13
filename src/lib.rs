//! Zero-knowledge circuits for Gradido, built on halo2 (Pasta curves, IPA, no trusted setup).
//!
//! Scope today: shielded transfers after the Orchard model with decay inside the proof —
//! action circuit, keys, addresses, note encryption, signatures, commitment tree, bundle,
//! wire format and a C ABI for the node. See `privacy_todo.md` in the repository root for
//! the surrounding design and the roadmap.

pub mod address;
pub mod bundle;
pub mod circuit;
pub mod decay;
pub mod keys;
pub mod memo;
pub mod note;
pub mod note_encryption;
// the C ABI is for the node; in WebAssembly its exports would only drag the prover along
#[cfg(not(target_arch = "wasm32"))]
pub mod ffi;
pub mod prover;
pub mod signature;
pub mod signer;
pub mod tree;
#[cfg(target_arch = "wasm32")]
pub mod wasm;
pub mod wire;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_bundle;
#[cfg(test)]
mod tests_decay;
#[cfg(test)]
mod tests_e2e;
#[cfg(test)]
mod tests_signer;
