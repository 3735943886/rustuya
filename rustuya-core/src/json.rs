//! JSON seam (design decision D8).
//!
//! The **single** module that touches `serde_json`, so a later swap to a leaner
//! backend (`serde-json-core`, a hand-rolled writer) stays local. The byte-level
//! core — `frame`, `crypto`, `version` — does not use this at all; only the
//! command-generation / response-parsing layer does. See `docs/MILESTONES.md` (D8)
//! and `docs/DESIGN.md`.

use alloc::vec::Vec;

pub use serde_json::{Map, Value};

/// Serializes a JSON value to bytes for the wire.
#[must_use]
pub fn to_bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap_or_default()
}

/// Parses JSON bytes, returning `None` on malformed input.
#[must_use]
pub fn from_bytes(bytes: &[u8]) -> Option<Value> {
    serde_json::from_slice(bytes).ok()
}

/// Parses the **first** JSON value in `bytes`, ignoring any trailing bytes after
/// it. Unlike [`from_bytes`] (which rejects trailing content), this tolerates the
/// zero/PKCS padding a decrypted discovery payload can carry after the closing
/// brace. Returns `None` if no value parses at the start.
#[must_use]
pub fn from_bytes_prefix(bytes: &[u8]) -> Option<Value> {
    serde_json::Deserializer::from_slice(bytes)
        .into_iter::<Value>()
        .next()
        .and_then(Result::ok)
}
