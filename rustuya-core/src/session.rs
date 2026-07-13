//! Session-key negotiation for v3.4 / v3.5 (pure computation).
//!
//! The three-step handshake (tinytuya-compatible):
//!   1. client → device `SessKeyNegStart`: the client's 16-byte `local_nonce`;
//!   2. device → client `SessKeyNegResp`: `remote_nonce(16) || HMAC(local_key, local_nonce)(32)`;
//!   3. client → device `SessKeyNegFinish`: `HMAC(local_key, remote_nonce)`.
//!
//! Both sides then derive the session key from `local_nonce XOR remote_nonce`:
//!   * **v3.4**: `AES-128-ECB(local_key, xor)` (one block, no padding);
//!   * **v3.5**: the 16-byte GCM ciphertext of `xor` under
//!     `(local_key, iv = local_nonce[..12])`.
//!
//! This module is pure: the `local_nonce` is **supplied by the caller** (the FSM
//! draws it from its injected RNG), so the core touches no randomness and the
//! handshake is deterministic under test.

use alloc::vec::Vec;
use cipher::KeyInit;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::crypto::TuyaCipher;
use crate::version::Version;
use crate::{CoreError, Result};

type HmacSha256 = Hmac<Sha256>;

/// An in-progress handshake, holding the client's nonce between steps.
pub struct Handshake {
    local_nonce: [u8; 16],
}

/// The result of a completed handshake.
pub struct Finished {
    /// Sent to the device in `SessKeyNegFinish`.
    pub finish_hmac: Vec<u8>,
    /// The 16-byte key used to encrypt/HMAC all subsequent messages.
    pub session_key: Vec<u8>,
}

impl Handshake {
    /// Begins a handshake with a caller-supplied nonce (from the FSM's RNG).
    #[must_use]
    pub fn new(local_nonce: [u8; 16]) -> Self {
        Self { local_nonce }
    }

    /// The nonce to place in the `SessKeyNegStart` payload.
    #[must_use]
    pub fn local_nonce(&self) -> &[u8; 16] {
        &self.local_nonce
    }

    /// Verifies the device's `SessKeyNegResp` and returns its `remote_nonce`.
    /// Rejects a short payload or a bad HMAC (wrong local key).
    pub fn verify_response(&self, remote_payload: &[u8], local_key: &[u8]) -> Result<[u8; 16]> {
        if remote_payload.len() < 48 {
            return Err(CoreError::Truncated);
        }
        let remote_nonce: [u8; 16] = remote_payload[..16].try_into().expect("checked len >= 16");
        let remote_hmac = &remote_payload[16..48];

        let mut mac = HmacSha256::new_from_slice(local_key).expect("HMAC takes any key length");
        mac.update(&self.local_nonce);
        mac.verify_slice(remote_hmac)
            .map_err(|_| CoreError::HmacMismatch)?;
        Ok(remote_nonce)
    }

    /// Derives the session key and the finish HMAC.
    pub fn finish(
        &self,
        version: Version,
        remote_nonce: &[u8; 16],
        local_key: &[u8],
    ) -> Result<Finished> {
        let mut mac = HmacSha256::new_from_slice(local_key).expect("HMAC takes any key length");
        mac.update(remote_nonce);
        let finish_hmac = mac.finalize().into_bytes().to_vec();

        let mut xor = [0u8; 16];
        for (x, (&l, &r)) in xor.iter_mut().zip(self.local_nonce.iter().zip(remote_nonce)) {
            *x = l ^ r;
        }

        let cipher = TuyaCipher::new(local_key)?;
        let session_key = match version {
            Version::V3_4 => cipher.ecb_encrypt_block(&xor).to_vec(),
            Version::V3_5 => {
                let iv: [u8; 12] = self.local_nonce[..12].try_into().expect("16 >= 12");
                let ct = cipher.gcm_encrypt(&iv, &xor, &[])?;
                ct[..16].to_vec() // GCM ciphertext of the xor, without the tag
            }
            _ => return Err(CoreError::EncryptFailed), // only v3.4/v3.5 negotiate
        };
        Ok(Finished {
            finish_hmac,
            session_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCAL_KEY: &[u8] = b"0123456789abcdef";
    const LOCAL_NONCE: [u8; 16] = [1u8; 16];
    const REMOTE_NONCE: [u8; 16] = [2u8; 16];

    /// Builds a valid `SessKeyNegResp` for the given nonces/key.
    fn good_response() -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(LOCAL_KEY).unwrap();
        mac.update(&LOCAL_NONCE);
        let hmac = mac.finalize().into_bytes();
        let mut resp = REMOTE_NONCE.to_vec();
        resp.extend_from_slice(&hmac);
        resp
    }

    #[test]
    fn verify_accepts_good_and_rejects_bad_and_short() {
        let hs = Handshake::new(LOCAL_NONCE);
        assert_eq!(hs.verify_response(&good_response(), LOCAL_KEY).unwrap(), REMOTE_NONCE);

        let mut bad = good_response();
        *bad.last_mut().unwrap() ^= 0xff;
        assert_eq!(hs.verify_response(&bad, LOCAL_KEY), Err(CoreError::HmacMismatch));
        assert_eq!(hs.verify_response(&good_response(), b"wrongkey00000000"), Err(CoreError::HmacMismatch));
        assert_eq!(hs.verify_response(&[0u8; 40], LOCAL_KEY), Err(CoreError::Truncated));
    }

    #[test]
    fn finish_derives_16_byte_keys_deterministically() {
        let hs = Handshake::new(LOCAL_NONCE);
        for v in [Version::V3_4, Version::V3_5] {
            let a = hs.finish(v, &REMOTE_NONCE, LOCAL_KEY).unwrap();
            let b = hs.finish(v, &REMOTE_NONCE, LOCAL_KEY).unwrap();
            assert_eq!(a.session_key.len(), 16, "{v:?}");
            assert_eq!(a.finish_hmac.len(), 32, "{v:?}");
            assert_eq!(a.session_key, b.session_key, "{v:?} deterministic");
        }
        // v3.4 and v3.5 derive different keys from the same nonces.
        let k34 = Handshake::new(LOCAL_NONCE).finish(Version::V3_4, &REMOTE_NONCE, LOCAL_KEY).unwrap();
        let k35 = Handshake::new(LOCAL_NONCE).finish(Version::V3_5, &REMOTE_NONCE, LOCAL_KEY).unwrap();
        assert_ne!(k34.session_key, k35.session_key);
    }

    #[test]
    fn non_session_version_is_rejected() {
        let hs = Handshake::new(LOCAL_NONCE);
        assert!(hs.finish(Version::V3_3, &REMOTE_NONCE, LOCAL_KEY).is_err());
    }
}
