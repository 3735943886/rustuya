//! AES primitives for the Tuya local protocol.
//!
//! * **AES-128-ECB + PKCS7** — v3.1 / v3.3 payloads.
//! * **AES-128-GCM** (12-byte IV, 16-byte tag, frame header as AAD) — v3.4 / v3.5.
//!
//! This module does raw AES only. Base64 wrapping (v3.1/3.3), IV placement, and
//! framing belong to the protocol layer, not here. The GCM IV is supplied by the
//! caller — the core never generates randomness itself; the driver injects it.

use aes::Aes128;
use aes_gcm::{
    Aes128Gcm, Nonce,
    aead::{Aead, KeyInit, Payload, consts::U12},
};
use alloc::vec::Vec;
use cipher::{Block, BlockModeDecrypt, BlockModeEncrypt};
use ecb::{Decryptor, Encryptor};

use crate::{CoreError, Result};

const BLOCK: usize = 16;

/// A key-bound cipher for one device session (16-byte AES-128 key).
pub struct TuyaCipher {
    key: [u8; 16],
    gcm: Aes128Gcm,
}

impl TuyaCipher {
    /// Binds a 16-byte AES-128 key. Errors if the key is not exactly 16 bytes.
    pub fn new(key: &[u8]) -> Result<Self> {
        let key: [u8; 16] = key.try_into().map_err(|_| CoreError::EncryptFailed)?;
        let gcm = Aes128Gcm::new((&key).into());
        Ok(Self { key, gcm })
    }

    /// The bound key (e.g. to derive/compare a session key).
    #[must_use]
    pub fn key(&self) -> &[u8; 16] {
        &self.key
    }

    // -- AES-128-ECB (v3.1 / v3.3) -------------------------------------------

    /// Encrypts with AES-128-ECB and PKCS7 padding.
    pub fn ecb_encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let pad = BLOCK - (plaintext.len() % BLOCK);
        let mut buf = Vec::with_capacity(plaintext.len() + pad);
        buf.extend_from_slice(plaintext);
        buf.resize(plaintext.len() + pad, pad as u8);

        let mut enc = Encryptor::<Aes128>::new((&self.key).into());
        for chunk in buf.chunks_mut(BLOCK) {
            let block = <&mut Block<Aes128>>::try_from(chunk).map_err(|_| CoreError::EncryptFailed)?;
            enc.encrypt_block(block);
        }
        Ok(buf)
    }

    /// Decrypts AES-128-ECB and strips (validating) PKCS7 padding.
    pub fn ecb_decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(BLOCK) {
            return Err(CoreError::DecryptFailed);
        }
        let mut buf = ciphertext.to_vec();
        let mut dec = Decryptor::<Aes128>::new((&self.key).into());
        for chunk in buf.chunks_mut(BLOCK) {
            let block = <&mut Block<Aes128>>::try_from(chunk).map_err(|_| CoreError::DecryptFailed)?;
            dec.decrypt_block(block);
        }
        strip_pkcs7(buf)
    }

    // -- AES-128-GCM (v3.4 / v3.5) -------------------------------------------

    /// Encrypts with AES-128-GCM. Returns `ciphertext || tag`; the caller
    /// prepends the IV on the wire. `aad` is the authenticated frame header.
    pub fn gcm_encrypt(&self, iv: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let nonce: &Nonce<U12> = iv.into();
        self.gcm
            .encrypt(nonce, Payload { msg: plaintext, aad })
            .map_err(|_| CoreError::EncryptFailed)
    }

    /// Decrypts and authenticates AES-128-GCM. `ct_and_tag` is
    /// `ciphertext || tag`; a bad tag (or wrong `aad`) is rejected — the core
    /// never surfaces unauthenticated ciphertext.
    pub fn gcm_decrypt(&self, iv: &[u8; 12], ct_and_tag: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let nonce: &Nonce<U12> = iv.into();
        self.gcm
            .decrypt(nonce, Payload { msg: ct_and_tag, aad })
            .map_err(|_| CoreError::DecryptFailed)
    }
}

/// Validates and removes PKCS7 padding in place.
fn strip_pkcs7(mut buf: Vec<u8>) -> Result<Vec<u8>> {
    let pad = *buf.last().ok_or(CoreError::DecryptFailed)? as usize;
    if pad == 0 || pad > BLOCK || pad > buf.len() {
        return Err(CoreError::DecryptFailed);
    }
    if buf[buf.len() - pad..].iter().any(|&b| b as usize != pad) {
        return Err(CoreError::DecryptFailed);
    }
    buf.truncate(buf.len() - pad);
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"0123456789abcdef";

    #[test]
    fn new_rejects_wrong_key_length() {
        assert!(TuyaCipher::new(b"short").is_err());
        assert!(TuyaCipher::new(KEY).is_ok());
    }

    #[test]
    fn ecb_round_trips_including_block_boundary() {
        let c = TuyaCipher::new(KEY).unwrap();
        for msg in [&b""[..], b"hi", b"exactly16bytes!!", b"a longer tuya dps payload"] {
            let ct = c.ecb_encrypt(msg).unwrap();
            assert_eq!(ct.len() % BLOCK, 0);
            assert_eq!(c.ecb_decrypt(&ct).unwrap(), msg);
        }
    }

    #[test]
    fn ecb_rejects_bad_length_and_padding() {
        let c = TuyaCipher::new(KEY).unwrap();
        assert!(c.ecb_decrypt(&[0u8; 15]).is_err()); // not a block multiple
        assert!(c.ecb_decrypt(&[]).is_err());
        // valid-length block that decrypts to invalid padding
        assert!(c.ecb_decrypt(&[0u8; 16]).is_err());
    }

    #[test]
    fn gcm_round_trips_and_authenticates_aad() {
        let c = TuyaCipher::new(KEY).unwrap();
        let iv = [7u8; 12];
        let ct = c.gcm_encrypt(&iv, b"payload", b"header").unwrap();
        assert_eq!(c.gcm_decrypt(&iv, &ct, b"header").unwrap(), b"payload");
        // wrong AAD => tag mismatch => rejected
        assert!(c.gcm_decrypt(&iv, &ct, b"WRONG").is_err());
    }

    #[test]
    fn gcm_rejects_tampered_tag() {
        let c = TuyaCipher::new(KEY).unwrap();
        let iv = [1u8; 12];
        let mut ct = c.gcm_encrypt(&iv, b"x", b"").unwrap();
        *ct.last_mut().unwrap() ^= 0xff;
        assert!(c.gcm_decrypt(&iv, &ct, b"").is_err());
    }
}
