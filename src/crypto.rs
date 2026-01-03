//! Cryptographic operations for the Tuya protocol.
//!
//! Handles AES-128-ECB (v3.1, v3.3) and AES-128-GCM (v3.4, v3.5) encryption and decryption.

use crate::error::{Result, TuyaError};
use aes::Aes128;
use aes_gcm::{
    Aes128Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use cipher::{BlockDecryptMut, BlockEncryptMut};
use ecb::{Decryptor, Encryptor};

pub struct TuyaCipher {
    key: [u8; 16],
    gcm: Aes128Gcm,
}

impl TuyaCipher {
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.len() != 16 {
            return Err(TuyaError::EncryptionFailed);
        }
        let mut k = [0u8; 16];
        k.copy_from_slice(key);
        let gcm = Aes128Gcm::new(&k.into());
        Ok(Self { key: k, gcm })
    }

    pub fn key(&self) -> &[u8; 16] {
        &self.key
    }

    pub fn encrypt(
        &self,
        data: &[u8],
        use_base64: bool,
        iv: Option<&[u8]>,
        header: Option<&[u8]>,
        padding: bool,
    ) -> Result<Vec<u8>> {
        let encrypted_bytes = if let Some(iv_bytes) = iv {
            let nonce = Nonce::from_slice(&iv_bytes[..12]);

            let payload = Payload {
                msg: data,
                aad: header.unwrap_or(&[]),
            };

            let mut ciphertext = self
                .gcm
                .encrypt(nonce, payload)
                .map_err(|_| TuyaError::EncryptionFailed)?;

            let mut result = Vec::with_capacity(iv_bytes.len() + ciphertext.len());
            result.extend_from_slice(iv_bytes);
            result.append(&mut ciphertext);
            result
        } else {
            let mut encryptor = Encryptor::<Aes128>::new(&self.key.into());

            let padded_data = if padding {
                let len = data.len();
                let remainder = len % 16;
                let padding_len = 16 - remainder;

                let mut p = data.to_vec();
                for _ in 0..padding_len {
                    p.push(padding_len as u8);
                }
                p
            } else {
                if !data.len().is_multiple_of(16) {
                    return Err(TuyaError::EncryptionFailed);
                }
                data.to_vec()
            };

            let mut ciphertext = padded_data.clone();
            for chunk in ciphertext.chunks_mut(16) {
                let block = cipher::generic_array::GenericArray::from_mut_slice(chunk);
                encryptor.encrypt_block_mut(block);
            }

            ciphertext
        };

        if use_base64 {
            use base64::{Engine as _, engine::general_purpose};
            let b64_str = general_purpose::STANDARD.encode(&encrypted_bytes);
            Ok(b64_str.into_bytes())
        } else {
            Ok(encrypted_bytes)
        }
    }

    pub fn decrypt(
        &self,
        data: &[u8],
        use_base64: bool,
        iv: Option<&[u8]>,
        header: Option<&[u8]>,
        _tag: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let input_data = if use_base64 {
            use base64::{Engine as _, engine::general_purpose};
            general_purpose::STANDARD
                .decode(data)
                .map_err(|_| TuyaError::DecryptionFailed)?
        } else {
            data.to_vec()
        };

        if let Some(iv_bytes) = iv {
            let nonce = Nonce::from_slice(&iv_bytes[..12]);

            let payload = Payload {
                msg: &input_data,
                aad: header.unwrap_or(&[]),
            };

            let plaintext = self
                .gcm
                .decrypt(nonce, payload)
                .map_err(|_| TuyaError::DecryptionFailed)?;

            Ok(plaintext)
        } else {
            let mut decryptor = Decryptor::<Aes128>::new(&self.key.into());
            let mut plaintext = input_data.clone();

            if plaintext.len() % 16 != 0 {
                return Err(TuyaError::DecryptionFailed);
            }

            for chunk in plaintext.chunks_mut(16) {
                let block = cipher::generic_array::GenericArray::from_mut_slice(chunk);
                decryptor.decrypt_block_mut(block);
            }

            if plaintext.is_empty() {
                return Ok(plaintext);
            }
            let pad_len = plaintext[plaintext.len() - 1] as usize;
            if pad_len == 0 || pad_len > 16 || pad_len > plaintext.len() {
                return Err(TuyaError::DecryptionFailed);
            }
            for i in 0..pad_len {
                if plaintext[plaintext.len() - 1 - i] != pad_len as u8 {
                    return Err(TuyaError::DecryptionFailed);
                }
            }
            plaintext.truncate(plaintext.len() - pad_len);
            Ok(plaintext)
        }
    }
}
