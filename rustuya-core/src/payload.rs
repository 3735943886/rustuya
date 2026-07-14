//! Per-version payload codec: JSON plaintext ↔ frame body.
//!
//! Sits between [`crate::command`] (JSON) and [`crate::frame`] (wire), handling
//! the version-specific wrapping the [`Profile`](crate::version::Profile)
//! describes: AES-ECB, the 15-byte version header (inside vs outside the
//! ciphertext), and v3.1's md5/base64 scheme.
//!
//! It does **not** deal with the retcode. The 0.3 core sniffed payload bytes to
//! guess whether a 4-byte return code was present (`docs/DESIGN.md`, S1); in practice
//! the actor always passed "retcode present", so the heuristic was dead code.
//! Here retcode splitting is the message layer's explicit, caller-known concern.

use alloc::string::String;
use alloc::vec::Vec;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use md5::{Digest, Md5};

use crate::command::CommandType;
use crate::crypto::TuyaCipher;
use crate::version::{HeaderPos, PayloadEnc, Version};
use crate::{CoreError, Result};

const HEADER_LEN: usize = 15;

/// Commands whose payload carries no 15-byte version header.
const NO_HEADER_CMDS: &[u32] = &[
    CommandType::DpQuery as u32,
    CommandType::DpQueryNew as u32,
    CommandType::UpdateDps as u32,
    CommandType::HeartBeat as u32,
    CommandType::SessKeyNegStart as u32,
    CommandType::SessKeyNegResp as u32,
    CommandType::SessKeyNegFinish as u32,
    CommandType::LanExtStream as u32,
];

/// Wraps a JSON plaintext into the frame body for `version` / `cmd`.
///
/// For v3.5 the result is *unencrypted* (the 6699 frame's GCM encrypts it);
/// for all other versions the body is ECB-encrypted (v3.1 additionally
/// base64/md5-wraps `Control`).
pub fn encode_payload(
    version: Version,
    cmd: u32,
    plaintext: &[u8],
    cipher: &TuyaCipher,
) -> Result<Vec<u8>> {
    if version == Version::V3_1 {
        return encode_v31(cmd, plaintext, cipher);
    }
    let profile = version.profile();
    let header = wants_header(cmd);
    Ok(match (profile.header, profile.payload_enc) {
        // v3.2 / v3.3: encrypt, then prepend the header (outside the ciphertext).
        (HeaderPos::AfterEncrypt, PayloadEnc::Ecb) => {
            let ct = cipher.ecb_encrypt(plaintext)?;
            if header {
                prepend(&version.header(), &ct)
            } else {
                ct
            }
        }
        // v3.4: prepend the header (inside the ciphertext), then encrypt.
        (HeaderPos::BeforeEncrypt, PayloadEnc::Ecb) => {
            let data = if header {
                prepend(&version.header(), plaintext)
            } else {
                plaintext.to_vec()
            };
            cipher.ecb_encrypt(&data)?
        }
        // v3.5: prepend the header, no separate encryption (frame GCM handles it).
        (HeaderPos::BeforeEncrypt, PayloadEnc::InFrameGcm) => {
            if header {
                prepend(&version.header(), plaintext)
            } else {
                plaintext.to_vec()
            }
        }
        _ => plaintext.to_vec(),
    })
}

/// Unwraps a frame body back to the JSON plaintext for `version`.
///
/// For v3.5 `body` is already GCM-decrypted by the frame; for others it is
/// ECB-decrypted here. Any leading version header is stripped.
pub fn decode_payload(version: Version, body: &[u8], cipher: &TuyaCipher) -> Result<Vec<u8>> {
    Ok(match version {
        Version::V3_1 => decode_v31(body, cipher)?,
        // header sits inside the (GCM/ECB) ciphertext → strip after decrypt.
        Version::V3_5 => strip_header(body.to_vec(), version),
        Version::V3_4 => {
            let decrypted = cipher.ecb_decrypt(body).unwrap_or_else(|_| body.to_vec());
            strip_header(decrypted, version)
        }
        // v3.2 / v3.3 / Auto: header sits outside the ciphertext → strip before
        // decrypt (and defensively again after).
        _ => {
            let mut p = body.to_vec();
            if has_version_header(&p, version) {
                p.drain(..HEADER_LEN);
            }
            if !p.is_empty()
                && let Ok(decrypted) = cipher.ecb_decrypt(&p)
            {
                return Ok(strip_header(decrypted, version));
            }
            p
        }
    })
}

// -- v3.1 md5/base64 scheme -------------------------------------------------

fn encode_v31(cmd: u32, plaintext: &[u8], cipher: &TuyaCipher) -> Result<Vec<u8>> {
    if cmd != CommandType::Control as u32 && cmd != CommandType::ControlNew as u32 {
        return Ok(plaintext.to_vec()); // v3.1 sends most commands in the clear
    }
    let ct = cipher.ecb_encrypt(plaintext)?;
    let b64 = BASE64.encode(&ct);
    let b64 = b64.as_bytes();

    // md5("data=" + b64 + "||lpv=3.1||" + key), hex[8..24].
    let mut h = Md5::new();
    h.update(b"data=");
    h.update(b64);
    h.update(b"||lpv=3.1||");
    h.update(cipher.key());
    let hex = hex_lower(&h.finalize());
    let sig = &hex.as_bytes()[8..24];

    let mut out = Vec::with_capacity(3 + 16 + b64.len());
    out.extend_from_slice(b"3.1");
    out.extend_from_slice(sig);
    out.extend_from_slice(b64);
    Ok(out)
}

fn decode_v31(body: &[u8], cipher: &TuyaCipher) -> Result<Vec<u8>> {
    if body.starts_with(b"3.1") && body.len() > 19 {
        let ct = BASE64
            .decode(&body[19..]) // strip "3.1" (3) + md5 sig (16)
            .map_err(|_| CoreError::DecryptFailed)?;
        cipher.ecb_decrypt(&ct)
    } else {
        Ok(body.to_vec())
    }
}

// -- helpers ----------------------------------------------------------------

fn wants_header(cmd: u32) -> bool {
    !NO_HEADER_CMDS.contains(&cmd)
}

fn has_version_header(body: &[u8], version: Version) -> bool {
    let h = version.header();
    body.len() >= HEADER_LEN && body[..3] == h[..3]
}

fn strip_header(mut body: Vec<u8>, version: Version) -> Vec<u8> {
    if has_version_header(&body, version) {
        body.drain(..HEADER_LEN);
    }
    body
}

fn prepend(head: &[u8], tail: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(head.len() + tail.len());
    v.extend_from_slice(head);
    v.extend_from_slice(tail);
    v
}

fn hex_lower(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(TABLE[(b >> 4) as usize] as char);
        s.push(TABLE[(b & 0x0f) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"0123456789abcdef";
    const HDR_CMD: u32 = CommandType::Control as u32; // wants a version header
    const NO_HDR_CMD: u32 = CommandType::DpQuery as u32; // omits it

    fn roundtrip(version: Version, cmd: u32) {
        let cipher = TuyaCipher::new(KEY).unwrap();
        let plain = br#"{"dps":{"1":true,"20":"white"}}"#;
        let body = encode_payload(version, cmd, plain, &cipher).unwrap();
        let back = decode_payload(version, &body, &cipher).unwrap();
        assert_eq!(back, plain, "{version:?} cmd={cmd:#x}");
    }

    #[test]
    fn roundtrips_every_version_with_and_without_header() {
        for v in [
            Version::V3_1,
            Version::V3_2,
            Version::V3_3,
            Version::V3_4,
            Version::V3_5,
        ] {
            roundtrip(v, HDR_CMD);
            roundtrip(v, NO_HDR_CMD);
        }
    }

    #[test]
    fn v33_prepends_header_outside_ciphertext_for_header_cmds() {
        let cipher = TuyaCipher::new(KEY).unwrap();
        let body = encode_payload(Version::V3_3, HDR_CMD, b"hello", &cipher).unwrap();
        assert_eq!(&body[..3], b"3.3");
        // no-header command: no prefix, body is exactly the ciphertext
        let body = encode_payload(Version::V3_3, NO_HDR_CMD, b"hello", &cipher).unwrap();
        assert_ne!(&body[..3], b"3.3");
    }

    #[test]
    fn v35_is_unencrypted_and_header_inside() {
        let cipher = TuyaCipher::new(KEY).unwrap();
        let body = encode_payload(Version::V3_5, HDR_CMD, b"plaintext", &cipher).unwrap();
        assert_eq!(&body[..3], b"3.5");
        assert!(body.ends_with(b"plaintext")); // not encrypted at this layer
    }

    #[test]
    fn v31_control_is_md5_base64_wrapped_others_clear() {
        let cipher = TuyaCipher::new(KEY).unwrap();
        let ctrl = encode_payload(Version::V3_1, HDR_CMD, b"secret", &cipher).unwrap();
        assert_eq!(&ctrl[..3], b"3.1");
        let query = encode_payload(Version::V3_1, NO_HDR_CMD, b"plain", &cipher).unwrap();
        assert_eq!(query, b"plain"); // clear-text
    }
}
