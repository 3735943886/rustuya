//! Whole-message encode / decode: the top of the byte pipeline.
//!
//! Ties [`crate::payload`] (JSON ↔ body) to [`crate::frame`] (body ↔ wire),
//! picking the frame format and integrity from the version's
//! [`Profile`](crate::version::Profile), and handling the retcode.
//!
//! ```text
//! encode:  json --encode_payload--> body --frame::pack--> wire
//! decode:  wire --frame::unpack--> body --[strip retcode]--> --decode_payload--> json
//! ```
//!
//! The retcode is the first 4 bytes of the frame body / GCM plaintext, uniform
//! across formats (outside the ECB for 55AA, inside the GCM for 6699 — but
//! `frame::unpack` hands back the body either way). Clients never *send* a
//! retcode, so [`encode_message`] has none; [`decode_message`] strips it when
//! the caller says a response carries one (`SMELLS.md`, S1 — no byte-sniffing).

use alloc::vec::Vec;

use crate::crypto::TuyaCipher;
use crate::frame;
use crate::payload::{decode_payload, encode_payload};
use crate::version::{Frame as WireFrame, Integrity as WireIntegrity, Version};
use crate::Result;

/// A decoded message: identity, optional device return code, and the JSON bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub seqno: u32,
    pub cmd: u32,
    pub retcode: Option<u32>,
    /// Decoded (decrypted, de-headered) JSON payload bytes.
    pub payload: Vec<u8>,
}

/// Encodes a request (`json`) into wire bytes for `version`.
///
/// `key` is the cipher/HMAC key (local key for v3.1–v3.3, session key for
/// v3.4/v3.5). `iv` is the caller-injected 12-byte GCM nonce — used only for
/// v3.5, ignored otherwise, but always required so the core never generates it.
pub fn encode_message(
    version: Version,
    cmd: u32,
    seqno: u32,
    json: &[u8],
    key: &[u8],
    iv: &[u8; 12],
) -> Result<Vec<u8>> {
    let cipher = TuyaCipher::new(key)?;
    let body = encode_payload(version, cmd, json, &cipher)?;
    Ok(match version.profile().frame {
        WireFrame::F55AA(WireIntegrity::Crc32) => {
            frame::pack_55aa(seqno, cmd, &body, frame::Integrity::Crc32)
        }
        WireFrame::F55AA(WireIntegrity::Hmac) => {
            frame::pack_55aa(seqno, cmd, &body, frame::Integrity::Hmac(key))
        }
        WireFrame::F6699 => frame::pack_6699(seqno, cmd, &body, key, iv)?,
    })
}

/// Decodes wire bytes into a [`Message`] for `version`.
///
/// `has_retcode` states whether a 4-byte device return code prefixes the body
/// (true for device responses; the caller knows from context, cf. S1).
pub fn decode_message(
    version: Version,
    data: &[u8],
    key: &[u8],
    has_retcode: bool,
) -> Result<Message> {
    let cipher = TuyaCipher::new(key)?;
    let raw = match version.profile().frame {
        WireFrame::F55AA(WireIntegrity::Crc32) => frame::unpack_55aa(data, frame::Integrity::Crc32)?,
        WireFrame::F55AA(WireIntegrity::Hmac) => {
            frame::unpack_55aa(data, frame::Integrity::Hmac(key))?
        }
        WireFrame::F6699 => frame::unpack_6699(data, key)?,
    };

    let mut body = raw.body;
    let mut retcode = None;
    if has_retcode && body.len() >= 4 {
        retcode = Some(u32::from_be_bytes([body[0], body[1], body[2], body[3]]));
        body.drain(..4);
    }
    let payload = decode_payload(version, &body, &cipher)?;
    Ok(Message {
        seqno: raw.seqno,
        cmd: raw.cmd,
        retcode,
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::CommandType;

    const KEY: &[u8] = b"0123456789abcdef";
    const IV: [u8; 12] = [9u8; 12];
    const JSON: &[u8] = br#"{"dps":{"1":true}}"#;

    fn versions() -> [Version; 5] {
        [
            Version::V3_1,
            Version::V3_2,
            Version::V3_3,
            Version::V3_4,
            Version::V3_5,
        ]
    }

    #[test]
    fn request_roundtrips_every_version() {
        let cmd = CommandType::Control as u32;
        for v in versions() {
            let wire = encode_message(v, cmd, 3, JSON, KEY, &IV).unwrap();
            let msg = decode_message(v, &wire, KEY, false).unwrap();
            assert_eq!(msg.seqno, 3, "{v:?}");
            assert_eq!(msg.cmd, cmd, "{v:?}");
            assert_eq!(msg.retcode, None, "{v:?}");
            assert_eq!(msg.payload, JSON, "{v:?}");
        }
    }

    #[test]
    fn no_header_command_roundtrips() {
        let cmd = CommandType::DpQuery as u32;
        for v in versions() {
            let wire = encode_message(v, cmd, 1, JSON, KEY, &IV).unwrap();
            let msg = decode_message(v, &wire, KEY, false).unwrap();
            assert_eq!(msg.payload, JSON, "{v:?}");
        }
    }

    #[test]
    fn retcode_is_stripped_when_present() {
        // Simulate a device response: the body/plaintext is prefixed with a
        // 4-byte return code, ahead of the (headered) payload.
        let cipher = TuyaCipher::new(KEY).unwrap();
        let cmd = CommandType::Status as u32;
        let inner = encode_payload(Version::V3_5, cmd, JSON, &cipher).unwrap(); // header + json
        let mut plaintext = 0u32.to_be_bytes().to_vec(); // retcode 0
        plaintext.extend_from_slice(&inner);
        let wire = frame::pack_6699(7, cmd, &plaintext, KEY, &IV).unwrap();

        let msg = decode_message(Version::V3_5, &wire, KEY, true).unwrap();
        assert_eq!(msg.retcode, Some(0));
        assert_eq!(msg.payload, JSON);
    }

    #[test]
    fn wrong_key_fails_v34_hmac_and_v35_gcm() {
        let cmd = CommandType::Control as u32;
        for v in [Version::V3_4, Version::V3_5] {
            let wire = encode_message(v, cmd, 1, JSON, KEY, &IV).unwrap();
            assert!(decode_message(v, &wire, b"WRONGKEY00000000", false).is_err(), "{v:?}");
        }
    }
}
