//! Wire framing for the Tuya local protocol — the two on-wire frame formats.
//!
//! * **55AA** (`0x0000_55AA … 0x0000_AA55`) — v3.1 / v3.3 (CRC-32) and v3.4
//!   (HMAC-SHA256). The body is framed as-is: payload encryption (ECB / base64)
//!   is the protocol layer's job, done before packing / after unpacking.
//! * **6699** (`0x0000_6699 … 0x0000_9966`) — v3.5. AES-GCM with the frame
//!   header as AAD, so (de)encryption is necessarily done here. The IV is
//!   **caller-supplied** — the core never generates randomness.
//!
//! Deliberately narrow: this module knows nothing about retcodes, dps, or
//! protocol versions. It turns `(seqno, cmd, body)` into bytes and back, with
//! integrity or authenticated encryption. Splitting a retcode out of `body` and
//! deciding *whether* one is present is the protocol layer's job — the 0.3 core
//! guessed it by sniffing payload bytes, which this design removes (see
//! `SMELLS.md`, S1).

use alloc::vec::Vec;
use cipher::KeyInit;
use crc::{CRC_32_ISO_HDLC, Crc};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::crypto::TuyaCipher;
use crate::{CoreError, Result};

pub const PREFIX_55AA: u32 = 0x0000_55AA;
pub const SUFFIX_55AA: u32 = 0x0000_AA55;
pub const PREFIX_6699: u32 = 0x0000_6699;
pub const SUFFIX_6699: u32 = 0x0000_9966;

/// Upper bound on a header-declared length, checked before any allocation.
pub const MAX_PAYLOAD_LEN: u32 = 256 * 1024;

// Built once, `const` — the 0.3 core reconstructed this on every pack/unpack.
const CRC32: Crc<u32> = Crc::<u32>::new(&CRC_32_ISO_HDLC);
type HmacSha256 = Hmac<Sha256>;

const H55AA: usize = 16; // prefix + seqno + cmd + len
const H6699: usize = 18; // prefix + reserved + seqno + cmd + len
const SUFFIX: usize = 4;

/// A decoded frame: identity plus the raw body.
///
/// `body` is the region between the length field and the footer for **55AA**
/// (still ECB-encrypted for v3.4; base64/plain for v3.1/3.3), or the GCM
/// **plaintext** for **6699**. Retcode / dps interpretation is the protocol
/// layer's job; a leading retcode, if any, is still in `body`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawFrame {
    pub seqno: u32,
    pub cmd: u32,
    pub body: Vec<u8>,
}

/// Integrity mode for a 55AA frame.
pub enum Integrity<'a> {
    /// CRC-32 (v3.1 / v3.3).
    Crc32,
    /// HMAC-SHA256 keyed by the session/local key (v3.4).
    Hmac(&'a [u8]),
}

impl Integrity<'_> {
    fn footer_len(&self) -> usize {
        match self {
            Integrity::Crc32 => 4,
            Integrity::Hmac(_) => 32,
        }
    }
}

/// The fixed header prefix plus the total frame length — enough to drive TCP
/// reassembly. Returns `Ok(None)` when `data` does not yet hold a full header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub prefix: u32,
    pub seqno: u32,
    pub cmd: u32,
    /// Total bytes of the complete frame (prefix .. suffix inclusive).
    pub frame_len: usize,
}

/// Reads just enough of `data` to identify the frame and its total length.
///
/// `Ok(None)` means "need more bytes" (the header isn't fully present yet) — the
/// driver keeps reading. `Err` means a malformed/oversized/unknown header.
pub fn peek_header(data: &[u8]) -> Result<Option<Header>> {
    if data.len() < 4 {
        return Ok(None);
    }
    let prefix = rd_u32(data, 0)?;
    let (hdr, len) = match prefix {
        PREFIX_55AA => {
            if data.len() < H55AA {
                return Ok(None);
            }
            (H55AA, rd_u32(data, 12)?)
        }
        PREFIX_6699 => {
            if data.len() < H6699 {
                return Ok(None);
            }
            (H6699, rd_u32(data, 14)?)
        }
        _ => return Err(CoreError::BadHeader),
    };
    if len > MAX_PAYLOAD_LEN {
        return Err(CoreError::TooLong);
    }
    // 55AA: `len` counts body+footer+suffix after the 16-byte header.
    // 6699: `len` counts iv+ct+tag after the 18-byte header, then +suffix.
    let frame_len = match prefix {
        PREFIX_55AA => hdr + len as usize,
        _ => hdr + len as usize + SUFFIX,
    };
    let (seqno, cmd) = if prefix == PREFIX_55AA {
        (rd_u32(data, 4)?, rd_u32(data, 8)?)
    } else {
        (rd_u32(data, 6)?, rd_u32(data, 10)?)
    };
    Ok(Some(Header {
        prefix,
        seqno,
        cmd,
        frame_len,
    }))
}

// -- 55AA -------------------------------------------------------------------

/// Frames a 55AA message. `body` is emitted verbatim between the length field
/// and the footer (the protocol layer supplies it pre-encrypted for v3.4).
#[must_use]
pub fn pack_55aa(seqno: u32, cmd: u32, body: &[u8], integrity: Integrity<'_>) -> Vec<u8> {
    let len = body.len() + integrity.footer_len() + SUFFIX;
    let mut out = Vec::with_capacity(H55AA + len);
    out.extend_from_slice(&PREFIX_55AA.to_be_bytes());
    out.extend_from_slice(&seqno.to_be_bytes());
    out.extend_from_slice(&cmd.to_be_bytes());
    out.extend_from_slice(&(len as u32).to_be_bytes());
    out.extend_from_slice(body);
    match integrity {
        Integrity::Crc32 => {
            let crc = CRC32.checksum(&out).to_be_bytes();
            out.extend_from_slice(&crc);
        }
        Integrity::Hmac(key) => {
            let mut mac = HmacSha256::new_from_slice(key).expect("HMAC takes any key length");
            mac.update(&out);
            out.extend_from_slice(&mac.finalize().into_bytes());
        }
    }
    out.extend_from_slice(&SUFFIX_55AA.to_be_bytes());
    out
}

/// Parses and verifies a 55AA frame, returning the raw body.
pub fn unpack_55aa(data: &[u8], integrity: Integrity<'_>) -> Result<RawFrame> {
    let header = full_header(data, PREFIX_55AA)?;
    let footer_len = integrity.footer_len();
    let payload_end = header
        .frame_len
        .checked_sub(footer_len + SUFFIX)
        .filter(|&e| e >= H55AA)
        .ok_or(CoreError::Truncated)?;

    let signed = &data[..payload_end];
    let footer = &data[payload_end..payload_end + footer_len];
    match integrity {
        Integrity::Crc32 => {
            if footer != CRC32.checksum(signed).to_be_bytes() {
                return Err(CoreError::CrcMismatch);
            }
        }
        Integrity::Hmac(key) => {
            let mut mac = HmacSha256::new_from_slice(key).expect("HMAC takes any key length");
            mac.update(signed);
            mac.verify_slice(footer)
                .map_err(|_| CoreError::HmacMismatch)?;
        }
    }
    Ok(RawFrame {
        seqno: header.seqno,
        cmd: header.cmd,
        body: data[H55AA..payload_end].to_vec(),
    })
}

// -- 6699 -------------------------------------------------------------------

/// Frames a 6699 (v3.5) message: AES-GCM with the header as AAD. `plaintext`
/// (retcode, if any, already prepended by the caller) is encrypted; `iv` is
/// injected by the caller — never generated here.
pub fn pack_6699(
    seqno: u32,
    cmd: u32,
    plaintext: &[u8],
    key: &[u8],
    iv: &[u8; 12],
) -> Result<Vec<u8>> {
    let total = 12 + plaintext.len() + 16; // iv + ciphertext + tag
    let mut header = Vec::with_capacity(H6699);
    header.extend_from_slice(&PREFIX_6699.to_be_bytes());
    header.extend_from_slice(&0u16.to_be_bytes()); // reserved
    header.extend_from_slice(&seqno.to_be_bytes());
    header.extend_from_slice(&cmd.to_be_bytes());
    header.extend_from_slice(&(total as u32).to_be_bytes());

    let cipher = TuyaCipher::new(key)?;
    let ct = cipher.gcm_encrypt(iv, plaintext, &header[4..])?; // AAD = header sans prefix

    let mut out = Vec::with_capacity(H6699 + total + SUFFIX);
    out.extend_from_slice(&header);
    out.extend_from_slice(iv);
    out.extend_from_slice(&ct);
    out.extend_from_slice(&SUFFIX_6699.to_be_bytes());
    Ok(out)
}

/// Parses, decrypts, and authenticates a 6699 frame, returning the GCM
/// plaintext as the body. A bad tag is rejected — no unauthenticated bytes
/// ever leave the core.
pub fn unpack_6699(data: &[u8], key: &[u8]) -> Result<RawFrame> {
    let header = full_header(data, PREFIX_6699)?;
    let region = &data[H6699..header.frame_len - SUFFIX]; // iv + ciphertext + tag
    if region.len() < 12 + 16 {
        return Err(CoreError::InvalidPayload);
    }
    let iv: &[u8; 12] = region[..12].try_into().expect("checked len >= 12");
    let ct_and_tag = &region[12..];
    let aad = &data[4..H6699];

    let cipher = TuyaCipher::new(key)?;
    let plaintext = cipher.gcm_decrypt(iv, ct_and_tag, aad)?;
    Ok(RawFrame {
        seqno: header.seqno,
        cmd: header.cmd,
        body: plaintext,
    })
}

// -- helpers ----------------------------------------------------------------

/// Peeks the header, then requires it to match `want` and the buffer to hold the
/// whole frame.
fn full_header(data: &[u8], want: u32) -> Result<Header> {
    let header = peek_header(data)?.ok_or(CoreError::Truncated)?;
    if header.prefix != want {
        return Err(CoreError::BadHeader);
    }
    if data.len() < header.frame_len {
        return Err(CoreError::Truncated);
    }
    Ok(header)
}

fn rd_u32(data: &[u8], off: usize) -> Result<u32> {
    data.get(off..off + 4)
        .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or(CoreError::Truncated)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"0123456789abcdef";

    #[test]
    fn roundtrip_55aa_crc() {
        let bytes = pack_55aa(5, 0x0a, b"hello", Integrity::Crc32);
        let f = unpack_55aa(&bytes, Integrity::Crc32).unwrap();
        assert_eq!(
            f,
            RawFrame {
                seqno: 5,
                cmd: 0x0a,
                body: b"hello".to_vec()
            }
        );
        // peek agrees on the total length
        assert_eq!(peek_header(&bytes).unwrap().unwrap().frame_len, bytes.len());
    }

    #[test]
    fn roundtrip_55aa_hmac() {
        let bytes = pack_55aa(9, 0x0d, b"body-bytes", Integrity::Hmac(KEY));
        let f = unpack_55aa(&bytes, Integrity::Hmac(KEY)).unwrap();
        assert_eq!(f.body, b"body-bytes");
        assert_eq!(peek_header(&bytes).unwrap().unwrap().frame_len, bytes.len());
    }

    #[test]
    fn crc_and_hmac_tamper_rejected() {
        let mut c = pack_55aa(1, 1, b"xyz", Integrity::Crc32);
        let n = c.len();
        c[n - 6] ^= 0xff; // flip a payload byte
        assert_eq!(
            unpack_55aa(&c, Integrity::Crc32),
            Err(CoreError::CrcMismatch)
        );

        let mut h = pack_55aa(1, 1, b"xyz", Integrity::Hmac(KEY));
        let n = h.len();
        h[n - 6] ^= 0xff;
        assert_eq!(
            unpack_55aa(&h, Integrity::Hmac(KEY)),
            Err(CoreError::HmacMismatch)
        );
    }

    #[test]
    fn roundtrip_6699_gcm() {
        let iv = [3u8; 12];
        let bytes = pack_6699(42, 0x10, b"the plaintext", KEY, &iv).unwrap();
        let f = unpack_6699(&bytes, KEY).unwrap();
        assert_eq!(
            f,
            RawFrame {
                seqno: 42,
                cmd: 0x10,
                body: b"the plaintext".to_vec()
            }
        );
        assert_eq!(peek_header(&bytes).unwrap().unwrap().frame_len, bytes.len());
    }

    #[test]
    fn gcm_tag_or_header_tamper_rejected() {
        let iv = [1u8; 12];
        let mut bytes = pack_6699(7, 2, b"secret", KEY, &iv).unwrap();
        let n = bytes.len();
        bytes[n - 5] ^= 0xff; // flip a tag byte
        assert_eq!(unpack_6699(&bytes, KEY), Err(CoreError::DecryptFailed));

        // tampering the AAD (cmd in the header) is also caught by GCM
        let mut b2 = pack_6699(7, 2, b"secret", KEY, &iv).unwrap();
        b2[10] ^= 0xff;
        assert_eq!(unpack_6699(&b2, KEY), Err(CoreError::DecryptFailed));
    }

    #[test]
    fn peek_needs_more_bytes() {
        let bytes = pack_55aa(1, 1, b"data", Integrity::Crc32);
        assert_eq!(peek_header(&[]).unwrap(), None);
        assert_eq!(peek_header(&bytes[..3]).unwrap(), None); // < 4
        assert_eq!(peek_header(&bytes[..10]).unwrap(), None); // < 16
        // full header present but body not yet complete
        let hdr = peek_header(&bytes[..H55AA]).unwrap().unwrap();
        assert_eq!(hdr.frame_len, bytes.len());
        // a short buffer fails the whole-frame check
        assert_eq!(
            unpack_55aa(&bytes[..bytes.len() - 1], Integrity::Crc32),
            Err(CoreError::Truncated)
        );
    }

    #[test]
    fn bad_prefix_and_oversized_rejected() {
        assert_eq!(
            peek_header(&[0, 0, 0, 0, 0, 0, 0, 0]),
            Err(CoreError::BadHeader)
        );
        // 55AA header claiming a huge length
        let mut oversized = Vec::new();
        oversized.extend_from_slice(&PREFIX_55AA.to_be_bytes());
        oversized.extend_from_slice(&0u32.to_be_bytes());
        oversized.extend_from_slice(&0u32.to_be_bytes());
        oversized.extend_from_slice(&(MAX_PAYLOAD_LEN + 1).to_be_bytes());
        assert_eq!(peek_header(&oversized), Err(CoreError::TooLong));
    }
}
