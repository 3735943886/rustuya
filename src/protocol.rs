//! Tuya wire protocol implementation.
//! Handles packet framing, header parsing, and CRC/HMAC verification.

use crate::crypto::TuyaCipher;
use crate::error::{Result, TuyaError};
use byteorder::{BigEndian, ByteOrder, ReadBytesExt, WriteBytesExt};
use crc::{CRC_32_ISO_HDLC, Crc};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::io::Cursor;

pub const PREFIX_55AA: u32 = 0x000055AA;
pub const PREFIX_6699: u32 = 0x00006699;
pub const SUFFIX_55AA: u32 = 0x0000AA55;
pub const SUFFIX_6699: u32 = 0x00009966;

define_command_type! {
    ApConfig = 0x01,
    Active = 0x02,
    SessKeyNegStart = 0x03,
    SessKeyNegResp = 0x04,
    SessKeyNegFinish = 0x05,
    Unbind = 0x06,
    Control = 0x07,
    Status = 0x08,
    HeartBeat = 0x09,
    DpQuery = 0x0a,
    QueryWifi = 0x0b,
    TokenBind = 0x0c,
    ControlNew = 0x0d,
    EnableWifi = 0x0e,
    WifiInfo = 0x0f,
    DpQueryNew = 0x10,
    SceneExecute = 0x11,
    UpdateDps = 0x12,
    UdpNew = 0x13,
    ApConfigNew = 0x14,
    LanGwActive = 0xfa,
    LanSubDevRequest = 0xfb,
    LanDeleteSubDev = 0xfc,
    LanReportSubDev = 0xfd,
    LanScene = 0xfe,
    LanPublishCloudConfig = 0xff,
    LanExportAppConfig = 0x22,
    LanPublishAppConfig = 0x23,
    ReqDevInfo = 0x25,
    LanExtStream = 0x40,
}

define_version! {
    V3_1 = ("3.1", 3.1),
    V3_3 = ("3.3", 3.3),
    V3_4 = ("3.4", 3.4),
    V3_5 = ("3.5", 3.5),
}

/// Tuya protocol message structure
#[derive(Debug, Clone)]
pub struct TuyaMessage {
    /// Sequence number
    pub seqno: u32,
    /// Command code
    pub cmd: u32,
    /// Return code (optional)
    pub retcode: Option<u32>,
    /// Actual payload (JSON or encrypted binary)
    pub payload: Vec<u8>,
    /// Protocol prefix (0x55AA or 0x6699)
    pub prefix: u32,
    /// IV (Initialization Vector, mainly for 6699 protocol)
    pub iv: Option<Vec<u8>>,
}

impl Default for TuyaMessage {
    fn default() -> Self {
        Self {
            seqno: 0,
            cmd: 0,
            retcode: None,
            payload: Vec::new(),
            prefix: PREFIX_55AA,
            iv: None,
        }
    }
}

/// Tuya protocol header structure
#[derive(Debug, Clone)]
pub struct TuyaHeader {
    /// Protocol prefix
    pub prefix: u32,
    /// Sequence number
    pub seqno: u32,
    /// Command code
    pub cmd: u32,
    /// Payload length (includes encrypted data + HMAC/CRC + Suffix)
    pub payload_len: u32,
    /// Total message length (header + payload)
    pub total_length: u32,
}

/// Pack TuyaMessage into binary data.
/// If hmac_key is provided, uses HMAC-SHA256; otherwise, uses CRC32.
pub fn pack_message(msg: &TuyaMessage, hmac_key: Option<&[u8]>) -> Result<Vec<u8>> {
    let mut data = Vec::new();

    if msg.prefix == PREFIX_55AA {
        // 55AA Header: Prefix(4), Seq(4), Cmd(4), Len(4)
        // Length = payload + (HMAC(32) + Suffix(4)) OR (CRC(4) + Suffix(4))
        let suffix_len = if hmac_key.is_some() { 32 + 4 } else { 4 + 4 };
        let payload_len = msg.payload.len() as u32 + suffix_len as u32;

        data.write_u32::<BigEndian>(msg.prefix)?;
        data.write_u32::<BigEndian>(msg.seqno)?;
        data.write_u32::<BigEndian>(msg.cmd)?;
        data.write_u32::<BigEndian>(payload_len)?;

        // Add payload
        data.extend_from_slice(&msg.payload);

        // Footer (checksum + Suffix)
        if let Some(key) = hmac_key {
            type HmacSha256 = Hmac<Sha256>;
            let mut mac =
                HmacSha256::new_from_slice(key).map_err(|_| TuyaError::EncryptionFailed)?;
            mac.update(&data);
            let result = mac.finalize().into_bytes();
            data.extend_from_slice(&result);
        } else {
            let crc32 = Crc::<u32>::new(&CRC_32_ISO_HDLC);
            let crc_val = crc32.checksum(&data);
            data.write_u32::<BigEndian>(crc_val)?;
        }
        data.write_u32::<BigEndian>(SUFFIX_55AA)?;
    } else if msg.prefix == PREFIX_6699 {
        let key = hmac_key.ok_or(TuyaError::EncryptionFailed)?;

        // 6699 Header: Prefix(4), Unknown(2), Seq(4), Cmd(4), Len(4)
        // Length = IV(12) + encrypted_data(Retcode+Payload) + Tag(16) + Suffix(4)

        let mut raw = Vec::new();
        if let Some(rc) = msg.retcode {
            raw.write_u32::<BigEndian>(rc)?;
        }
        raw.extend_from_slice(&msg.payload);

        let iv_len = 12;
        let tag_len = 16;
        let total_payload_len = iv_len + raw.len() + tag_len;

        let mut header_bytes = Vec::new();
        header_bytes.write_u32::<BigEndian>(PREFIX_6699)?;
        header_bytes.write_u16::<BigEndian>(0)?; // Unknown
        header_bytes.write_u32::<BigEndian>(msg.seqno)?;
        header_bytes.write_u32::<BigEndian>(msg.cmd)?;
        header_bytes.write_u32::<BigEndian>(total_payload_len as u32)?;

        // Determine IV (create new if not provided)
        let iv_vec = if let Some(ref iv) = msg.iv {
            iv.clone()
        } else {
            let mut iv = vec![0u8; 12];
            rand::RngCore::fill_bytes(&mut rand::rng(), &mut iv);
            iv
        };

        // GCM Encryption (AAD = Header[4..])
        let cipher = TuyaCipher::new(key)?;
        let encrypted =
            cipher.encrypt(&raw, false, Some(&iv_vec), Some(&header_bytes[4..]), false)?;

        data.extend_from_slice(&header_bytes);
        data.extend_from_slice(&encrypted); // encrypt() returns IV + Ciphertext + Tag
        data.write_u32::<BigEndian>(SUFFIX_6699)?;
    }

    Ok(data)
}

/// Parse Tuya header from binary data.
pub fn parse_header(data: &[u8]) -> Result<TuyaHeader> {
    if data.len() < 16 {
        return Err(TuyaError::DecodeError("Header too short".into()));
    }

    let mut cursor = Cursor::new(data);
    let prefix = cursor.read_u32::<BigEndian>()?;

    match prefix {
        PREFIX_55AA => {
            // 55AA: Prefix(4), Seq(4), Cmd(4), Len(4)
            let seqno = cursor.read_u32::<BigEndian>()?;
            let cmd = cursor.read_u32::<BigEndian>()?;
            let payload_len = cursor.read_u32::<BigEndian>()?;
            let total_length = payload_len + 16;
            Ok(TuyaHeader {
                prefix,
                seqno,
                cmd,
                payload_len,
                total_length,
            })
        }
        PREFIX_6699 => {
            // 6699: Prefix(4), Unknown(2), Seq(4), Cmd(4), Len(4)
            if data.len() < 18 {
                return Err(TuyaError::DecodeError("6699 header too short".into()));
            }
            let _unknown = cursor.read_u16::<BigEndian>()?;
            let seqno = cursor.read_u32::<BigEndian>()?;
            let cmd = cursor.read_u32::<BigEndian>()?;
            let payload_len = cursor.read_u32::<BigEndian>()?;
            let total_length = payload_len + 18 + 4; // Header(18) + Payload(Length) + Suffix(4)
            Ok(TuyaHeader {
                prefix,
                seqno,
                cmd,
                payload_len,
                total_length,
            })
        }
        _ => Err(TuyaError::InvalidHeader),
    }
}

/// Unpack binary data into TuyaMessage structure.
pub fn unpack_message(
    data: &[u8],
    hmac_key: Option<&[u8]>,
    header: Option<TuyaHeader>,
    no_retcode: Option<bool>,
) -> Result<TuyaMessage> {
    let header = match header {
        Some(h) => h,
        None => parse_header(data)?,
    };

    if data.len() < header.total_length as usize {
        return Err(TuyaError::DecodeError("Data shorter than expected".into()));
    }

    if header.prefix == PREFIX_55AA {
        let header_len = 16;
        let end_len = if hmac_key.is_some() { 32 + 4 } else { 4 + 4 };
        let msg_len = header.total_length as usize;
        let payload_end = msg_len - end_len;

        if payload_end < header_len {
            return Err(TuyaError::DecodeError(format!(
                "Payload end ({}) is before header end ({})",
                payload_end, header_len
            )));
        }

        let mut payload_start = header_len;
        let mut retcode = None;

        // Determine whether to parse retcode
        let should_parse_retcode = match no_retcode {
            Some(no) => !no,
            None => {
                // Auto-detect: not JSON format and has space for 4 bytes
                payload_end - payload_start >= 4
                    && data[payload_start] != b'{'
                    && (data[payload_start] == 0
                        || (payload_end - payload_start > 4 && data[payload_start] != b'3'))
            }
        };

        if should_parse_retcode && payload_end - payload_start >= 4 {
            retcode = Some(BigEndian::read_u32(&data[payload_start..payload_start + 4]));
            payload_start += 4;
        }

        let payload = data[payload_start..payload_end].to_vec();

        // Verify checksum (CRC/HMAC)
        let checksum_data = &data[..payload_end];
        let footer = &data[payload_end..msg_len];

        if let Some(key) = hmac_key {
            type HmacSha256 = Hmac<Sha256>;
            let mut mac =
                HmacSha256::new_from_slice(key).map_err(|_| TuyaError::EncryptionFailed)?;
            mac.update(checksum_data);
            let result = mac.finalize().into_bytes();
            if result.as_slice() != &footer[..32] {
                return Err(TuyaError::HmacMismatch);
            }
        } else {
            let crc32 = Crc::<u32>::new(&CRC_32_ISO_HDLC);
            let calc_crc = crc32.checksum(checksum_data);
            let recv_crc = BigEndian::read_u32(&footer[..4]);
            if calc_crc != recv_crc {
                return Err(TuyaError::CrcMismatch);
            }
        }

        Ok(TuyaMessage {
            seqno: header.seqno,
            cmd: header.cmd,
            retcode,
            payload,
            prefix: header.prefix,
            iv: None,
        })
    } else if header.prefix == PREFIX_6699 {
        let key = hmac_key.ok_or(TuyaError::EncryptionFailed)?;
        let header_len = 18;
        let suffix_len = 4;
        let tag_len = 16;
        let iv_len = 12;

        let msg_len = header.total_length as usize;
        let payload_with_iv_tag = &data[header_len..msg_len - suffix_len];

        if payload_with_iv_tag.len() < iv_len + tag_len {
            return Err(TuyaError::InvalidPayload);
        }

        let iv = &payload_with_iv_tag[..iv_len];
        let ciphertext_with_tag = &payload_with_iv_tag[iv_len..];

        // GCM Decryption (AAD = Header[4..])
        let cipher = TuyaCipher::new(key)?;
        let header_bytes = &data[4..header_len];
        let decrypted = cipher.decrypt(
            ciphertext_with_tag,
            false,
            Some(iv),
            Some(header_bytes),
            None,
        )?;

        let mut payload = decrypted;
        let mut retcode = None;
        let retcode_len = 4;

        // Determine whether to parse retcode (6699 protocol)
        let should_parse_retcode = match no_retcode {
            Some(no) => !no,
            None => {
                // Auto-detect: if payload starts with 0 or non-'{', and followed by '{' or '3' (version header)
                payload.len() >= retcode_len
                    && payload[0] != b'{'
                    && (payload.len() > retcode_len
                        && (payload[retcode_len] == b'{' || payload[retcode_len] == b'3'))
            }
        };

        if should_parse_retcode && payload.len() >= retcode_len {
            retcode = Some(BigEndian::read_u32(&payload[..retcode_len]));
            payload = payload[retcode_len..].to_vec();
        }

        Ok(TuyaMessage {
            seqno: header.seqno,
            cmd: header.cmd,
            retcode,
            payload,
            prefix: header.prefix,
            iv: Some(iv.to_vec()),
        })
    } else {
        Err(TuyaError::InvalidHeader)
    }
}
