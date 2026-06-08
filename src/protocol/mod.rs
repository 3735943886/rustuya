//! Tuya wire protocol implementation.
//!
//! Handles packet framing, header parsing, CRC calculation, and HMAC verification.

use crate::crypto::TuyaCipher;
use crate::error::{Result, TuyaError};
use crate::macros::{define_command_type, define_version};
use byteorder::{BigEndian, ByteOrder, ReadBytesExt, WriteBytesExt};
use cipher::KeyInit;
use crc::{CRC_32_ISO_HDLC, Crc};
use hmac::{Hmac, Mac};
use serde::Serialize;
use serde_json::{Map, Value};
use sha2::Sha256;
use std::io::Cursor;

pub const PREFIX_55AA: u32 = 0x000055AA;
pub const PREFIX_6699: u32 = 0x00006699;
pub const SUFFIX_55AA: u32 = 0x0000AA55;
pub const SUFFIX_6699: u32 = 0x00009966;

/// Upper bound on the wire-claimed payload length accepted by
/// [`parse_header`]. Real Tuya LAN payloads are small (status/control are
/// well under 1 KiB; bulk responses like sub-device lists or `LanExtStream`
/// can be larger), so 256 KiB clears every legitimate frame while bounding
/// the allocation a malformed or malicious 16-byte header can trigger in
/// `read_full_packet` (which otherwise resizes a buffer to the claimed
/// length before reading). Without this, a single header claiming a
/// near-`u32::MAX` length is a memory-amplification DoS.
pub const MAX_PAYLOAD_LEN: u32 = 256 * 1024;

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

pub const NO_PROTOCOL_HEADER_CMDS: &[u32] = &[
    CommandType::DpQuery as u32,
    CommandType::DpQueryNew as u32,
    CommandType::UpdateDps as u32,
    CommandType::HeartBeat as u32,
    CommandType::SessKeyNegStart as u32,
    CommandType::SessKeyNegResp as u32,
    CommandType::SessKeyNegFinish as u32,
    CommandType::LanExtStream as u32,
];

define_version! {
    V3_1 = ("3.1", 3.1),
    V3_2 = ("3.2", 3.2),
    V3_3 = ("3.3", 3.3),
    V3_4 = ("3.4", 3.4),
    V3_5 = ("3.5", 3.5),
}

#[must_use]
pub fn create_base_payload(
    device_id: &str,
    cid: Option<&str>,
    data: Option<Value>,
    t: Option<Value>,
) -> Map<String, Value> {
    let mut payload = Map::new();
    payload.insert("gwId".into(), device_id.into());
    payload.insert("devId".into(), cid.unwrap_or(device_id).into());
    payload.insert("uid".into(), device_id.into());
    if let Some(c) = cid {
        payload.insert("cid".into(), c.into());
    }
    if let Some(v) = t {
        payload.insert("t".into(), v);
    }
    if let Some(d) = data {
        payload.insert("dps".into(), d);
    }
    payload
}

// ---------------------------------------------------------------------------
// Shared payload-transformation helpers (M4.2)
//
// Common arms factored out of v3.1/v3.2/v3.3/v3.4/v3.5 `generate_payload`
// implementations. Per-version differences (e.g. v3.2's DpQuery default-dps
// injection, v3.1's DpQuery "keep all" stance) stay inline in the specific
// version's match arm.
// ---------------------------------------------------------------------------

/// `UpdateDps` payload shape — identical across all currently-supported
/// protocol versions: keep only `cid`, then insert `dpId` from `data` (or a
/// default list).
pub(crate) fn apply_update_dps(payload: &mut Map<String, Value>, data: Option<Value>) {
    payload.retain(|k, _| k == "cid");
    let d = data.unwrap_or_else(|| serde_json::json!([18, 19, 20]));
    payload.insert("dpId".into(), d);
}

/// `Status` / `HeartBeat` strip — same across all versions: device doesn't
/// echo `uid` or `t` on these.
pub(crate) fn strip_status_heartbeat(payload: &mut Map<String, Value>) {
    payload.remove("uid");
    payload.remove("t");
}

/// v3.4/v3.5 modern `Control` / `ControlNew` envelope:
/// `{ protocol: 5, t, data: { cid?, ctype?, dps? } }`
pub(crate) fn modern_control_envelope(
    t: u64,
    cid: Option<&str>,
    data: Option<Value>,
) -> Map<String, Value> {
    let mut payload = Map::new();
    payload.insert("protocol".into(), 5.into());
    payload.insert("t".into(), t.into());

    let mut data_obj = Map::new();
    if let Some(c) = cid {
        data_obj.insert("cid".into(), c.into());
        data_obj.insert("ctype".into(), 0.into());
    }
    if let Some(d) = data {
        data_obj.insert("dps".into(), d);
    }
    payload.insert("data".into(), Value::Object(data_obj));
    payload
}

/// `LanExtStream` envelope — `{ reqType, data: {...rest} }`. Hoists `reqType`
/// out of the caller-supplied `data` to the payload root and wraps the
/// remaining fields under `data`. This shape is version-independent: tinytuya
/// defines `LAN_EXT_STREAM` only once (no per-version override), so v3.1–v3.5
/// all emit the same structure (see `Device::sub_discover`, which is the real
/// caller).
pub(crate) fn lan_ext_stream_envelope(data: Option<Value>) -> Map<String, Value> {
    let mut payload = Map::new();
    if let Some(Value::Object(mut data_obj)) = data {
        if let Some(req_type) = data_obj.remove("reqType") {
            payload.insert("reqType".into(), req_type);
        }
        payload.insert("data".into(), Value::Object(data_obj));
    }
    payload
}

pub mod dev22;
pub mod v31;
pub mod v32;
pub mod v33;
pub mod v34;
pub mod v35;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DeviceType {
    #[default]
    Auto,
    Default,
    Device22,
}

/// Error returned when parsing a [`DeviceType`] from a string fails.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid device type: {0}")]
pub struct ParseDeviceTypeError(pub String);

impl std::str::FromStr for DeviceType {
    type Err = ParseDeviceTypeError;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "auto" | "" => Ok(DeviceType::Auto),
            "default" => Ok(DeviceType::Default),
            "device22" => Ok(DeviceType::Device22),
            _ => Err(ParseDeviceTypeError(s.to_string())),
        }
    }
}

impl DeviceType {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            DeviceType::Auto => "auto",
            DeviceType::Default => "default",
            DeviceType::Device22 => "device22",
        }
    }
}

impl<'a> std::convert::TryFrom<&'a str> for DeviceType {
    type Error = ParseDeviceTypeError;
    fn try_from(s: &'a str) -> std::result::Result<Self, Self::Error> {
        s.parse()
    }
}

impl std::convert::TryFrom<String> for DeviceType {
    type Error = ParseDeviceTypeError;
    fn try_from(s: String) -> std::result::Result<Self, Self::Error> {
        s.parse()
    }
}

impl std::fmt::Display for DeviceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

pub trait TuyaProtocol: Send + Sync {
    fn version(&self) -> Version;
    fn get_effective_command(&self, command: CommandType) -> u32;
    fn generate_payload(
        &self,
        device_id: &str,
        command: CommandType,
        data: Option<Value>,
        cid: Option<&str>,
        t: u64,
    ) -> Result<(u32, Value)>;
    fn pack_payload(&self, payload: &[u8], cmd: u32, cipher: &TuyaCipher) -> Result<Vec<u8>>;
    fn decrypt_payload(&self, payload: Vec<u8>, cipher: &TuyaCipher) -> Result<Vec<u8>>;
    fn has_version_header(&self, payload: &[u8]) -> bool;

    /// Returns whether this protocol version requires session key negotiation.
    fn requires_session_key(&self) -> bool;

    /// Encrypts the session key according to protocol version requirements.
    fn encrypt_session_key(
        &self,
        session_key: &[u8],
        cipher: &TuyaCipher,
        nonce: &[u8],
    ) -> Result<Vec<u8>>;

    /// Returns the message prefix (e.g., 0x55AA or 0x6699) for this protocol version.
    fn get_prefix(&self) -> u32;

    /// Returns the HMAC key to use for message packing/unpacking, if applicable.
    fn get_hmac_key<'a>(&self, cipher_key: &'a [u8]) -> Option<&'a [u8]>;

    /// Returns whether an empty payload is allowed for the given command.
    fn is_empty_payload_allowed(&self, cmd: u32) -> bool;

    /// Returns whether the protocol should attempt dev22 fallback on error.
    fn should_check_dev22_fallback(&self) -> bool;

    /// Step 1: Prepare local nonce for session key negotiation.
    fn prepare_session_key_negotiation(&self) -> Vec<u8> {
        use rand::Rng;
        let mut local_nonce = vec![0u8; 16];
        rand::rng().fill_bytes(&mut local_nonce);
        local_nonce
    }

    /// Step 2: Verify the HMAC from device response during negotiation.
    fn verify_session_key_response(
        &self,
        local_nonce: &[u8],
        remote_payload: &[u8],
        local_key: &[u8],
    ) -> Result<Vec<u8>> {
        if remote_payload.len() < 48 {
            return Err(TuyaError::KeyOrVersionError);
        }
        let remote_nonce = &remote_payload[..16];
        let remote_hmac = &remote_payload[16..48];

        let mut mac =
            Hmac::<Sha256>::new_from_slice(local_key).map_err(|_| TuyaError::EncryptionFailed)?;
        mac.update(local_nonce);
        mac.verify_slice(remote_hmac)
            .map_err(|_| TuyaError::EncryptionFailed)?;

        Ok(remote_nonce.to_vec())
    }

    /// Step 3: Calculate final session key and its HMAC for the finish message.
    fn finalize_session_key(
        &self,
        local_nonce: &[u8],
        remote_nonce: &[u8],
        local_key: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(local_key).map_err(|_| TuyaError::EncryptionFailed)?;
        mac.update(remote_nonce);
        let finish_hmac = mac.finalize().into_bytes().to_vec();

        let session_key: Vec<u8> = local_nonce
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ remote_nonce[i % remote_nonce.len()])
            .collect();

        Ok((session_key, finish_hmac))
    }
}

#[must_use]
pub fn get_protocol(version: Version, dev_type: DeviceType) -> Box<dyn TuyaProtocol> {
    let base: Box<dyn TuyaProtocol> = match version {
        Version::V3_1 => Box::new(v31::ProtocolV31),
        Version::V3_2 => Box::new(v32::ProtocolV32),
        Version::V3_3 => Box::new(v33::ProtocolV33),
        Version::V3_4 => Box::new(v34::ProtocolV34),
        Version::V3_5 => Box::new(v35::ProtocolV35),
        // Fallback to v3.3 if version is Auto or unknown
        _ => Box::new(v33::ProtocolV33),
    };

    // v3.2 is *always* device22: tinytuya's `set_version(3.2)` forces
    // `dev_type = "device22"` ("3.2 behaves like 3.3 with device22"), so a real
    // v3.2 device answers the status query only via the device22 dialect
    // (`DpQuery` sent as `ControlNew`, requesting specific dps). Apply the
    // wrapper regardless of the requested dev_type.
    if dev_type == DeviceType::Device22 || version == Version::V3_2 {
        Box::new(dev22::ProtocolDev22::new(base))
    } else {
        base
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct TuyaMessage {
    pub seqno: u32,
    pub cmd: u32,
    pub retcode: Option<u32>,
    pub payload: Vec<u8>,
    pub prefix: u32,
    pub iv: Option<Vec<u8>>,
}

impl TuyaMessage {
    #[must_use]
    pub fn payload_as_string(&self) -> Option<String> {
        std::str::from_utf8(&self.payload)
            .ok()
            .map(std::string::ToString::to_string)
    }

    #[must_use]
    pub fn is_55aa(&self) -> bool {
        self.prefix == PREFIX_55AA
    }

    #[must_use]
    pub fn is_6699(&self) -> bool {
        self.prefix == PREFIX_6699
    }
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

#[derive(Debug, Clone)]
pub struct TuyaHeader {
    pub prefix: u32,
    pub seqno: u32,
    pub cmd: u32,
    pub payload_len: u32,
    pub total_length: u32,
}

/// Packs `TuyaMessage` into binary data.
pub fn pack_message(msg: &TuyaMessage, hmac_key: Option<&[u8]>) -> Result<Vec<u8>> {
    let mut data = Vec::new();

    if msg.prefix == PREFIX_55AA {
        let suffix_len = if hmac_key.is_some() { 32 + 4 } else { 4 + 4 };
        let payload_len = msg.payload.len() as u32 + suffix_len as u32;

        data.write_u32::<BigEndian>(msg.prefix)?;
        data.write_u32::<BigEndian>(msg.seqno)?;
        data.write_u32::<BigEndian>(msg.cmd)?;
        data.write_u32::<BigEndian>(payload_len)?;

        data.extend_from_slice(&msg.payload);

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
        header_bytes.write_u16::<BigEndian>(0)?;
        header_bytes.write_u32::<BigEndian>(msg.seqno)?;
        header_bytes.write_u32::<BigEndian>(msg.cmd)?;
        header_bytes.write_u32::<BigEndian>(total_payload_len as u32)?;

        let iv_vec = if let Some(ref iv) = msg.iv {
            iv.clone()
        } else {
            let mut iv = vec![0u8; 12];
            rand::Rng::fill_bytes(&mut rand::rng(), &mut iv);
            iv
        };

        let cipher = TuyaCipher::new(key)?;
        let encrypted =
            cipher.encrypt(&raw, false, Some(&iv_vec), Some(&header_bytes[4..]), false)?;

        data.extend_from_slice(&header_bytes);
        data.extend_from_slice(&encrypted);
        data.write_u32::<BigEndian>(SUFFIX_6699)?;
    }

    Ok(data)
}

/// Validates a wire-supplied payload length against [`MAX_PAYLOAD_LEN`] and
/// returns the framed total length (`payload_len + header_overhead`).
///
/// The bound check rejects a header claiming an implausible length before
/// any allocation keyed off it; the `checked_add` guards the addition
/// against `u32` overflow (belt-and-suspenders — the bound already keeps
/// the sum far from `u32::MAX`, but this stays correct if the cap is ever
/// raised).
fn checked_total_length(payload_len: u32, header_overhead: u32) -> Result<u32> {
    if payload_len > MAX_PAYLOAD_LEN {
        return Err(TuyaError::DecodeError(format!(
            "Header claims payload length {payload_len} exceeds maximum {MAX_PAYLOAD_LEN}"
        )));
    }
    payload_len
        .checked_add(header_overhead)
        .ok_or_else(|| TuyaError::DecodeError("Header length overflow".into()))
}

pub fn parse_header(data: &[u8]) -> Result<TuyaHeader> {
    if data.len() < 16 {
        return Err(TuyaError::DecodeError("Header too short".into()));
    }

    let mut cursor = Cursor::new(data);
    let prefix = cursor.read_u32::<BigEndian>()?;

    match prefix {
        PREFIX_55AA => {
            let seqno = cursor.read_u32::<BigEndian>()?;
            let cmd = cursor.read_u32::<BigEndian>()?;
            let payload_len = cursor.read_u32::<BigEndian>()?;
            let total_length = checked_total_length(payload_len, 16)?;
            Ok(TuyaHeader {
                prefix,
                seqno,
                cmd,
                payload_len,
                total_length,
            })
        }
        PREFIX_6699 => {
            if data.len() < 18 {
                return Err(TuyaError::DecodeError("6699 header too short".into()));
            }
            let _unknown = cursor.read_u16::<BigEndian>()?;
            let seqno = cursor.read_u32::<BigEndian>()?;
            let cmd = cursor.read_u32::<BigEndian>()?;
            let payload_len = cursor.read_u32::<BigEndian>()?;
            let total_length = checked_total_length(payload_len, 18 + 4)?;
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
                "Payload end ({payload_end}) is before header end ({header_len})"
            )));
        }

        let mut payload_start = header_len;
        let mut retcode = None;

        let should_parse_retcode = match no_retcode {
            Some(no) => !no,
            None => {
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

        let should_parse_retcode = match no_retcode {
            Some(no) => !no,
            None => {
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
