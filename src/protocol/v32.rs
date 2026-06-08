use crate::crypto::TuyaCipher;
use crate::error::Result;
use crate::protocol::{
    CommandType, NO_PROTOCOL_HEADER_CMDS, TuyaProtocol, Version, apply_update_dps,
    create_base_payload, lan_ext_stream_envelope, strip_status_heartbeat,
};
use log::trace;
use serde_json::Value;

pub struct ProtocolV32;

impl ProtocolV32 {
    fn add_protocol_header(&self, payload: &[u8]) -> Vec<u8> {
        let mut header = Version::V3_2.as_bytes().to_vec();
        header.extend_from_slice(&[0u8; 12]);
        header.extend_from_slice(payload);
        header
    }
}

impl TuyaProtocol for ProtocolV32 {
    fn version(&self) -> Version {
        Version::V3_2
    }

    fn get_effective_command(&self, command: CommandType) -> u32 {
        command as u32
    }

    fn generate_payload(
        &self,
        device_id: &str,
        command: CommandType,
        data: Option<Value>,
        cid: Option<&str>,
        t: u64,
    ) -> Result<(u32, Value)> {
        let cmd_to_send = self.get_effective_command(command);
        let mut payload =
            create_base_payload(device_id, cid, data.clone(), Some(t.to_string().into()));

        // v3.2 shares v3.3's framing/payload shape. The device22 status-query
        // dialect (v3.2 is always device22 — see `get_protocol`) is supplied by
        // the `ProtocolDev22` wrapper, which intercepts `DpQuery`; this bare
        // profile therefore treats `DpQuery` like v3.3 (keep the base payload).
        match command {
            CommandType::UpdateDps => apply_update_dps(&mut payload, data),
            CommandType::Control | CommandType::ControlNew | CommandType::DpQueryNew => {
                payload.remove("gwId");
            }
            CommandType::DpQuery => {
                // Keep gwId/devId/uid/cid/t/dps unchanged (same as v3.3).
            }
            CommandType::LanExtStream => {
                payload = lan_ext_stream_envelope(data);
            }
            CommandType::Status | CommandType::HeartBeat => strip_status_heartbeat(&mut payload),
            _ => {
                // Default: gwId, devId, uid, cid, t, dps
            }
        }

        let payload_obj = Value::Object(payload);
        trace!("v3.2 generated payload (cmd {cmd_to_send}): {payload_obj}");

        Ok((cmd_to_send, payload_obj))
    }

    fn pack_payload(&self, payload: &[u8], cmd: u32, cipher: &TuyaCipher) -> Result<Vec<u8>> {
        // Encryption/Decryption same as v3.3
        let mut packed = cipher.encrypt(payload, false, None, None, true)?;
        if !NO_PROTOCOL_HEADER_CMDS.contains(&cmd) {
            packed = self.add_protocol_header(&packed);
        }
        Ok(packed)
    }

    fn decrypt_payload(&self, mut payload: Vec<u8>, cipher: &TuyaCipher) -> Result<Vec<u8>> {
        // Encryption/Decryption same as v3.3 (but check for 3.2 header)
        if payload.len() >= 15 && &payload[..3] == Version::V3_2.as_bytes() {
            payload.drain(..15);
        }
        if !payload.is_empty()
            && let Ok(decrypted) = cipher.decrypt(&payload, false, None, None, None)
        {
            let mut d = decrypted;
            if d.len() >= 15 && &d[..3] == Version::V3_2.as_bytes() {
                d.drain(..15);
            }
            return Ok(d);
        }
        Ok(payload)
    }

    fn has_version_header(&self, payload: &[u8]) -> bool {
        payload.len() >= 15 && &payload[..3] == Version::V3_2.as_bytes()
    }

    fn requires_session_key(&self) -> bool {
        false
    }

    fn encrypt_session_key(
        &self,
        session_key: &[u8],
        cipher: &TuyaCipher,
        _nonce: &[u8],
    ) -> Result<Vec<u8>> {
        cipher.encrypt(session_key, false, None, None, false)
    }

    fn get_prefix(&self) -> u32 {
        crate::protocol::PREFIX_55AA
    }

    fn get_hmac_key<'a>(&self, _cipher_key: &'a [u8]) -> Option<&'a [u8]> {
        None
    }

    fn is_empty_payload_allowed(&self, _cmd: u32) -> bool {
        false
    }

    fn should_check_dev22_fallback(&self) -> bool {
        false
    }
}
