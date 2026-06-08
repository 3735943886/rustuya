use crate::crypto::TuyaCipher;
use crate::error::Result;
use crate::protocol::{
    CommandType, NO_PROTOCOL_HEADER_CMDS, TuyaProtocol, Version, apply_update_dps,
    create_base_payload, lan_ext_stream_envelope, modern_control_envelope, strip_status_heartbeat,
};
use log::trace;
use serde_json::Value;

pub struct ProtocolV34;

impl ProtocolV34 {
    fn add_protocol_header(&self, payload: &[u8]) -> Vec<u8> {
        let mut header = Version::V3_4.as_bytes().to_vec();
        header.extend_from_slice(&[0u8; 12]);
        header.extend_from_slice(payload);
        header
    }
}

impl TuyaProtocol for ProtocolV34 {
    fn version(&self) -> Version {
        Version::V3_4
    }

    fn get_effective_command(&self, command: CommandType) -> u32 {
        match command {
            CommandType::Control => CommandType::ControlNew as u32,
            CommandType::DpQuery => CommandType::DpQueryNew as u32,
            cmd => cmd as u32,
        }
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

        match command {
            CommandType::UpdateDps => apply_update_dps(&mut payload, data),
            CommandType::Control | CommandType::ControlNew => {
                payload = modern_control_envelope(t, cid, data);
            }
            CommandType::LanExtStream => {
                payload = lan_ext_stream_envelope(data);
            }
            CommandType::DpQuery | CommandType::DpQueryNew => {
                payload.retain(|k, _| k == "cid" || k == "dps");
            }
            CommandType::Status | CommandType::HeartBeat => strip_status_heartbeat(&mut payload),
            _ => {
                // Default: gwId, devId, uid, cid, t, dps
            }
        }

        let payload_obj = Value::Object(payload);
        trace!("v3.4 generated payload (cmd {cmd_to_send}): {payload_obj}");

        Ok((cmd_to_send, payload_obj))
    }

    fn pack_payload(&self, payload: &[u8], cmd: u32, cipher: &TuyaCipher) -> Result<Vec<u8>> {
        let use_header = !NO_PROTOCOL_HEADER_CMDS.contains(&cmd);
        let mut data = payload.to_vec();

        if use_header {
            data = self.add_protocol_header(&data);
        }

        cipher.encrypt(&data, false, None, None, true)
    }

    fn decrypt_payload(&self, mut payload: Vec<u8>, cipher: &TuyaCipher) -> Result<Vec<u8>> {
        // v3.4 uses 55AA prefix for some responses which need decryption
        if let Ok(decrypted) = cipher.decrypt(&payload, false, None, None, None) {
            payload = decrypted;
        }

        if self.has_version_header(&payload) {
            payload.drain(..15);
        }
        Ok(payload)
    }

    fn has_version_header(&self, payload: &[u8]) -> bool {
        payload.len() >= 15 && &payload[..3] == Version::V3_4.as_bytes()
    }

    fn requires_session_key(&self) -> bool {
        true
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

    fn get_hmac_key<'a>(&self, cipher_key: &'a [u8]) -> Option<&'a [u8]> {
        Some(cipher_key)
    }

    fn is_empty_payload_allowed(&self, _cmd: u32) -> bool {
        false
    }

    fn should_check_dev22_fallback(&self) -> bool {
        true
    }
}
