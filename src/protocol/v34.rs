use crate::crypto::TuyaCipher;
use crate::error::Result;
use crate::protocol::{
    CommandType, NO_PROTOCOL_HEADER_CMDS, TuyaProtocol, Version, create_base_payload,
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
            CommandType::UpdateDps => {
                payload.retain(|k, _| k == "cid");
                let d = data.unwrap_or_else(|| serde_json::json!([18, 19, 20]));
                payload.insert("dpId".into(), d);
            }
            CommandType::Control | CommandType::ControlNew => {
                payload.clear();
                payload.insert("protocol".into(), 5.into());
                payload.insert("t".into(), t.into());

                let mut data_obj = serde_json::Map::new();
                if let Some(c) = cid {
                    data_obj.insert("cid".into(), c.into());
                    data_obj.insert("ctype".into(), 0.into());
                }
                if let Some(d) = data {
                    data_obj.insert("dps".into(), d);
                }
                payload.insert("data".into(), Value::Object(data_obj));
            }
            CommandType::LanExtStream => {
                // For LanExtStream in v3.4, we only keep reqType at root and move everything else under "data"
                payload.clear();
                if let Some(Value::Object(mut data_obj)) = data {
                    if let Some(req_type) = data_obj.remove("reqType") {
                        payload.insert("reqType".into(), req_type);
                    }
                    payload.insert("data".into(), Value::Object(data_obj));
                }
            }
            CommandType::DpQuery | CommandType::DpQueryNew => {
                payload.retain(|k, _| k == "cid" || k == "dps");
            }
            CommandType::Status | CommandType::HeartBeat => {
                payload.remove("uid");
                payload.remove("t");
            }
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
