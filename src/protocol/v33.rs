use crate::crypto::TuyaCipher;
use crate::error::Result;
use crate::protocol::{
    CommandType, NO_PROTOCOL_HEADER_CMDS, TuyaProtocol, Version, create_base_payload,
};
use log::trace;
use serde_json::Value;

pub struct ProtocolV33;

impl ProtocolV33 {
    fn add_protocol_header(&self, payload: &[u8]) -> Vec<u8> {
        let mut header = Version::V3_3.as_bytes().to_vec();
        header.extend_from_slice(&[0u8; 12]);
        header.extend_from_slice(payload);
        header
    }
}

impl TuyaProtocol for ProtocolV33 {
    fn version(&self) -> Version {
        Version::V3_3
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

        match command {
            CommandType::UpdateDps => {
                payload.retain(|k, _| k == "cid");
                let d = data.unwrap_or_else(|| serde_json::json!([18, 19, 20]));
                payload.insert("dpId".into(), d);
            }
            CommandType::Control | CommandType::ControlNew => {
                payload.remove("gwId");
            }
            CommandType::DpQuery => {
                // Keep all: gwId, devId, uid, cid, t, dps
            }
            CommandType::DpQueryNew => {
                payload.remove("gwId");
            }
            CommandType::LanExtStream => {
                payload = data
                    .unwrap_or_else(|| serde_json::json!({}))
                    .as_object()
                    .cloned()
                    .unwrap_or_default();
                if let Some(c) = cid {
                    payload.insert("cid".into(), c.into());
                    payload.insert("ctype".into(), 0.into());
                }
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
        trace!(
            "v3.3 generated payload (cmd {}): {}",
            cmd_to_send, payload_obj
        );

        Ok((cmd_to_send, payload_obj))
    }

    fn pack_payload(&self, payload: &[u8], cmd: u32, cipher: &TuyaCipher) -> Result<Vec<u8>> {
        let mut packed = cipher.encrypt(payload, false, None, None, true)?;
        if !NO_PROTOCOL_HEADER_CMDS.contains(&cmd) {
            packed = self.add_protocol_header(&packed);
        }
        Ok(packed)
    }

    fn decrypt_payload(&self, mut payload: Vec<u8>, cipher: &TuyaCipher) -> Result<Vec<u8>> {
        if payload.len() >= 15 && &payload[..3] == Version::V3_3.as_bytes() {
            payload.drain(..15);
        }
        if !payload.is_empty()
            && let Ok(decrypted) = cipher.decrypt(&payload, false, None, None, None)
        {
            let mut d = decrypted;
            if d.len() >= 15 && &d[..3] == Version::V3_3.as_bytes() {
                d.drain(..15);
            }
            return Ok(d);
        }
        Ok(payload)
    }

    fn has_version_header(&self, payload: &[u8]) -> bool {
        payload.len() >= 15 && &payload[..3] == Version::V3_3.as_bytes()
    }
}
