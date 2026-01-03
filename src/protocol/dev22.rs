use crate::crypto::TuyaCipher;
use crate::error::Result;
use crate::protocol::{CommandType, TuyaProtocol, Version, create_base_payload};
use log::trace;
use serde_json::Value;

pub struct ProtocolDev22;

impl TuyaProtocol for ProtocolDev22 {
    fn version(&self) -> Version {
        Version::V3_3
    }

    fn get_effective_command(&self, command: CommandType) -> u32 {
        match command {
            CommandType::DpQuery => CommandType::ControlNew as u32,
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
                payload.remove("gwId");
            }
            CommandType::DpQuery => {
                payload.remove("gwId");
                if payload.get("dps").is_none() {
                    payload.insert("dps".into(), serde_json::json!({}));
                }
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
            "dev22 generated payload (cmd {}): {}",
            cmd_to_send, payload_obj
        );

        Ok((cmd_to_send, payload_obj))
    }

    fn pack_payload(&self, payload: &[u8], _cmd: u32, cipher: &TuyaCipher) -> Result<Vec<u8>> {
        cipher.encrypt(payload, false, None, None, true)
    }

    fn decrypt_payload(&self, payload: Vec<u8>, cipher: &TuyaCipher) -> Result<Vec<u8>> {
        cipher.decrypt(&payload, false, None, None, None)
    }

    fn has_version_header(&self, payload: &[u8]) -> bool {
        !payload.len().is_multiple_of(16)
    }
}
