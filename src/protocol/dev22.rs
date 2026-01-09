use crate::crypto::TuyaCipher;
use crate::error::Result;
use crate::protocol::{CommandType, TuyaProtocol, Version, create_base_payload};
use log::trace;
use serde_json::Value;

pub struct ProtocolDev22 {
    base: Box<dyn TuyaProtocol>,
}

impl ProtocolDev22 {
    #[must_use]
    pub fn new(base: Box<dyn TuyaProtocol>) -> Self {
        Self { base }
    }
}

impl TuyaProtocol for ProtocolDev22 {
    fn version(&self) -> Version {
        self.base.version()
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
                    payload.insert("dps".into(), serde_json::json!({"1": null}));
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
        trace!("dev22 generated payload (cmd {cmd_to_send}): {payload_obj}");

        Ok((cmd_to_send, payload_obj))
    }

    fn pack_payload(&self, payload: &[u8], cmd: u32, cipher: &TuyaCipher) -> Result<Vec<u8>> {
        self.base.pack_payload(payload, cmd, cipher)
    }

    fn decrypt_payload(&self, payload: Vec<u8>, cipher: &TuyaCipher) -> Result<Vec<u8>> {
        self.base.decrypt_payload(payload, cipher)
    }

    fn has_version_header(&self, payload: &[u8]) -> bool {
        self.base.has_version_header(payload)
    }

    fn requires_session_key(&self) -> bool {
        self.base.requires_session_key()
    }

    fn encrypt_session_key(
        &self,
        session_key: &[u8],
        cipher: &TuyaCipher,
        nonce: &[u8],
    ) -> Result<Vec<u8>> {
        self.base.encrypt_session_key(session_key, cipher, nonce)
    }

    fn get_prefix(&self) -> u32 {
        self.base.get_prefix()
    }

    fn get_hmac_key<'a>(&self, cipher_key: &'a [u8]) -> Option<&'a [u8]> {
        self.base.get_hmac_key(cipher_key)
    }

    fn is_empty_payload_allowed(&self, cmd: u32) -> bool {
        self.base.is_empty_payload_allowed(cmd)
    }

    fn should_check_dev22_fallback(&self) -> bool {
        false
    }
}
