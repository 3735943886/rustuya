use crate::crypto::TuyaCipher;
use crate::error::{Result, TuyaError};
use crate::protocol::{CommandType, TuyaProtocol, Version, create_base_payload};
use base64::{Engine as _, engine::general_purpose};
use log::trace;
use md5::{Digest, Md5};
use serde_json::Value;

pub struct ProtocolV31;

impl TuyaProtocol for ProtocolV31 {
    fn version(&self) -> Version {
        Version::V3_1
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
                // Default for others: gwId, devId, uid, cid, t, dps
            }
        }

        let payload_obj = Value::Object(payload);
        trace!(
            "v3.1 generated payload (cmd {}): {}",
            cmd_to_send, payload_obj
        );

        Ok((cmd_to_send, payload_obj))
    }

    fn pack_payload(&self, payload: &[u8], cmd: u32, cipher: &TuyaCipher) -> Result<Vec<u8>> {
        if cmd == CommandType::Control as u32 || cmd == CommandType::ControlNew as u32 {
            // 1. AES-128-ECB encrypt
            let encrypted = cipher.encrypt(payload, false, None, None, true)?;

            // 2. Base64 encode
            let b64_payload = general_purpose::STANDARD.encode(&encrypted);
            let b64_bytes = b64_payload.as_bytes();

            // 3. Compute MD5 over: b"data=" + base64payload + b"||lpv=3.1||" + local_key
            let mut hasher = Md5::new();
            hasher.update(b"data=");
            hasher.update(b64_bytes);
            hasher.update(b"||lpv=3.1||");
            hasher.update(cipher.key());

            let hash = hasher.finalize();
            let md5_hex = hex::encode(hash);
            let md5_slice = &md5_hex[8..24];

            // 4. Final payload: b"3.1" + md5slice + base64payload
            let mut final_payload = Vec::with_capacity(3 + 16 + b64_bytes.len());
            final_payload.extend_from_slice(b"3.1");
            final_payload.extend_from_slice(md5_slice.as_bytes());
            final_payload.extend_from_slice(b64_bytes);

            Ok(final_payload)
        } else {
            Ok(payload.to_vec())
        }
    }

    fn decrypt_payload(&self, payload: Vec<u8>, cipher: &TuyaCipher) -> Result<Vec<u8>> {
        if payload.starts_with(b"3.1") && payload.len() > 19 {
            // Strip "3.1" (3 bytes) and MD5 slice (16 bytes)
            let encrypted_b64 = &payload[19..];

            // Base64 decode
            let encrypted = general_purpose::STANDARD
                .decode(encrypted_b64)
                .map_err(|_| TuyaError::DecryptionFailed)?;

            // AES-ECB decrypt
            cipher.decrypt(&encrypted, false, None, None, None)
        } else {
            Ok(payload)
        }
    }

    fn has_version_header(&self, _payload: &[u8]) -> bool {
        false
    }
}
