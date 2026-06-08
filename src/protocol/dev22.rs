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
        // device22 is a *dialect layered on top of* the base version, not a
        // replacement. Only the standard status query is remapped (rejected by
        // the device → retried via `CONTROL_NEW`); every other command keeps
        // the base version's command mapping (e.g. v3.4/v3.5 still remap
        // `Control` → `ControlNew`).
        match command {
            CommandType::DpQuery => CommandType::ControlNew as u32,
            cmd => self.base.get_effective_command(cmd),
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
        // device22 only overrides the status query: the device rejects the
        // standard `DpQuery`/`DpQueryNew`, so we ask for the requested dps via
        // `CONTROL_NEW` instead. This dialect shape is the same regardless of
        // the base version (it mirrors tinytuya's `device22` payload_dict
        // override, which is merged on top of every version template).
        //
        // Everything else delegates to the base version protocol so that
        // version-specific behaviour (e.g. the v3.4/v3.5 modern `Control`
        // envelope) is preserved. tinytuya's `device22` template only carries a
        // `DP_QUERY` override, so all other commands fall through to the
        // version's own shape — this matches that.
        if command != CommandType::DpQuery {
            return self.base.generate_payload(device_id, command, data, cid, t);
        }

        let mut payload =
            create_base_payload(device_id, cid, data.clone(), Some(t.to_string().into()));
        payload.remove("gwId");
        if payload.get("dps").is_none() {
            payload.insert("dps".into(), serde_json::json!({"1": null}));
        }

        let cmd_to_send = CommandType::ControlNew as u32;
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
