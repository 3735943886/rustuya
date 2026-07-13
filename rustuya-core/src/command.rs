//! Tuya command codes and JSON request-envelope generation.
//!
//! [`generate_payload`] builds the dps command JSON (gwId / devId / uid / t / dps
//! with per-command field rules) to match the tinytuya reference. It is
//! **version-independent** for the base (non-device22) path — only the wire
//! codec differs by version. The device22 dialect wraps this (next slice).

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::json::{Map, Value};

/// Tuya local command codes (the `cmd` field on the wire).
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandType {
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
    LanExportAppConfig = 0x22,
    LanPublishAppConfig = 0x23,
    ReqDevInfo = 0x25,
    LanExtStream = 0x40,
    LanGwActive = 0xfa,
    LanSubDevRequest = 0xfb,
    LanDeleteSubDev = 0xfc,
    LanReportSubDev = 0xfd,
    LanScene = 0xfe,
    LanPublishCloudConfig = 0xff,
}

impl CommandType {
    /// The numeric command code sent on the wire.
    #[must_use]
    pub fn code(self) -> u32 {
        self as u32
    }
}

/// Builds the JSON request envelope for `command`, returning `(cmd_code, value)`.
///
/// Version-independent; the device22 dialect is applied as a separate wrapper.
/// `t` is the device timestamp (seconds) — always serialized as a string, as
/// tinytuya does.
#[must_use]
pub fn generate_payload(
    device_id: &str,
    command: CommandType,
    data: Option<Value>,
    cid: Option<&str>,
    t: u64,
) -> (u32, Value) {
    use CommandType::{
        Control, ControlNew, DpQueryNew, HeartBeat, LanExtStream, Status, UpdateDps,
    };
    let payload = match command {
        // Only `cid` (if any) survives; `dpId` replaces `dps`.
        UpdateDps => {
            let mut m = Map::new();
            if let Some(c) = cid {
                m.insert("cid".to_string(), c.into());
            }
            m.insert("dpId".to_string(), data.unwrap_or_else(default_dp_ids));
            m
        }
        // A wholly different envelope built from the request object.
        LanExtStream => lan_ext_stream(data),
        _ => {
            let mut m = base_payload(device_id, cid, data, t);
            match command {
                Control | ControlNew | DpQueryNew => {
                    m.remove("gwId");
                }
                Status | HeartBeat => {
                    m.remove("uid");
                    m.remove("t");
                }
                _ => {} // ApConfig, DpQuery, SceneExecute, ReqDevInfo, … keep the base
            }
            m
        }
    };
    (command.code(), Value::Object(payload))
}

fn base_payload(
    device_id: &str,
    cid: Option<&str>,
    data: Option<Value>,
    t: u64,
) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("gwId".to_string(), device_id.into());
    m.insert("devId".to_string(), cid.unwrap_or(device_id).into());
    m.insert("uid".to_string(), device_id.into());
    if let Some(c) = cid {
        m.insert("cid".to_string(), c.into());
    }
    m.insert("t".to_string(), t.to_string().into());
    if let Some(d) = data {
        m.insert("dps".to_string(), d);
    }
    m
}

fn lan_ext_stream(data: Option<Value>) -> Map<String, Value> {
    let mut m = Map::new();
    if let Some(Value::Object(mut obj)) = data {
        if let Some(req_type) = obj.remove("reqType") {
            m.insert("reqType".to_string(), req_type);
        }
        m.insert("data".to_string(), Value::Object(obj));
    }
    m
}

fn default_dp_ids() -> Value {
    Value::Array(Vec::from([
        Value::from(18u64),
        Value::from(19u64),
        Value::from(20u64),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const ID: &str = "01234567890123456789ab";
    const T: u64 = 1_700_000_000;

    fn mk(cmd: CommandType, data: Option<Value>) -> (u32, Value) {
        generate_payload(ID, cmd, data, None, T)
    }

    #[test]
    fn base_commands_keep_full_envelope() {
        let (code, p) = mk(CommandType::ApConfig, None);
        assert_eq!(code, 1);
        assert_eq!(p, json!({"gwId": ID, "devId": ID, "uid": ID, "t": "1700000000"}));
        // DpQuery / SceneExecute / ReqDevInfo share the same shape
        assert_eq!(mk(CommandType::DpQuery, None).0, 0x0a);
        assert_eq!(mk(CommandType::DpQuery, None).1, p);
    }

    #[test]
    fn control_family_drops_gwid() {
        let (code, p) = mk(CommandType::Control, None);
        assert_eq!(code, 7);
        assert_eq!(p, json!({"devId": ID, "uid": ID, "t": "1700000000"}));
        assert_eq!(mk(CommandType::ControlNew, None).0, 0x0d);
        assert_eq!(mk(CommandType::DpQueryNew, None).0, 0x10);
    }

    #[test]
    fn status_and_heartbeat_strip_uid_and_t() {
        let (code, p) = mk(CommandType::Status, None);
        assert_eq!(code, 8);
        assert_eq!(p, json!({"gwId": ID, "devId": ID}));
        assert_eq!(mk(CommandType::HeartBeat, None).1, p);
    }

    #[test]
    fn update_dps_defaults_and_control_carries_dps() {
        let (code, p) = mk(CommandType::UpdateDps, None);
        assert_eq!(code, 0x12);
        assert_eq!(p, json!({"dpId": [18, 19, 20]}));

        // dps data flows into a Control envelope
        let (_, p) = mk(CommandType::Control, Some(json!({"1": true})));
        assert_eq!(p, json!({"devId": ID, "uid": ID, "t": "1700000000", "dps": {"1": true}}));
    }

    #[test]
    fn lan_ext_stream_reshapes_into_reqtype_and_data() {
        let (code, p) = mk(
            CommandType::LanExtStream,
            Some(json!({"reqType": "subdev_online_stat_query", "cids": []})),
        );
        assert_eq!(code, 0x40);
        assert_eq!(p, json!({"reqType": "subdev_online_stat_query", "data": {"cids": []}}));
    }
}
