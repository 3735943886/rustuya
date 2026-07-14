//! Tuya command codes and JSON request-envelope generation.
//!
//! [`generate`] builds the dps command JSON to match the tinytuya reference.
//! Two envelope templates exist:
//!   * **legacy** (v3.1 / v3.2 / v3.3): `{gwId, devId, uid, t, dps}` with
//!     per-command field stripping;
//!   * **modern** (v3.4 / v3.5): `Control`/`DpQuery` become
//!     `{protocol: 5, t, data: {...}}` / `{dps}`, and their command codes are
//!     remapped to `ControlNew` / `DpQueryNew`.
//!
//! The **device22** dialect is layered on top: it overrides only the status
//! query (`DpQuery` → `ControlNew`, asking for `{"1": null}` when no dps given);
//! v3.2 is always device22.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::json::{Map, Value};
use crate::version::{DeviceType, Version};

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

/// Builds the request envelope for `command`, applying the device22 dialect when
/// `dev_type` is [`DeviceType::Device22`] or the version is v3.2 (always
/// device22). Returns `(cmd_code, value)`.
#[must_use]
pub fn generate(
    version: Version,
    dev_type: DeviceType,
    device_id: &str,
    command: CommandType,
    data: Option<Value>,
    cid: Option<&str>,
    t: u64,
) -> (u32, Value) {
    let dev22 = dev_type == DeviceType::Device22 || version == Version::V3_2;
    // device22 overrides *only* the status query; everything else uses the base
    // version's shape.
    if dev22 && command == CommandType::DpQuery {
        let mut m = base_payload(device_id, cid, data, t);
        m.remove("gwId");
        m.entry("dps".to_string()).or_insert_with(|| {
            let mut d = Map::new();
            d.insert("1".to_string(), Value::Null);
            Value::Object(d)
        });
        return (CommandType::ControlNew.code(), Value::Object(m));
    }
    generate_payload(version, device_id, command, data, cid, t)
}

/// The base (non-device22) envelope for `command` at `version`.
#[must_use]
pub fn generate_payload(
    version: Version,
    device_id: &str,
    command: CommandType,
    data: Option<Value>,
    cid: Option<&str>,
    t: u64,
) -> (u32, Value) {
    use CommandType::{
        Control, ControlNew, DpQuery, DpQueryNew, HeartBeat, LanExtStream, Status, UpdateDps,
    };
    let modern = is_modern(version);

    let payload = match command {
        UpdateDps => update_dps(cid, data),
        LanExtStream => lan_ext_stream(data),
        Control | ControlNew if modern => modern_control_envelope(t, cid, data),
        DpQuery | DpQueryNew if modern => dps_only(cid, data),
        // legacy control family (and modern falls through above): drop gwId.
        Control | ControlNew | DpQueryNew => {
            let mut m = base_payload(device_id, cid, data, t);
            m.remove("gwId");
            m
        }
        Status | HeartBeat => {
            let mut m = base_payload(device_id, cid, data, t);
            m.remove("uid");
            m.remove("t");
            m
        }
        // ApConfig, legacy DpQuery, SceneExecute, ReqDevInfo, … keep the base.
        _ => base_payload(device_id, cid, data, t),
    };
    (effective_command(version, command), Value::Object(payload))
}

/// v3.4/v3.5 remap `Control` → `ControlNew` and `DpQuery` → `DpQueryNew`; all
/// other commands (and all legacy versions) keep their own code.
fn effective_command(version: Version, command: CommandType) -> u32 {
    match (is_modern(version), command) {
        (true, CommandType::Control) => CommandType::ControlNew.code(),
        (true, CommandType::DpQuery) => CommandType::DpQueryNew.code(),
        _ => command.code(),
    }
}

fn is_modern(version: Version) -> bool {
    matches!(version, Version::V3_4 | Version::V3_5)
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
    m.insert("t".to_string(), t.to_string().into()); // legacy: t as string
    if let Some(d) = data {
        m.insert("dps".to_string(), d);
    }
    m
}

/// v3.4/v3.5 `Control`/`ControlNew`: `{protocol: 5, t: <int>, data: {cid?, ctype?, dps?}}`.
fn modern_control_envelope(t: u64, cid: Option<&str>, data: Option<Value>) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("protocol".to_string(), Value::from(5u64));
    m.insert("t".to_string(), Value::from(t)); // modern: t as integer

    let mut inner = Map::new();
    if let Some(c) = cid {
        inner.insert("cid".to_string(), c.into());
        inner.insert("ctype".to_string(), Value::from(0u64));
    }
    if let Some(d) = data {
        inner.insert("dps".to_string(), d);
    }
    m.insert("data".to_string(), Value::Object(inner));
    m
}

/// v3.4/v3.5 `DpQuery`/`DpQueryNew`: only `cid`/`dps` survive.
fn dps_only(cid: Option<&str>, data: Option<Value>) -> Map<String, Value> {
    let mut m = Map::new();
    if let Some(c) = cid {
        m.insert("cid".to_string(), c.into());
    }
    if let Some(d) = data {
        m.insert("dps".to_string(), d);
    }
    m
}

fn update_dps(cid: Option<&str>, data: Option<Value>) -> Map<String, Value> {
    let mut m = Map::new();
    if let Some(c) = cid {
        m.insert("cid".to_string(), c.into());
    }
    m.insert("dpId".to_string(), data.unwrap_or_else(default_dp_ids));
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

    #[test]
    fn legacy_control_drops_gwid_status_strips() {
        let (code, p) = generate_payload(Version::V3_3, ID, CommandType::Control, None, None, T);
        assert_eq!(code, 7);
        assert_eq!(p, json!({"devId": ID, "uid": ID, "t": "1700000000"}));

        let (code, p) = generate_payload(Version::V3_3, ID, CommandType::Status, None, None, T);
        assert_eq!(code, 8);
        assert_eq!(p, json!({"gwId": ID, "devId": ID}));
    }

    #[test]
    fn modern_control_and_dpquery_and_remap() {
        let (code, p) = generate_payload(
            Version::V3_4,
            ID,
            CommandType::Control,
            Some(json!({"1": true})),
            None,
            T,
        );
        assert_eq!(code, 0x0d); // Control -> ControlNew
        assert_eq!(
            p,
            json!({"protocol": 5, "t": 1700000000, "data": {"dps": {"1": true}}})
        );

        let (code, p) = generate_payload(Version::V3_5, ID, CommandType::DpQuery, None, None, T);
        assert_eq!(code, 0x10); // DpQuery -> DpQueryNew
        assert_eq!(p, json!({}));
    }

    #[test]
    fn dev22_dpquery_override_and_v32_always_dev22() {
        let (code, p) = generate(
            Version::V3_3,
            DeviceType::Device22,
            ID,
            CommandType::DpQuery,
            None,
            None,
            T,
        );
        assert_eq!(code, 0x0d);
        assert_eq!(
            p,
            json!({"devId": ID, "uid": ID, "t": "1700000000", "dps": {"1": null}})
        );

        // v3.2 is device22 even with dev_type=Auto
        let (code, _) = generate(
            Version::V3_2,
            DeviceType::Auto,
            ID,
            CommandType::DpQuery,
            None,
            None,
            T,
        );
        assert_eq!(code, 0x0d);
    }
}
