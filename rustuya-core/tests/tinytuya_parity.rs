//! Payload parity against tinytuya, ported to the sans-io core.
//!
//! The fixture is the same one generated from tinytuya for the 0.3 crate
//! (`gen_tinytuya_payloads.py`); tinytuya is the reference. For every
//! (version x device type x command x data) case it records the command code
//! and JSON payload tinytuya emits with the clock pinned. This feeds the
//! identical inputs to `rustuya_core::command::generate` and asserts an
//! (order-insensitive) match.

use rustuya_core::command::{CommandType, generate};
use rustuya_core::version::{DeviceType, Version};
use serde_json::Value;

const FIXTURE: &str = include_str!("fixtures/tinytuya_payloads.json");

fn version_of(s: &str) -> Version {
    Version::parse(s).unwrap_or_else(|| panic!("unknown version in fixture: {s}"))
}

fn dev_type_of(s: &str) -> DeviceType {
    DeviceType::parse(s).unwrap_or_else(|| panic!("unknown dev_type in fixture: {s}"))
}

fn command_of(s: &str) -> CommandType {
    match s {
        "ApConfig" => CommandType::ApConfig,
        "Control" => CommandType::Control,
        "Status" => CommandType::Status,
        "HeartBeat" => CommandType::HeartBeat,
        "DpQuery" => CommandType::DpQuery,
        "ControlNew" => CommandType::ControlNew,
        "DpQueryNew" => CommandType::DpQueryNew,
        "UpdateDps" => CommandType::UpdateDps,
        "SceneExecute" => CommandType::SceneExecute,
        "ReqDevInfo" => CommandType::ReqDevInfo,
        "LanExtStream" => CommandType::LanExtStream,
        other => panic!("unknown command in fixture: {other}"),
    }
}

#[test]
fn tinytuya_payload_parity() {
    let root: Value = serde_json::from_str(FIXTURE).expect("fixture is valid JSON");
    let device_id = root["device_id"].as_str().expect("device_id");
    let cases = root["cases"].as_array().expect("cases array");

    let mut failures: Vec<String> = Vec::new();
    let mut checked = 0usize;

    for case in cases {
        let version_s = case["version"].as_str().unwrap();
        let dev_type_s = case["dev_type"].as_str().unwrap();
        let command_s = case["command"].as_str().unwrap();
        let data = &case["data"];
        let t = case["t"].as_u64().unwrap();
        let expected_cmd = case["expected_cmd"].as_u64().unwrap() as u32;
        let expected_payload = &case["expected_payload"];

        let data_opt = if data.is_null() {
            None
        } else {
            Some(data.clone())
        };

        let (cmd, payload) = generate(
            version_of(version_s),
            dev_type_of(dev_type_s),
            device_id,
            command_of(command_s),
            data_opt,
            None,
            t,
        );
        checked += 1;

        if cmd != expected_cmd || &payload != expected_payload {
            failures.push(format!(
                "{version_s} {dev_type_s} {command_s} data={data}\n     tinytuya: cmd={expected_cmd} {expected_payload}\n     core    : cmd={cmd} {payload}"
            ));
        }
    }

    eprintln!("tinytuya parity: checked {checked} cases");
    if !failures.is_empty() {
        eprintln!("\n--- divergences ({}) ---", failures.len());
        for d in &failures {
            eprintln!("  {d}");
        }
        panic!("{} payload divergence(s) from tinytuya", failures.len());
    }
}
