use rustuya::CommandType;
/**
 * Direct Request Example
 *
 * This example demonstrates how to use the `request` method to send
 * specific Tuya commands directly to a device.
 */
use rustuya::sync::Device;
use serde_json::json;

fn main() {
    // 1. Initialize Device
    // Replace with actual device ID, IP address, local key, and protocol version.
    let device = Device::new("DEVICE_ID", "ADDRESS", "DEVICE_KEY", "VERSION");
    println!("--- Rustuya Direct Request Example ---");

    // 2. Send a Control request (same as calling device.set_dps())
    println!("Sending Control request to turn on DP 1...");
    device.request(CommandType::Control, Some(json!({"1": true})), None);

    println!("Done.");
}
