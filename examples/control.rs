/**
 * Device Control Example
 *
 * This example demonstrates the fundamental ways to control a Tuya device:
 * using `set_value` for single DP updates and `set_dps` for multiple DP updates.
 *
 * Author: 3735943886
 */
use rustuya::sync::Device;
use serde_json::json;
use std::{thread, time};

fn main() {
    // 1. Initialize Device
    // Replace with actual device ID, IP address, local key, and protocol version.
    let device = Device::new("DEVICE_ID", "ADDRESS", "DEVICE_KEY", "VERSION");
    println!("--- Rustuya Control Example ---");

    // 2. Control single DP (Data Point)
    // set_value(dp_id, value) is convenient for updating a single DP
    println!("Step 1: Switching ON (using set_value)...");
    device.set_value(1, true);

    // Small delay to let the device process
    thread::sleep(time::Duration::from_secs(1));

    // 3. Control multiple DPs
    // set_dps(json_object) is used for updating one or more DPs at once
    println!("Step 2: Switching OFF (using set_dps)...");
    device.set_dps(json!({"1": false}));

    println!("Done!");
}
