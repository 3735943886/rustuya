/**
 * Basic Device Control Example
 *
 * This example demonstrates the fundamental ways to control a Tuya device:
 * using `set_value` for single DP updates and `set_dps` for multiple DP updates.
 */
use rustuya::sync::Device;
use serde_json::json;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Basic Configuration
    let device_id = "device_id";
    let local_key = "device_key";

    // 2. Initialize Device
    let device = Device::new(device_id, local_key);

    println!("--- Rustuya Basic Control Example ---");
    println!("Target Device: {}", device_id);

    // 3. Control single DP (Data Point)
    println!("Step 1: Switching ON (using set_value)...");
    // set_value(dp_id, value) is convenient for updating a single DP
    device.set_value(1, json!(true))?;

    // Small delay to let the device process
    std::thread::sleep(std::time::Duration::from_secs(1));

    // 4. Control multiple DPs
    println!("Step 2: Switching OFF (using set_dps)...");
    // set_dps(json_object) is used for updating one or more DPs at once
    device.set_dps(json!({"1": false}))?;

    println!("Done!");

    Ok(())
}
