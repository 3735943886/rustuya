/**
 * Device Control Example
 *
 * This example demonstrates the fundamental ways to control a Tuya device:
 * using `set_value` for single DP updates and `set_dps` for multiple DP updates.
 *
 * Author: 3735943886
 */
use rustuya::DeviceBuilder;
use serde_json::json;
use tokio::time::{Duration, sleep};

#[tokio::main]
async fn main() {
    let id2 = "ebed83c21d73b95055nsc5"; // 아바토
    let key2 = "];#=gT4'1:Ph8rc_";
    // 1. Initialize Device
    // Replace with actual device ID, IP address, local key, and protocol version.
    let device = DeviceBuilder::new(id2, key2).address("Auto").build();
    println!("--- Rustuya Control Example ---");

    // 2. Control single DP (Data Point)
    // set_value(dp_id, value) is convenient for updating a single DP
    println!("Step 1: Switching ON (using set_value)...");
    match device.set_value(1, true).await {
        Ok(Some(msg)) => println!(
            "Response 1: {}",
            msg.payload_as_string().unwrap_or_default()
        ),
        Ok(None) => println!("Response 1: No data (nowait=true or no response)"),
        Err(e) => println!("Response 1 Error: {:?}", e),
    }

    // Small delay to let the device process
    sleep(Duration::from_secs(1)).await;

    // 3. Control multiple DPs
    // set_dps(json_object) is used for updating one or more DPs at once
    println!("Step 2: Switching OFF (using set_dps)...");
    match device.set_dps(json!({"1": false})).await {
        Ok(Some(msg)) => println!(
            "Response 2: {}",
            msg.payload_as_string().unwrap_or_default()
        ),
        Ok(None) => println!("Response 2: No data (nowait=true or no response)"),
        Err(e) => println!("Response 2 Error: {:?}", e),
    }

    println!("Step 3: Querying status...");
    match device.status().await {
        Ok(Some(msg)) => println!(
            "Response 3: {}",
            msg.payload_as_string().unwrap_or_default()
        ),
        Ok(None) => println!("Response 3: No data"),
        Err(e) => println!("Response 3 Error: {:?}", e),
    }

    println!("Done!");
}
