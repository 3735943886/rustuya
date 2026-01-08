/**
 * Device Control Example
 *
 * This example demonstrates the fundamental ways to control a Tuya device:
 * using `set_value` for single DP updates and `set_dps` for multiple DP updates.
 */
use rustuya::DeviceBuilder;
use serde_json::json;
use tokio::time::{Duration, sleep};

#[tokio::main]
async fn main() {
    println!("--- Rustuya - Device Control ---");

    // 1. Initialize Device (Using Lab Wired Gateway as an example)
    let id = "eb5176f91956a97b165dc5";
    let key = "FGhe;!?GLh$vv9<c";
    let device = DeviceBuilder::new(id, key).address("Auto").build();

    // 2. Control single DP (Data Point)
    // set_value(dp_id, value) is convenient for updating a single DP
    println!("[STEP 1] Switching ON (using set_value)...");
    match device.set_value(1, true).await {
        Ok(Some(msg)) => println!(
            "[SUCCESS] Response: {}",
            msg.payload_as_string().unwrap_or_default()
        ),
        Ok(None) => println!("[INFO] No direct response (nowait=true or no response)"),
        Err(e) => eprintln!("[ERROR] Control failed: {:?}", e),
    }

    // Small delay between commands
    sleep(Duration::from_secs(1)).await;

    // 3. Control multiple DPs
    // set_dps(json_object) is used for updating one or more DPs at once
    println!("[STEP 2] Switching OFF (using set_dps)...");
    match device.set_dps(json!({"1": false})).await {
        Ok(Some(msg)) => println!(
            "[SUCCESS] Response: {}",
            msg.payload_as_string().unwrap_or_default()
        ),
        Ok(None) => println!("[INFO] No direct response"),
        Err(e) => eprintln!("[ERROR] Control failed: {:?}", e),
    }

    // 4. Query status
    println!("[STEP 3] Querying current status...");
    match device.status().await {
        Ok(Some(msg)) => println!(
            "[SUCCESS] Status: {}",
            msg.payload_as_string().unwrap_or_default()
        ),
        Ok(None) => println!("[INFO] No status data received"),
        Err(e) => eprintln!("[ERROR] Status query failed: {:?}", e),
    }

    println!("[INFO] Example finished.");
}
