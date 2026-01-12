/**
 * Unified Listener Example
 *
 * This example demonstrates how to aggregate events from multiple Tuya devices
 * into a single unified receiver in a non-async environment.
 */
use rustuya::sync::{Device, unified_listener};

fn main() {
    println!("--- Rustuya Unified Listener Example ---");

    // 1. Basic Configuration
    let device_id_1 = "device_id_1";
    let local_key_1 = "device_key_1";
    let device_id_2 = "device_id_2";
    let local_key_2 = "device_key_2";

    // 2. Initialize multiple devices
    let devices = vec![
        Device::new(device_id_1, local_key_1),
        Device::new(device_id_2, local_key_2),
    ];

    println!(
        "[INFO] Created {} devices. Starting unified listener...",
        devices.len()
    );

    // 3. Create a unified listener receiver
    let rx = unified_listener(devices);

    // 4. Process events from any of the devices in a single loop
    println!("[INFO] Waiting for events (Press Ctrl+C to stop)...");

    while let Ok(result) = rx.recv() {
        match result {
            Ok(event) => {
                println!(
                    "[EVENT] Device: {}, Command: {:?}, Payload: {}",
                    event.device_id,
                    event.message.cmd,
                    event.message.payload_as_string().unwrap_or_default()
                );
            }
            Err(e) => {
                eprintln!("[ERROR] Error receiving event: {}", e);
            }
        }
    }
}
