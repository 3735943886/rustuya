/**
 * Unified Listener Example (Sync)
 *
 * This example demonstrates how to aggregate events from multiple Tuya devices
 * into a single unified receiver in a non-async environment.
 */
use rustuya::sync::{Device, unified_listener};

fn main() {
    println!("--- Rustuya - Unified Listener (Sync) ---");

    // 1. Create multiple devices using provided credentials
    let devices = vec![
        Device::new("ebc8dc02c02761c44e1iho", "W:tqKTs?g)agP62S"), // AUBESS 20A
        Device::new("eb7ba8427911a8ccbda92w", "GyFSITk>TL8?EBRK"), // Office Light
        Device::new("eb3ff73bef776e4a1aay8r", "c)H+2(TY@sY)e&5L"), // Wired Gateway
        Device::new("eb5176f91956a97b165dc5", "FGhe;!?GLh$vv9<c"), // Lab Wired Gateway
    ];

    println!(
        "[INFO] Created {} devices. Starting unified listener...",
        devices.len()
    );

    // 2. Create a unified listener receiver
    let rx = unified_listener(devices);

    // 3. Process events from any of the devices in a single loop
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
