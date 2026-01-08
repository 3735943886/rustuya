/**
 * Unified Listener Example
 *
 * This example demonstrates how to aggregate events from multiple Tuya devices
 * into a single unified stream for centralized management.
 */
use futures_util::StreamExt;
use rustuya::device::{DeviceBuilder, unified_listener};

#[tokio::main]
async fn main() {
    println!("--- Rustuya - Unified Listener ---");

    // 1. Create multiple devices using provided credentials
    let devices = vec![
        DeviceBuilder::new("ebc8dc02c02761c44e1iho", "W:tqKTs?g)agP62S").build(), // AUBESS 20A
        DeviceBuilder::new("eb7ba8427911a8ccbda92w", "GyFSITk>TL8?EBRK").build(), // Office Light
        DeviceBuilder::new("eb3ff73bef776e4a1aay8r", "c)H+2(TY@sY)e&5L").build(), // Wired Gateway
        DeviceBuilder::new("eb5176f91956a97b165dc5", "FGhe;!?GLh$vv9<c").build(), // Lab Wired Gateway
    ];

    println!(
        "[INFO] Created {} devices. Starting unified listener...",
        devices.len()
    );

    // 2. Create a unified listener stream
    let stream = unified_listener(devices);
    tokio::pin!(stream);

    // 3. Process events from any of the devices in a single loop
    println!("[INFO] Waiting for events (Press Ctrl+C to stop)...");

    loop {
        tokio::select! {
            Some(result) = stream.next() => {
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
    }
}
