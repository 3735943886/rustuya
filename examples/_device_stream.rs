/**
 * Single Device Stream Example
 *
 * This example demonstrates how to listen to real-time events and status updates
 * from a single Tuya device.
 */
use futures_util::StreamExt;
use rustuya::DeviceBuilder;
use std::time::Duration;

#[tokio::main]
async fn main() {
    println!("--- Rustuya - Device Stream ---");

    // 1. Initialize Device (Using Office Light as an example)
    let id = "eb7ba8427911a8ccbda92w";
    let key = "GyFSITk>TL8?EBRK";
    let device = DeviceBuilder::new(id, key).address("Auto").build();

    println!("[INFO] Starting listener for device: {}", id);

    // 2. Get the event stream
    let stream = device.listener();
    tokio::pin!(stream);

    // 3. Process events in real-time
    println!("[INFO] Waiting for events (Press Ctrl+C to stop)...");

    let timeout = tokio::time::sleep(Duration::from_secs(60));
    tokio::pin!(timeout);

    loop {
        tokio::select! {
            Some(result) = stream.next() => {
                match result {
                    Ok(msg) => {
                        println!(
                            "[EVENT] Command: {:?}, Payload: {}",
                            msg.cmd,
                            msg.payload_as_string().unwrap_or_default()
                        );
                    }
                    Err(e) => {
                        eprintln!("[ERROR] Listener error: {}", e);
                    }
                }
            }
            _ = &mut timeout => {
                println!("[INFO] Example timeout reached. Exiting.");
                break;
            }
        }
    }
}
