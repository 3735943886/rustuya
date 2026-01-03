/**
 * Status Stream Example
 *
 * This example demonstrates how to listen for real-time status updates and
 * other messages from a single Tuya device.
 *
 * Author: 3735943886
 */
use rustuya::sync::Device;

fn main() {
    // 1. Initialize Device
    // Replace with actual device ID, IP address, local key, and protocol version.
    let device = Device::new("DEVICE_ID", "ADDRESS", "DEVICE_KEY", "VERSION");
    println!("--- Rustuya Listen Example ---");

    // 2. Get message listener (mpsc::Receiver)
    let rx = device.listener();

    // 3. Continuously read messages from the receiver
    println!("Listening for messages... (Press Ctrl+C to stop)");
    while let Ok(msg) = rx.recv() {
        if let Some(payload_str) = msg.payload_as_string() {
            println!("Payload: {}", payload_str);
        }
    }
}
