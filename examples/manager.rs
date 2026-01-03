/**
 * Multi-Device Manager Example
 *
 * This example demonstrates how to manage multiple Tuya devices using a single Manager.
 * It includes adding devices, setting up a global event listener, and interacting with devices.
 *
 * Author: 3735943886
 */
use rustuya::sync::Manager;
use std::{thread, time};

fn main() {
    // 1. Maximize FD limit (Recommended for Unix-like systems when managing many devices)
    let _ = Manager::maximize_fd_limit();

    // 2. Initialize Manager
    let manager = Manager::new();

    // 2. Define devices to manage
    // Replace with actual device ID, IP address, local key, and protocol version.
    let device_configs = vec![
        ("DEVICE_ID_1", "ADDRESS_1", "DEVICE_KEY_1", "VER_1"),
        ("DEVICE_ID_2", "ADDRESS_2", "DEVICE_KEY_2", "VER_2"),
        ("DEVICE_ID_3", "ADDRESS_3", "DEVICE_KEY_3", "VER_3"),
        ("DEVICE_ID_4", "ADDRESS_4", "DEVICE_KEY_4", "VER_4"),
    ];

    // 3. Add devices to the manager
    for (id, addr, key, ver) in &device_configs {
        if let Err(e) = manager.add(id, addr, key, *ver) {
            eprintln!("Failed to add device {}: {}", id, e);
        }
    }

    // 4. Create a global event listener
    let receiver = manager.listener();

    // 5. Start listening loop in a background thread
    let num_devices = device_configs.len();
    thread::spawn(move || {
        println!("Listening for events from {} devices...", num_devices);
        loop {
            match receiver.recv() {
                Ok(event) => {
                    // Output the received message payload if it's a valid string
                    if let Some(payload) = event.message.payload_as_string() {
                        println!("--- Received Message ---");
                        println!("Device ID: {}", event.device_id);
                        println!("Payload:   {}", payload);
                        println!("------------------------");
                    }
                }
                Err(e) => {
                    eprintln!("Listener error: {}", e);
                    break;
                }
            }
        }
    });

    // 6. Send status request to all devices
    println!("--- Sending Status Requests ---");
    for (id, _, _, _) in &device_configs {
        if let Some(device) = manager.get(id) {
            println!("Requesting status for: {}", id);
            device.status();
            thread::sleep(time::Duration::from_secs(1));
        }
    }
    println!("-------------------------------");

    // 7. Keep the main thread alive to receive events
    thread::sleep(time::Duration::from_secs(30));
    println!("Example finished.");
}
