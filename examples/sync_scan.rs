/**
 * Scanner Example (Sync Iterator)
 *
 * This example demonstrates how to use the synchronous scanner to find
 * Tuya devices on the local network in real-time using a standard iterator (Receiver).
 */
use rustuya::sync::Scanner;

fn main() {
    println!("--- Rustuya - Scanner (Sync) ---");
    println!("[INFO] Scanning the network for Tuya devices in real-time...");

    // 1. Get the global sync scanner instance
    let scanner = Scanner::get();

    // 2. Get a scan_stream (mpsc::Receiver) which acts as a synchronous iterator
    let stream = scanner.scan_stream();

    let mut count = 0;

    // 3. Process devices as they are discovered (blocking loop)
    // Receiver implements IntoIterator, so we can use it in a for loop
    for device in stream {
        count += 1;
        println!(
            "[{}] Found Device: ID={}, IP={}, Version={:?}",
            count, device.id, device.ip, device.version
        );
    }

    println!("[INFO] Scan finished. Total devices found: {count}");
}
