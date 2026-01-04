/**
 * Scanner Example (Async Stream)
 *
 * This example demonstrates how to use the asynchronous UDP scanner to find
 * Tuya devices on the local network in real-time using a Stream.
 *
 * Author: 3735943886
 */
use futures_util::StreamExt;
use rustuya::scanner::Scanner;

#[tokio::main]
async fn main() {
    println!("--- Rustuya - Scanner (Async) ---");
    println!("Scanning the network for Tuya devices in real-time...");

    // 1. Create a new scanner with a custom timeout
    let scanner = Scanner::new();

    // 2. Get a stream of discovery results
    let stream = scanner.scan_stream();
    tokio::pin!(stream);

    let mut count = 0;

    // 3. Process devices as they are discovered
    while let Some(device) = stream.next().await {
        count += 1;
        println!(
            "[{}] Found Device: ID={}, IP={}, Version={:?}",
            count, device.id, device.ip, device.version
        );
    }

    println!("Scan finished. Total devices found: {}", count);
}
