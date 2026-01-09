/**
 * Scanner Example (Async Stream)
 *
 * This example demonstrates how to use the asynchronous UDP scanner to find
 * Tuya devices on the local network in real-time using a Stream.
 */
use futures_util::StreamExt;

use rustuya::Scanner;

#[tokio::main]
async fn main() {
    println!("--- Rustuya - Scanner (Async) ---");
    println!("[INFO] Scanning the network for Tuya devices in real-time...");

    // 1. Get a stream of discovery results directly from Scanner
    let stream = Scanner::scan_stream();
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

    println!("[INFO] Scan finished. Total devices found: {count}");
}
