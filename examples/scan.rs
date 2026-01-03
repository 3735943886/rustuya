/**
 * Scanner Example (Sync)
 *
 * This example demonstrates how to use the synchronous UDP scanner to find
 * Tuya devices on the local network and detect their protocol versions.
 *
 * Author: 3735943886
 */
use rustuya::sync::Scanner;

fn main() {
    // Initialize logger to see discovery details
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    println!("--- Rustuya - Scanner ---");
    println!("Scanning the network for Tuya devices...");

    // 1. Create a new scanner with a timeout of 18 seconds
    let scanner = Scanner::new();

    // 2. Perform the scan
    let _ = scanner.scan();
}
