/**
 * Basic Status Stream Example
 *
 * This example demonstrates how to listen for real-time status updates and
 * other messages from a single Tuya device using an asynchronous stream.
 *
 * Author: 3735943886
 */
use rustuya::DeviceBuilder;
use tokio_stream::StreamExt;

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace")).init();
    // 1. Basic Configuration
    // Replace with actual device ID, IP address, local key, and protocol version.
    //let device_id = "ebcc8bf871a0da3d7dpgbg";
    //let local_key = "SlfZ.(EAH:Qb/)kW"; // or "192.168.1.xx"
    let device_id = "ebed83c21d73b95055nsc5"; // 아바토
    let local_key = "];#=gT4'1:Ph8rc_";
    let address = "10.10.240.42";
    let version = "3.5";

    // 2. Initialize Device
    let device = DeviceBuilder::new(device_id, local_key)
        .address(address)
        .version(version)
        .build();

    println!("--- Rustuya Basic Stream Example ---");
    println!("Listening for messages from: {device_id}");

    // 3. Get message stream
    let stream = device.listener();
    tokio::pin!(stream);

    // 4. Send initial status query to check seqno matching
    println!("Sending status query...");
    device.status().await;

    // 5. Continuously read messages from the stream
    while let Some(msg) = stream.next().await {
        match msg {
            Ok(m) => {
                println!("--- Received Message ---");
                println!("SeqNo:   {}", m.seqno);
                println!("Command: 0x{:02X}", m.cmd);
                if let Ok(json) = String::from_utf8(m.payload) {
                    println!("Payload: {json}");
                }
                println!("------------------------");
            }
            Err(e) => eprintln!("Stream error: {e}"),
        }
    }
}
