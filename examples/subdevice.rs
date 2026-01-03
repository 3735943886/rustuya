/**
 * Basic Sub-Device Control Example
 *
 * This example demonstrates how to control a sub-device
 * that is connected via a Tuya Gateway, using the sub-device's CID.
 *
 * Author: 3735943886
 */
use rustuya::sync::Device;

fn main() {
    // 1. Gateway & Sub-Device Info
    let gateway_id = "GATEWAY_ID";
    let gateway_key = "GATEWAY_KEY";
    let gateway_ip = "ADDRESS";
    let gateway_ver = "VER";
    let sub_device_cid = "SUBDEVICE_CID"; // e.g., "a4c138..."

    println!("--- Rustuya Simple Gateway Control ---");

    // 2. Initialize Gateway
    let gateway = Device::new(gateway_id, gateway_ip, gateway_key, gateway_ver);

    // 3. Get Sub-Device
    let sub_dev = gateway.sub(sub_device_cid);

    println!(
        "Sending 'ON' command to sub-device ({}) via gateway...",
        sub_device_cid
    );

    // 4. Switch ON (DP 1 is usually power)
    sub_dev.set_value(1, true);

    println!("Done!");
}
