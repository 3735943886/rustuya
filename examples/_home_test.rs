use rustuya::sync::Device;

fn main() {
    // 이 예제는 tokio 없이 일반 main에서 실행됩니다.
    println!("[INFO] Starting Synchronous Tuya Test...");

    // 2. Device 동기 래퍼 사용
    let device_id = "ebed83c21d73b95055nsc5";
    let local_key = "];#=gT4'1:Ph8rc_";

    println!("[INFO] Connecting to device {} (sync)...", device_id);

    // 비동기와 동일한 인터페이스: Device::new 또는 Device::builder()...run()
    let device = Device::builder(device_id, local_key).address("Auto").run();

    // 3. 상태 업데이트 및 값 설정 (동기 방식)
    println!("[INFO] Requesting status...");
    match device.status() {
        Ok(Some(res)) => println!("[SUCCESS] Status result: {}", res),
        Ok(None) => println!("[SUCCESS] Status sent (no response yet)"),
        Err(e) => println!("[ERROR] Status failed: {:?}", e),
    }

    println!("[INFO] Setting value (sync)...");
    match device.set_value(1, true) {
        Ok(Some(res)) => println!("[SUCCESS] SetValue result: {}", res),
        Ok(None) => println!("[SUCCESS] SetValue sent (no response yet)"),
        Err(e) => println!("[ERROR] SetValue failed: {:?}", e),
    }

    println!("[INFO] Test finished. Cleaning up...");
}
