use rustuya::Device;

#[tokio::main]
async fn main() {
    // 이 예제는 tokio 런타임 위에서 비동기로 실행됩니다.
    println!("[INFO] Starting Asynchronous Tuya Test...");

    // 1. Device 비동기 코어 사용
    let id = "eb7ba8427911a8ccbda92w";
    let key = "GyFSITk>TL8?EBRK";

    println!("[INFO] Connecting to device {} (async)...", id);

    // 비동기 방식: Device::new 또는 Device::builder()...run()
    // run()은 즉시 Device 인스턴스를 반환하며 내부적으로 연결 태스크를 시작합니다.
    let device = Device::builder(id, key).address("Auto").run();

    // 2. 상태 업데이트 및 값 설정 (비동기 방식, .await 필요)
    println!("[INFO] Requesting status...");
    match device.status().await {
        Ok(Some(res)) => println!("[SUCCESS] Status result: {}", res),
        Ok(None) => println!("[SUCCESS] Status sent (no response yet)"),
        Err(e) => println!("[ERROR] Status failed: {:?}", e),
    }

    println!("[INFO] Setting value (async)...");
    match device.set_value(1, true).await {
        Ok(Some(res)) => println!("[SUCCESS] SetValue result: {}", res),
        Ok(None) => println!("[SUCCESS] SetValue sent (no response yet)"),
        Err(e) => println!("[ERROR] SetValue failed: {:?}", e),
    }

    println!("[INFO] Test finished. Cleaning up...");
}
