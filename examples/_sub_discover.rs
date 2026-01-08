use rustuya::DeviceBuilder;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 로그 설정: RUST_LOG 환경변수가 없으면 기본적으로 info 레벨 출력
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    println!("--- Rustuya - Sub Discovery Debug Tool ---");

    //let id = "eb5176f91956a97b165dc5";
    //let key = "FGhe;!?GLh$vv9<c";
    let id = "eb3ff73bef776e4a1aay8r";
    let key = "c)H+2(TY@sY)e&5L";

    // 1. 디바이스 설정 및 빌드
    let device = DeviceBuilder::new(id, key).build();

    println!("[INFO] Target Device: {}", id);

    // 4. sub_discover 명령 전송
    println!("[PROCESS] Sending status command...");
    let ret = device.status().await?;
    println!("Response: {:?}", ret);

    println!("[PROCESS] Sending sub_discover command...");
    let ret = device.sub_discover().await?;
    println!("Response: {:?}", ret);
    Ok(())
}
