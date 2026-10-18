//! Address resolution uses the same actor, backoff, limiter and shutdown as TCP.
use rustuya_core::{CommandType, frame};
use rustuya_tokio::{ConnectLimiter, ConnectionState, Device, Discovery, Version};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, UdpSocket};

const ID: &str = "addressless-test";
const KEY: &[u8; 16] = b"0123456789abcdef";

fn discovery() -> (Discovery, u16) {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    drop(socket);
    (
        Discovery::builder()
            .ports(vec![port])
            .active(false)
            .build()
            .unwrap(),
        port,
    )
}

async fn announce(disco: &Discovery, port: u16, version: &str) {
    announce_optional(disco, port, Some(version)).await;
}

async fn announce_optional(disco: &Discovery, port: u16, version: Option<&str>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut payload = serde_json::json!({"gwId": ID, "ip": "127.0.0.1"});
    if let Some(version) = version {
        payload["version"] = serde_json::json!(version);
    }
    let packet = frame::pack_55aa(
        0,
        CommandType::UdpNew as u32,
        payload.to_string().as_bytes(),
        frame::Integrity::Crc32,
    );
    let expected = version.and_then(Version::parse);
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            socket.send_to(&packet, ("127.0.0.1", port)).await.unwrap();
            if disco.get(ID).is_some_and(|info| info.version == expected) {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("announcement cached with its expected version");
}

async fn disconnected(dev: &Device) {
    let mut state = dev.watch_connection_state();
    tokio::time::timeout(Duration::from_secs(2), async {
        while *state.borrow_and_update() != ConnectionState::Disconnected {
            state.changed().await.unwrap();
        }
    })
    .await
    .expect("first failed attempt is visible");
}

#[tokio::test]
async fn late_discovery_cancels_backoff_and_connects_without_readding() {
    let (disco, port) = discovery();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let limiter = ConnectLimiter::new(1);
    let dev = Device::builder(ID, *KEY)
        .rediscover(&disco)
        .version(Version::Auto)
        .port(listener.local_addr().unwrap().port())
        .connect_limiter(&limiter)
        .backoff(
            Duration::from_secs(3600),
            Duration::from_secs(3600),
            Duration::ZERO,
        )
        .connect()
        .unwrap();
    disconnected(&dev).await;
    assert_eq!(
        limiter.available(),
        1,
        "unresolved devices cannot hold dial permits"
    );
    announce(&disco, port, "3.3").await;
    dev.wait_connected(Duration::from_secs(3)).await.unwrap();
    assert_eq!(
        *dev.watch_connection_state().borrow(),
        ConnectionState::Connected
    );
    let (_socket, _) = listener.accept().await.unwrap();
    dev.close().await;
    assert_eq!(limiter.available(), 1);
    disco.close().await;
}

#[tokio::test]
async fn warm_cache_resolves_address_and_version_without_another_announcement() {
    let (disco, port) = discovery();
    announce(&disco, port, "3.4").await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dev = Device::builder(ID, *KEY)
        .rediscover(&disco)
        .version(Version::Auto)
        .port(listener.local_addr().unwrap().port())
        .connect()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut header = [0; 16];
        socket.read_exact(&mut header).await.unwrap();
        assert_eq!(
            u32::from_be_bytes(header[8..12].try_into().unwrap()),
            CommandType::SessKeyNegStart as u32,
            "Auto must adopt the cached version before the first connection"
        );
        assert!(
            !dev.is_connected(),
            "3.4 is not connected until the handshake completes"
        );
    })
    .await
    .unwrap();
    dev.close().await;
    disco.close().await;
}

#[tokio::test]
async fn repeated_discovery_misses_do_not_repeat_offline_notifications_and_can_close() {
    let (disco, _) = discovery();
    let dev = Device::builder(ID, *KEY)
        .rediscover(&disco)
        .backoff(
            Duration::from_millis(10),
            Duration::from_millis(20),
            Duration::ZERO,
        )
        .connect()
        .unwrap();
    disconnected(&dev).await;
    // Subscribe after failure: the current value must still expose it.
    let mut state = dev.watch_connection_state();
    assert_eq!(*state.borrow_and_update(), ConnectionState::Disconnected);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), state.changed())
            .await
            .is_err(),
        "backoff retries must not flood offline notifications"
    );
    tokio::time::timeout(Duration::from_secs(1), dev.close())
        .await
        .unwrap();
    disco.close().await;
}

#[tokio::test]
async fn first_tcp_failure_is_visible_even_if_the_device_was_never_connected() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let dev = Device::builder(ID, *KEY)
        .address("127.0.0.1")
        .port(port)
        .version(Version::V3_3)
        .connect()
        .unwrap();
    disconnected(&dev).await;
    dev.close().await;
}

#[tokio::test]
async fn known_ip_auto_waits_for_a_concrete_version_before_dialing() {
    let (disco, port) = discovery();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let limiter = ConnectLimiter::new(1);
    let dev = Device::builder(ID, *KEY)
        .address("127.0.0.1")
        .port(listener.local_addr().unwrap().port())
        .version(Version::Auto)
        .rediscover(&disco)
        .connect_limiter(&limiter)
        .backoff(
            Duration::from_secs(3600),
            Duration::from_secs(3600),
            Duration::ZERO,
        )
        .connect()
        .unwrap();
    disconnected(&dev).await;
    assert_eq!(
        limiter.available(),
        1,
        "version resolution cannot hold a dial permit"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err(),
        "a configured IP must not bypass Auto version resolution"
    );
    announce_optional(&disco, port, None).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err(),
        "a versionless announcement must not permit dialing"
    );
    assert!(!dev.is_connected());
    assert_eq!(
        *dev.watch_connection_state().borrow(),
        ConnectionState::Disconnected
    );
    assert_eq!(limiter.available(), 1);

    announce(&disco, port, "3.4").await;
    tokio::time::timeout(Duration::from_secs(3), async {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut header = [0; 16];
        socket.read_exact(&mut header).await.unwrap();
        assert_eq!(
            u32::from_be_bytes(header[8..12].try_into().unwrap()),
            CommandType::SessKeyNegStart as u32,
            "late discovery must wake the same actor and select the 3.4 handshake"
        );
        assert!(
            !dev.is_connected(),
            "TCP alone cannot mark a 3.4 session connected"
        );
    })
    .await
    .unwrap();
    dev.close().await;
    disco.close().await;
}

#[tokio::test]
async fn missing_ip_and_auto_require_both_fields_from_discovery() {
    let (disco, port) = discovery();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    announce_optional(&disco, port, None).await;
    let dev = Device::builder(ID, *KEY)
        .port(listener.local_addr().unwrap().port())
        .version(Version::Auto)
        .rediscover(&disco)
        .backoff(
            Duration::from_millis(10),
            Duration::from_millis(20),
            Duration::ZERO,
        )
        .connect()
        .unwrap();
    disconnected(&dev).await;
    let mut state = dev.watch_connection_state();
    state.borrow_and_update();
    assert!(
        tokio::time::timeout(Duration::from_millis(100), listener.accept())
            .await
            .is_err(),
        "resolving only the address cannot establish TCP"
    );
    assert!(
        !state.has_changed().unwrap(),
        "retries cannot flood offline notifications"
    );
    announce(&disco, port, "3.3").await;
    dev.wait_connected(Duration::from_secs(3)).await.unwrap();
    let (_socket, _) = listener.accept().await.unwrap();
    dev.close().await;
    disco.close().await;
}

#[tokio::test]
async fn auto_without_discovery_is_rejected_even_with_a_configured_ip() {
    let err = Device::builder(ID, *KEY)
        .address("127.0.0.1")
        .version(Version::Auto)
        .connect()
        .expect_err("Auto cannot resolve without discovery");
    assert!(matches!(err, rustuya_tokio::TuyaError::Config(_)));
}

#[tokio::test]
async fn explicit_version_works_without_a_discovery_announcement() {
    let (disco, _) = discovery();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dev = Device::builder(ID, *KEY)
        .address("127.0.0.1")
        .port(listener.local_addr().unwrap().port())
        .version(Version::V3_3)
        .rediscover(&disco)
        .connect()
        .unwrap();
    dev.wait_connected(Duration::from_secs(3)).await.unwrap();
    let (_socket, _) = listener.accept().await.unwrap();
    dev.close().await;
    disco.close().await;
}
