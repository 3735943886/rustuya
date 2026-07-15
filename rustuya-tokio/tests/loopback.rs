//! End-to-end driver test against a hand-rolled v3.3 "device" on loopback TCP.
//!
//! This exercises the *whole* driver path over real tokio sockets — dial, the
//! legacy (no-handshake) connect, `query()` encoding a `DpQuery`, the mock
//! device's framed reply, RX reassembly + decode in the core, and the reply
//! fanning out to the `listener()` bus. It is the from-scratch stand-in for the
//! `tuyamock` E2E gate until that mock is wired in (M1.7).

mod common;

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use rustuya_core::crypto::TuyaCipher;
use rustuya_core::{CommandType, frame};
use rustuya_tokio::{Device, Event, TuyaError, Version};

const KEY: &[u8; 16] = b"0123456789abcdef";
const ID: &str = "01234567890123456789ab";

/// Deterministically hold a mock connection open exactly as long as the driver
/// keeps it: block reading until the client half-closes (EOF), which the driver
/// does on `dev.close()`. Replaces a timing guess (`sleep(200ms)` hoping the reply
/// was read) with a real synchronization edge — no wall-clock in the test.
async fn wait_until_closed(sock: &mut tokio::net::TcpStream) {
    let mut sink = [0u8; 256];
    while let Ok(n) = sock.read(&mut sink).await {
        if n == 0 {
            break; // client closed the connection
        }
    }
}

/// Craft a realistic v3.3 device response: a 55AA/CRC-32 frame whose body is the
/// 4-byte return code (plaintext, outside the ECB) followed by the ECB-encrypted
/// JSON — exactly what a real device puts on the wire and what the core FSM
/// decodes with `has_retcode = true`.
fn v33_response(cmd: CommandType, json: &[u8]) -> Vec<u8> {
    let cipher = TuyaCipher::new(KEY).unwrap();
    let ct = cipher.ecb_encrypt(json).unwrap();
    let mut body = 0u32.to_be_bytes().to_vec(); // retcode 0
    body.extend_from_slice(&ct);
    frame::pack_55aa(1, cmd as u32, &body, frame::Integrity::Crc32)
}

/// Accept one connection, wait for the driver's request, reply once with `json`,
/// then hold the socket open until the driver closes it.
async fn serve_once(listener: TcpListener, json: &'static [u8]) {
    let (mut sock, _) = listener.accept().await.unwrap();
    let mut buf = [0u8; 4096];
    let n = sock.read(&mut buf).await.unwrap();
    assert!(n > 0, "device saw the request frame");
    let reply = v33_response(CommandType::DpQuery, json);
    sock.write_all(&reply).await.unwrap();
    wait_until_closed(&mut sock).await;
}

#[tokio::test]
async fn status_roundtrips_against_a_v33_device() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(serve_once(listener, br#"{"dps":{"1":true,"2":42}}"#));

    let dev = Device::builder(ID, *KEY)
        .address("127.0.0.1")
        .port(port)
        .version(Version::V3_3)
        .connect()
        .unwrap();

    let state = common::query_dps(&dev).await;
    assert_eq!(state["dps"]["1"], true);
    assert_eq!(state["dps"]["2"], 42);

    dev.close().await;
    server.await.unwrap();
}

#[tokio::test]
async fn set_value_encodes_a_control_and_reads_the_ack() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    // The device echoes an updated-state push as the "ack".
    let server = tokio::spawn(serve_once(listener, br#"{"dps":{"1":false}}"#));

    let dev = Device::builder(ID, *KEY)
        .address("127.0.0.1")
        .port(port)
        .version(Version::V3_3)
        .connect()
        .unwrap();

    // Fire the Control, then read the device's echoed-state "ack" off the listener.
    let mut events = dev.listener();
    dev.set_value(1, false).await.expect("set_value fires");
    let resp = common::recv_dps(&mut events, Duration::from_secs(2))
        .await
        .expect("the ack fanned out to the listener");
    assert_eq!(resp["dps"]["1"], false);

    dev.close().await;
    server.await.unwrap();
}

/// Mock the v3.4 device side of the session-key handshake: read the driver's
/// `SessKeyNegStart`, recover its local nonce, and reply with a valid
/// `SessKeyNegResp` (`remote_nonce || HMAC(local_nonce, key)`). Then read the
/// `SessKeyNegFinish` the driver sends, at which point the driver is Connected.
async fn serve_v34_handshake(listener: TcpListener) {
    use hmac::digest::KeyInit;
    use hmac::{Hmac, Mac};
    use rustuya_core::message::decode_message;
    use sha2::Sha256;

    let (mut sock, _) = listener.accept().await.unwrap();
    let mut buf = [0u8; 4096];

    // 1. SessKeyNegStart → local nonce (framed with the local key, no retcode).
    let n = sock.read(&mut buf).await.unwrap();
    let start = decode_message(Version::V3_4, &buf[..n], KEY, false).unwrap();
    let local_nonce = start.payload;

    // 2. Reply with remote_nonce || HMAC-SHA256(local_nonce, key), framed as a
    //    real device does: a 4-byte retcode sits in the 55AA body *outside* the
    //    ECB ciphertext (like tuyamock's pack_response), then HMAC framing.
    let remote_nonce = [7u8; 16];
    let mut mac = Hmac::<Sha256>::new_from_slice(KEY).unwrap();
    mac.update(&local_nonce);
    let mut reply = remote_nonce.to_vec();
    reply.extend_from_slice(&mac.finalize().into_bytes());
    let cipher = TuyaCipher::new(KEY).unwrap();
    let mut body = 0u32.to_be_bytes().to_vec(); // retcode 0
    body.extend_from_slice(&cipher.ecb_encrypt(&reply).unwrap());
    let wire = frame::pack_55aa(
        1,
        CommandType::SessKeyNegResp as u32,
        &body,
        frame::Integrity::Hmac(KEY),
    );
    sock.write_all(&wire).await.unwrap();

    // 3. Absorb the SessKeyNegFinish so the driver's write completes; the driver
    //    is now Connected. Then hold the socket open until the driver closes it.
    let _ = sock.read(&mut buf).await.unwrap();
    wait_until_closed(&mut sock).await;
}

#[tokio::test]
async fn v34_handshake_reaches_connected_over_real_sockets() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(serve_v34_handshake(listener));

    let dev = Device::builder(ID, *KEY)
        .address("127.0.0.1")
        .port(port)
        .version(Version::V3_4)
        .connect()
        .unwrap();

    // The driver pumps SessKeyNegStart → Resp → Finish through the FSM and only
    // signals `connected` once the handshake completes.
    dev.wait_connected(Duration::from_secs(2))
        .await
        .expect("handshake completes and the device connects");
    assert!(dev.is_connected());

    dev.close().await;
    server.await.unwrap();
}

#[tokio::test]
async fn listener_stream_yields_events_via_next() {
    use tokio_stream::StreamExt;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(serve_once(listener, br#"{"dps":{"5":"on"}}"#));

    let dev = Device::builder(ID, *KEY)
        .address("127.0.0.1")
        .port(port)
        .version(Version::V3_3)
        .connect()
        .unwrap();

    // Subscribe before any traffic so the bus retains the event for this stream.
    let mut events = dev.listener();
    dev.query().await.expect("query triggers a reply");

    // The reply also fans out to the listener bus; the `.next()` idiom (Stream impl)
    // delivers it as an Event.
    let ev = tokio::time::timeout(Duration::from_secs(2), events.next())
        .await
        .expect("an event within 2s")
        .expect("stream still open");
    let msg = match ev {
        Event::Frame(m) => m,
        Event::Lagged(n) => panic!("unexpected lag: {n}"),
    };
    let v: serde_json::Value = serde_json::from_slice(&msg.payload).unwrap();
    assert_eq!(v["dps"]["5"], "on");

    dev.close().await;
    server.await.unwrap();
}

#[tokio::test]
async fn sub_device_request_carries_the_cid_over_the_wire() {
    use rustuya_core::message::decode_message;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    // The device side: read the sub-device request, decode it, and assert the
    // envelope actually addresses the sub-device (proves cid threads driver →
    // core → wire), then reply so the call completes.
    let server = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 4096];
        let n = sock.read(&mut buf).await.unwrap();
        let req = decode_message(Version::V3_3, &buf[..n], KEY, false).unwrap();
        let env: serde_json::Value = serde_json::from_slice(&req.payload).unwrap();
        assert_eq!(
            env["cid"], "subchannel01",
            "request envelope carries the cid"
        );

        let reply = v33_response(CommandType::DpQuery, br#"{"dps":{"9":true}}"#);
        sock.write_all(&reply).await.unwrap();
        wait_until_closed(&mut sock).await;
    });

    let dev = Device::builder(ID, *KEY)
        .address("127.0.0.1")
        .port(port)
        .version(Version::V3_3)
        .connect()
        .unwrap();

    let mut events = dev.listener();
    dev.sub("subchannel01").query().await.expect("sub query fires");
    let state = common::recv_dps(&mut events, Duration::from_secs(2))
        .await
        .expect("sub-device reply on the listener");
    assert_eq!(state["dps"]["9"], true);

    dev.close().await;
    server.await.unwrap();
}

#[tokio::test]
async fn connect_requires_an_address() {
    let err = Device::builder(ID, *KEY)
        .connect()
        .expect_err("no address → error");
    assert!(matches!(err, TuyaError::Config(_)));
}

#[tokio::test]
async fn connect_rejects_a_bad_key_length() {
    let err = Device::builder(ID, b"tooshort".to_vec())
        .address("127.0.0.1")
        .connect()
        .expect_err("bad key → error");
    assert!(matches!(err, TuyaError::Config(_)));
}

#[tokio::test]
async fn query_on_an_unreachable_device_times_out() {
    // Port 1 (nothing listening): the dial fails, the FSM backs off, and the
    // fire never sees `connected`, so it times out rather than hanging.
    let dev = Device::builder(ID, *KEY)
        .address("127.0.0.1")
        .port(1)
        .version(Version::V3_3)
        .send_timeout(Duration::from_millis(300))
        .connect()
        .unwrap();

    let err = dev.query().await.expect_err("no device → error");
    assert!(matches!(err, TuyaError::Timeout), "got {err:?}");
    dev.close().await;
}
