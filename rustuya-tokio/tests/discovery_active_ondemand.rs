//! End-to-end test for the **on-demand** active probe (no perpetual beat) and its
//! **single-flight** coalescing.
//!
//! A tiny "device" binds the v3.5 probe port (7000) and, each time it hears a
//! probe, replies with an announcement to the discovery's receive port — exactly
//! the active elicitation an active-only device needs. Two scenarios, run
//! sequentially in one test so they never contend for udp/7000:
//!
//! 1. `find()` on a cache miss fires one probe that elicits the reply and resolves
//!    (proves active is actually triggered on demand, not perpetually).
//! 2. Many concurrent `find()`s for the same id collapse to a *handful* of probes,
//!    not one per call (proves the batch-drain single-flight — the 1000-builder
//!    race we designed against).
//!
//! Deterministic: `find` either resolves (probe worked) or times out (fails);
//! probe counting uses an atomic asserted against a coalescing bound, never a
//! sleep-derived number.

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

use rustuya_core::{frame, CommandType};
use rustuya_tokio::Discovery;

const PROBE_PORT: u16 = 7000; // the v3.5 probe port the "device" listens on
const DISCO_PORT: u16 = 56674; // where the discovery receives announcements

fn announcement(id: &str, ip: &str) -> Vec<u8> {
    let json = format!(r#"{{"gwId":"{id}","ip":"{ip}","version":"3.3"}}"#);
    frame::pack_55aa(0, CommandType::UdpNew as u32, json.as_bytes(), frame::Integrity::Crc32)
}

/// Bind 0.0.0.0:7000 (limited-broadcast reception) with SO_BROADCAST/REUSEADDR.
fn probe_listener() -> std::io::Result<std::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    sock.set_broadcast(true)?;
    sock.set_nonblocking(true)?;
    sock.bind(&std::net::SocketAddr::from((Ipv4Addr::UNSPECIFIED, PROBE_PORT)).into())?;
    Ok(sock.into())
}

/// Mock device: reply to every probe with `id`'s announcement, counting probes.
fn spawn_responder(id: &'static str) -> std::io::Result<(Arc<AtomicU32>, JoinHandle<()>)> {
    let sock = UdpSocket::from_std(probe_listener()?)?;
    let count = Arc::new(AtomicU32::new(0));
    let c = count.clone();
    let h = tokio::spawn(async move {
        let reply = announcement(id, "127.0.0.1");
        let out = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        let mut buf = [0u8; 2048];
        while sock.recv_from(&mut buf).await.is_ok() {
            c.fetch_add(1, Ordering::SeqCst);
            let _ = out.send_to(&reply, ("127.0.0.1", DISCO_PORT)).await;
        }
    });
    Ok((count, h))
}

#[tokio::test]
async fn on_demand_active_probe_fires_and_coalesces() {
    // --- Scenario 1: a single find fires one on-demand probe and resolves. ---
    const ID1: &str = "ondemand0000000000001a";
    let Ok((_probes1, resp1)) = spawn_responder(ID1) else {
        eprintln!("skip: could not bind udp/7000 (in use)");
        return;
    };

    let disco1 = Discovery::builder()
        .ports(vec![DISCO_PORT])
        .active(true) // active allowed — but only fires on demand
        .build()
        .expect("bind discovery");

    let info = disco1
        .find(ID1, Duration::from_secs(3))
        .await
        .expect("resolved via an on-demand active probe");
    assert_eq!(info.id, ID1);
    assert_eq!(info.ip, "127.0.0.1".parse::<std::net::IpAddr>().unwrap());

    disco1.close().await;
    resp1.abort(); // free udp/7000 before scenario 2 rebinds it
    let _ = resp1.await;

    // --- Scenario 2: 50 concurrent finds coalesce to a handful of probes. ---
    const ID2: &str = "coalesce0000000000001a";
    let (probes2, resp2) = spawn_responder(ID2).expect("rebind udp/7000");

    let disco2 = Discovery::builder()
        .ports(vec![DISCO_PORT])
        .active(true)
        .build()
        .expect("bind discovery");

    let tasks: Vec<_> = (0..50)
        .map(|_| {
            let d = disco2.clone();
            tokio::spawn(async move { d.find(ID2, Duration::from_secs(3)).await })
        })
        .collect();
    for t in tasks {
        t.await.unwrap().expect("each concurrent find resolves");
    }

    let n = probes2.load(Ordering::SeqCst);
    assert!(n >= 1, "at least one probe fired");
    assert!(n <= 10, "50 finds coalesced to {n} probes (not one per call)");

    disco2.close().await;
    resp2.abort();
    let _ = resp2.await;
}
