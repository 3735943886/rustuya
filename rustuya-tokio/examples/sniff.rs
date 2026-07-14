//! Raw diagnostic — hex-dump every discovery datagram, no parsing by the driver.
//!
//! Shows (a) whether announcements are even reaching this host (a socket/network
//! question, separate from decode) and (b) their exact on-wire bytes. Paste the
//! hex back to turn a real announcement into a regression fixture — the
//! authoritative check a self-crafted test can't be.
//!
//! ```text
//! cargo run --example sniff -- [seconds]
//! ```

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use rustuya_tokio::{Result, TuyaError};

#[tokio::main]
async fn main() -> Result<()> {
    let secs: u64 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(15);
    println!("sniffing ports 6666/6667/7000 for {secs}s (raw hex of each datagram)...");

    // One bound socket per port; each read task prints what it gets. socket2 for
    // SO_REUSEADDR/REUSEPORT so this coexists with a running Discovery/other tools.
    let mut tasks = Vec::new();
    for port in [6666u16, 6667, 7000] {
        let sock = match bind_recv(port) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("bind udp/{port} failed: {e}");
                continue;
            }
        };
        tasks.push(tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            loop {
                match sock.recv_from(&mut buf).await {
                    Ok((n, from)) => {
                        println!("\n[{port}] {n} bytes from {from}");
                        println!("  hex: {}", to_hex(&buf[..n]));
                        println!("  ascii: {}", to_ascii(&buf[..n]));
                    }
                    Err(e) => {
                        eprintln!("[{port}] recv error: {e}");
                        break;
                    }
                }
            }
        }));
    }
    if tasks.is_empty() {
        return Err(TuyaError::Config("no discovery port could be bound"));
    }

    tokio::time::sleep(Duration::from_secs(secs)).await;
    for t in tasks {
        t.abort();
    }
    println!("\ndone.");
    Ok(())
}

/// Bind a UDP socket for receiving broadcasts on `port`, shareable with other
/// sockets/processes (mirrors the driver's own `bind_recv`).
fn bind_recv(port: u16) -> std::io::Result<tokio::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    #[cfg(unix)]
    sock.set_reuse_port(true)?;
    sock.set_broadcast(true)?;
    sock.set_nonblocking(true)?;
    sock.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)).into())?;
    tokio::net::UdpSocket::from_std(sock.into())
}

/// Lowercase hex, space-separated per byte — paste-ready for a test fixture.
fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ")
}

/// Printable ASCII with non-printables shown as `.` (to eyeball the JSON).
fn to_ascii(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' })
        .collect()
}
