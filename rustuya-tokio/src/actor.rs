//! The per-device driver task: a thin tokio loop over the pure `rustuya-core`
//! [`Device`] FSM.
//!
//! The loop is the canonical sans-I/O driver shape (MILESTONES D1, "poll-split"):
//!
//! 1. **Dial** whenever the FSM [`wants_connect`](Device::wants_connect) — the
//!    core owns *whether* and *when* (backoff); the driver only opens the socket
//!    and reports [`Input::Connected`] / [`Input::ConnectFailed`].
//! 2. **Arm one timer** at the FSM's single [`poll_timeout`](Device::poll_timeout)
//!    deadline (backoff / heartbeat / idle / handshake — the core already merged
//!    them into one).
//! 3. **`select!`** over {a queued command, socket-readable, that timer} and feed
//!    the matching `handle_*`.
//! 4. **Settle**: drain [`poll_transmit`](Device::poll_transmit) to the socket and
//!    [`poll_event`](Device::poll_event) to the waiters / listener bus.
//!
//! No protocol decisions live here. The clock and the RNG are the only things the
//! driver injects — a `StdRng` (Send, OS-seeded) so every IV/nonce the core emits
//! stays unique, and a monotonic `tokio::time::Instant` base for `now`.

use std::collections::VecDeque;
use std::time::Duration as StdDuration;

use rand::rngs::StdRng;
use rand::SeedableRng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tokio::time::{sleep_until, timeout, Instant as TokioInstant};

use rustuya_core::device::{Config as CoreConfig, Device, Event, Input};
use rustuya_core::json::Value;
use rustuya_core::message::Message;
use rustuya_core::time::Instant as CoreInstant;
use rustuya_core::{CommandType, CoreError};

use crate::error::{Result, TuyaError};

/// A command handed from a [`Device`](crate::Device) handle to its actor task.
pub(crate) enum Cmd {
    /// Send a protocol command and complete `resp` with the next matching response.
    /// `cid` addresses a gateway sub-device; `None` addresses the device itself.
    Request {
        cmd: CommandType,
        data: Option<Value>,
        cid: Option<String>,
        resp: oneshot::Sender<Result<Message>>,
    },
    /// (Re)connect now: cancel any backoff wait and revive a terminal device.
    /// Fed by an explicit `connect_now()` or by the discovery rewake forwarder —
    /// both are the core's `Input::ConnectNow`. `addr` carries a freshly-discovered
    /// dial target (`Some` from the rewake forwarder when the device re-announces a
    /// possibly-changed IP); `None` (explicit `connect_now`) keeps the current one.
    ConnectNow { addr: Option<String> },
    /// Graceful shutdown: fail any in-flight waiters and exit the task.
    Close,
}

/// Everything the actor needs to run one device, moved in at spawn time.
pub(crate) struct ActorConfig {
    pub core: CoreConfig,
    pub addr: String,
    pub connect_timeout: StdDuration,
    /// Demand signal to the linked discovery: pinged on a failed dial so an
    /// active-only device (or one that moved IP) gets re-elicited. `None` when no
    /// discovery is linked. Coalesced at the discovery end (single-flight).
    pub want_scan: Option<mpsc::Sender<()>>,
}

/// Convert the driver's monotonic clock into the core's injected `now`.
#[inline]
fn now_since(base: TokioInstant) -> CoreInstant {
    CoreInstant::from_millis(base.elapsed().as_millis() as u64)
}

/// Wall-clock seconds the core stamps into request envelopes (the `t` field).
fn unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The channels the actor publishes out on, grouped so `settle`/`dispatch_events`
/// take one value instead of a growing argument list.
struct Sinks {
    /// The lossless push/response bus feeding every [`Listener`](crate::Listener).
    bcast: broadcast::Sender<Message>,
    /// Connection-up state feeding `is_connected` / `wait_connected`.
    conn: watch::Sender<bool>,
    /// The last authentication failure (wrong key / version), or `None` while the
    /// connection is healthy — so `wait_connected` can report *why* it won't come
    /// up instead of just timing out (the 0.3 "key or version" diagnostic).
    autherr: watch::Sender<Option<CoreError>>,
}

/// The actor entry point. Runs until every command sender is dropped or a
/// [`Cmd::Close`] arrives.
pub(crate) async fn run(
    acfg: ActorConfig,
    mut cmd_rx: mpsc::Receiver<Cmd>,
    bcast_tx: broadcast::Sender<Message>,
    conn_tx: watch::Sender<bool>,
    autherr_tx: watch::Sender<Option<CoreError>>,
) {
    let ActorConfig {
        core,
        mut addr,
        connect_timeout,
        want_scan,
    } = acfg;

    let sinks = Sinks { bcast: bcast_tx, conn: conn_tx, autherr: autherr_tx };
    let mut fsm = Device::new(core);
    // A Send CSPRNG (ChaCha), seeded from the OS. One instance for the task's
    // lifetime is fine: its period dwarfs any device's frame count, and pinning
    // it here keeps the actor future `Send` (a `ThreadRng` would not be).
    let mut rng = StdRng::from_os_rng();
    let base = TokioInstant::now();

    let mut stream: Option<TcpStream> = None;
    let mut waiters: VecDeque<oneshot::Sender<Result<Message>>> = VecDeque::new();
    let mut rbuf = vec![0u8; 8192];

    loop {
        // (A) Dial when the core asks. The result — success or failure — is just
        //     another input; the core decides what happens next (handshake, or a
        //     backoff timer).
        if fsm.wants_connect() {
            match timeout(connect_timeout, TcpStream::connect(&addr)).await {
                Ok(Ok(s)) => {
                    let _ = s.set_nodelay(true);
                    stream = Some(s);
                    fsm.handle_input(Input::Connected, now_since(base), &mut rng);
                }
                Ok(Err(e)) => {
                    log::debug!("connect {addr} failed: {e}");
                    stream = None;
                    fsm.handle_input(Input::ConnectFailed, now_since(base), &mut rng);
                    // Ask discovery to re-elicit: the address may be stale, or this
                    // is an active-only device passive can't hear. Coalesced there.
                    if let Some(w) = &want_scan {
                        let _ = w.try_send(());
                    }
                }
                Err(_) => {
                    log::debug!("connect {addr} timed out");
                    stream = None;
                    fsm.handle_input(Input::ConnectFailed, now_since(base), &mut rng);
                    if let Some(w) = &want_scan {
                        let _ = w.try_send(());
                    }
                }
            }
            settle(&mut fsm, &mut stream, &mut waiters, &sinks, base, &mut rng).await;
            continue;
        }

        // (B) One timer at the single next deadline (D2). `None` disables it.
        let deadline =
            fsm.poll_timeout().map(|d| base + StdDuration::from_millis(d.as_millis()));

        // (C) Whichever fires first drives the FSM.
        tokio::select! {
            cmd = cmd_rx.recv() => match cmd {
                Some(Cmd::Request { cmd, data, cid, resp }) => {
                    if fsm.is_connected() {
                        let t = unix_secs();
                        waiters.push_back(resp);
                        // `cid` is owned here for the duration of this call, so the
                        // core can borrow it — no per-request allocation in the FSM.
                        let input = Input::Send { cmd, data, cid: cid.as_deref(), t };
                        fsm.handle_input(input, now_since(base), &mut rng);
                    } else {
                        // Fail fast rather than queue into a socket that isn't up:
                        // the handle already waited for `connected` before sending,
                        // so this only trips on a connect/drop race.
                        let _ = resp.send(Err(TuyaError::Core(CoreError::NotConnected)));
                    }
                }
                // (Re)connect now: cancel backoff / revive a terminal device. A
                // rewake may carry a freshly-discovered address — adopt it so an
                // IP change (DHCP renewal, etc.) redials the *new* target rather
                // than the stale one fixed at spawn.
                Some(Cmd::ConnectNow { addr: new_addr }) => {
                    if let Some(a) = new_addr {
                        addr = a;
                    }
                    fsm.handle_input(Input::ConnectNow, now_since(base), &mut rng);
                }
                // All senders dropped, or an explicit Close: shut the task down.
                Some(Cmd::Close) | None => {
                    for w in waiters.drain(..) {
                        let _ = w.send(Err(TuyaError::Closed));
                    }
                    let _ = sinks.conn.send(false);
                    return;
                }
            },
            r = read_some(&mut stream, &mut rbuf), if stream.is_some() => match r {
                Ok(0) => fsm.handle_input(Input::Closed, now_since(base), &mut rng), // peer EOF
                Ok(n) => fsm.handle_input(Input::Received(&rbuf[..n]), now_since(base), &mut rng),
                Err(e) => {
                    log::debug!("read error: {e}");
                    fsm.handle_input(Input::Closed, now_since(base), &mut rng);
                }
            },
            _ = sleep_until(deadline.unwrap_or_else(TokioInstant::now)), if deadline.is_some() => {
                fsm.handle_timeout(now_since(base), &mut rng);
            }
        }

        settle(&mut fsm, &mut stream, &mut waiters, &sinks, base, &mut rng).await;
    }
}

/// One socket read into `buf`. Split out so the `select!` precondition
/// (`if stream.is_some()`) gates the `unwrap`.
async fn read_some(stream: &mut Option<TcpStream>, buf: &mut [u8]) -> std::io::Result<usize> {
    stream.as_mut().expect("guarded by `if stream.is_some()`").read(buf).await
}

/// Push everything the FSM produced out to the world: bytes to the socket, events
/// to the waiters and the listener bus. Re-runs once if a write fails (feeding the
/// core `Closed`, which enqueues `Disconnected` for us to dispatch), so the loop
/// runs at most twice and always leaves the FSM's queues empty.
async fn settle(
    fsm: &mut Device,
    stream: &mut Option<TcpStream>,
    waiters: &mut VecDeque<oneshot::Sender<Result<Message>>>,
    sinks: &Sinks,
    base: TokioInstant,
    rng: &mut StdRng,
) {
    loop {
        // Bytes out. A write failure is just another `Closed` input to the core.
        if let Err(e) = flush_tx(fsm, stream).await {
            log::debug!("write error: {e}");
            *stream = None;
            fsm.handle_input(Input::Closed, now_since(base), rng);
            // The Closed produced a Disconnected event; dispatch it next turn.
            continue;
        }
        // Events out. If the core tore the connection down, drop the socket so the
        // next dial gets a fresh one.
        if dispatch_events(fsm, waiters, sinks) {
            *stream = None;
        }
        return;
    }
}

/// Drain `poll_transmit` to the socket. Errors surface for the `Closed` re-feed.
async fn flush_tx(fsm: &mut Device, stream: &mut Option<TcpStream>) -> std::io::Result<()> {
    while let Some(bytes) = fsm.poll_transmit() {
        // No socket to write to (torn down mid-drain) → drop the bytes; the core
        // re-establishes state on the next connect.
        if let Some(s) = stream.as_mut() {
            s.write_all(&bytes).await?;
        }
    }
    Ok(())
}

/// Drain `poll_event`, routing each to the response waiters and the listener bus.
/// Returns `true` if a `Disconnected` was seen (the connection was torn down).
fn dispatch_events(
    fsm: &mut Device,
    waiters: &mut VecDeque<oneshot::Sender<Result<Message>>>,
    sinks: &Sinks,
) -> bool {
    let mut tore_down = false;
    while let Some(ev) = fsm.poll_event() {
        match ev {
            Event::Ready => {
                let _ = sinks.conn.send(true);
                // A healthy connection clears any stale auth-failure diagnostic.
                let _ = sinks.autherr.send(None);
            }
            Event::Response(msg) => {
                // Every response also feeds the listener bus (lossless attach is
                // the listener's concern; here we only fan out).
                let _ = sinks.bcast.send(msg.clone());
                deliver_to_waiter(waiters, msg);
            }
            Event::Disconnected => {
                tore_down = true;
                let _ = sinks.conn.send(false);
                for w in waiters.drain(..) {
                    let _ = w.send(Err(TuyaError::Disconnected));
                }
            }
            Event::ProtocolError(e) => {
                if e.is_auth_failure() {
                    // A CRC/HMAC/GCM failure means the payload didn't authenticate
                    // — almost always a wrong local key or protocol version. Surface
                    // it (0.3's ERR_KEY_OR_VER): publish it so `wait_connected`
                    // reports the reason instead of a bare timeout, warn-log it, and
                    // fail the oldest in-flight request with the real cause (this
                    // `ProtocolError` precedes the vaguer `Disconnected`).
                    log::warn!(
                        "authentication failed ({e}): likely a wrong local key or protocol version"
                    );
                    let _ = sinks.autherr.send(Some(e.clone()));
                    while let Some(w) = waiters.pop_front() {
                        if w.send(Err(TuyaError::Core(e.clone()))).is_ok() {
                            break;
                        }
                    }
                } else {
                    log::debug!("protocol error: {e}");
                }
            }
        }
    }
    tore_down
}

/// Complete the oldest still-live waiter with `msg`. Waiters whose receiver has
/// gone (a timed-out `request`) are popped and skipped, so a stale slot can't
/// swallow a live response. With no waiter the message was an unsolicited push —
/// it already went to the listener bus.
///
/// This is the documented fire-and-forget correlation (see [`crate::Device`]):
/// the Tuya LAN protocol carries no request/response token, so responses match
/// pending requests in FIFO order, not by identity.
fn deliver_to_waiter(waiters: &mut VecDeque<oneshot::Sender<Result<Message>>>, msg: Message) {
    while let Some(w) = waiters.pop_front() {
        match w.send(Ok(msg.clone())) {
            Ok(()) => return,   // delivered to a live caller
            Err(_) => continue, // receiver gone — try the next
        }
    }
}
