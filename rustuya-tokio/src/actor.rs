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
//!    [`poll_event`](Device::poll_event) to the listener bus.
//!
//! No protocol decisions live here. The clock and the RNG are the only things the
//! driver injects — a `StdRng` (Send, OS-seeded) so every IV/nonce the core emits
//! stays unique, and a monotonic `tokio::time::Instant` base for `now`.

use std::time::Duration as StdDuration;

use rand::SeedableRng;
use rand::rngs::StdRng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{OwnedSemaphorePermit, broadcast, mpsc, watch};
use tokio::time::{Instant as TokioInstant, sleep_until, timeout};

use crate::ConnectLimiter;

use rustuya_core::device::{Config as CoreConfig, Device, Event, Input};
use rustuya_core::json::Value;
use rustuya_core::message::Message;
use rustuya_core::time::Instant as CoreInstant;
use rustuya_core::{CommandType, CoreError};

/// Formats arbitrary bytes for a log line: printable ASCII as-is, everything
/// else as `\xNN`. Bytes off a device are only *hoped* to be UTF-8 — when they
/// are not, that is precisely what needs reading — so `String::from_utf8_lossy`
/// is the wrong tool: it replaces every bad byte with the same U+FFFD and erases
/// the evidence. Truncated so one malformed frame cannot flood a log.
struct DebugBytes<'a>(&'a [u8]);

impl core::fmt::Debug for DebugBytes<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use core::fmt::Write as _;
        /// Enough to show a JSON envelope's shape, a version header, or the
        /// leading block of a misdecrypted payload.
        const MAX: usize = 160;
        let shown = &self.0[..self.0.len().min(MAX)];
        f.write_char('"')?;
        for &b in shown {
            match b {
                b'"' => f.write_str("\\\"")?,
                b'\\' => f.write_str("\\\\")?,
                0x20..=0x7e => f.write_char(char::from(b))?,
                _ => write!(f, "\\x{b:02x}")?,
            }
        }
        f.write_char('"')?;
        if self.0.len() > MAX {
            write!(f, "…(+{} bytes)", self.0.len() - MAX)?;
        }
        Ok(())
    }
}

/// A command handed from a [`Device`](crate::Device) handle to its actor task.
pub(crate) enum Cmd {
    /// Fire a protocol command at the device. `cid` addresses a gateway sub-device;
    /// `None` addresses the device itself. Fire-and-forget: the reply (if any) is
    /// fanned out to the listener bus, not correlated back to the caller.
    Fire {
        cmd: CommandType,
        data: Option<Value>,
        cid: Option<String>,
    },
    /// (Re)connect now: cancel any backoff wait and revive a terminal device.
    /// Fed by an explicit `connect_now()` or by the discovery rewake forwarder —
    /// both are the core's `Input::ConnectNow`. `addr` carries a freshly-discovered
    /// dial target (`Some` from the rewake forwarder when the device re-announces a
    /// possibly-changed IP); `None` (explicit `connect_now`) keeps the current one.
    ConnectNow { addr: Option<String> },
    /// Graceful shutdown: exit the task.
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
    /// Fleet-wide cap on simultaneous connection establishment, or `None` for no
    /// cap (the default). A permit is taken before each dial and released the
    /// moment the FSM leaves `is_establishing()`.
    pub connect_limiter: Option<ConnectLimiter>,
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
    /// The push/response bus feeding every [`Listener`](crate::Listener).
    bcast: broadcast::Sender<Message>,
    /// Latch of the device's current status frame (last non-empty frame), feeding
    /// [`watch_status`](crate::Device::watch_status). State, not an event: a slow
    /// consumer that only wants the latest value reads this instead of the lossy bus.
    status: watch::Sender<Option<Message>>,
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
    status_tx: watch::Sender<Option<Message>>,
    conn_tx: watch::Sender<bool>,
    autherr_tx: watch::Sender<Option<CoreError>>,
) {
    let ActorConfig {
        core,
        mut addr,
        connect_timeout,
        want_scan,
        connect_limiter,
    } = acfg;

    let sinks = Sinks {
        bcast: bcast_tx,
        status: status_tx,
        conn: conn_tx,
        autherr: autherr_tx,
    };
    // Every log line this task emits is prefixed with it: one bridge drives a
    // whole fleet through identical code, so an unattributed line is unreadable.
    let id = core.device_id.clone();
    let mut fsm = Device::new(core);
    // A Send CSPRNG (ChaCha), seeded from the OS. One instance for the task's
    // lifetime is fine: its period dwarfs any device's frame count, and pinning
    // it here keeps the actor future `Send` (a `ThreadRng` would not be).
    let mut rng = StdRng::from_os_rng();
    let base = TokioInstant::now();

    let mut stream: Option<TcpStream> = None;
    // TCP read chunk. Any size is correct — the core's RxBuffer reassembles frames
    // across reads — so this is purely a syscall-count/throughput knob, not a frame
    // bound. 8 KiB comfortably holds a typical status frame in one read.
    let mut rbuf = vec![0u8; 8192];
    // Establishment permit, when a fleet-wide `ConnectLimiter` is shared in.
    // Taken just before a dial and dropped the moment the FSM stops
    // establishing — see `ConnectLimiter` for why holding it any longer would
    // deadlock a fleet larger than the cap.
    let mut permit: Option<OwnedSemaphorePermit> = None;

    loop {
        // (A) Dial when the core asks. The result — success or failure — is just
        //     another input; the core decides what happens next (handshake, or a
        //     backoff timer).
        if fsm.wants_connect() {
            if let Some(limiter) = &connect_limiter {
                match await_permit(limiter, &mut cmd_rx, &mut addr).await {
                    Some(p) => permit = Some(p),
                    // Closed while queued for a slot: never dial, just stop.
                    None => {
                        publish_state(&sinks.conn, false);
                        return;
                    }
                }
            }
            match timeout(connect_timeout, TcpStream::connect(&addr)).await {
                Ok(Ok(s)) => {
                    let _ = s.set_nodelay(true);
                    stream = Some(s);
                    fsm.handle_input(Input::Connected, now_since(base), &mut rng);
                }
                Ok(Err(e)) => {
                    log::debug!("{id}: connect {addr} failed: {e}");
                    stream = None;
                    fsm.handle_input(Input::ConnectFailed, now_since(base), &mut rng);
                    // Ask discovery to re-elicit: the address may be stale, or this
                    // is an active-only device passive can't hear. Coalesced there.
                    if let Some(w) = &want_scan {
                        let _ = w.try_send(());
                    }
                }
                Err(_) => {
                    log::debug!("{id}: connect {addr} timed out");
                    stream = None;
                    fsm.handle_input(Input::ConnectFailed, now_since(base), &mut rng);
                    if let Some(w) = &want_scan {
                        let _ = w.try_send(());
                    }
                }
            }
            settle(&id, &mut fsm, &mut stream, &sinks, base, &mut rng).await;
            // A failed dial (or a v3.1–v3.3 connect, which needs no handshake)
            // already resolved the attempt — give the slot back now.
            if !fsm.is_establishing() {
                drop(permit.take());
            }
            continue;
        }

        // (B) One timer at the single next deadline (D2). `None` disables it.
        let deadline = fsm
            .poll_timeout()
            .map(|d| base + StdDuration::from_millis(d.as_millis()));

        // (C) Whichever fires first drives the FSM.
        tokio::select! {
            cmd = cmd_rx.recv() => match cmd {
                Some(Cmd::Fire { cmd, data, cid }) => {
                    // Fire-and-forget: only emit if the socket is up. The handle
                    // already waited for `connected`, so a drop here is just a
                    // connect/drop race — the frame is dropped and the caller reads
                    // state from the listener bus.
                    if fsm.is_connected() {
                        let t = unix_secs();
                        // `cid` is owned here for the duration of this call, so the
                        // core can borrow it — no per-command allocation in the FSM.
                        let input = Input::Send { cmd, data, cid: cid.as_deref(), t };
                        fsm.handle_input(input, now_since(base), &mut rng);
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
                    publish_state(&sinks.conn, false);
                    return;
                }
            },
            r = read_some(&mut stream, &mut rbuf), if stream.is_some() => match r {
                Ok(0) => {
                    // Peer EOF. Worth a line of its own: "the device hung up on
                    // us" and "we timed out on a silent link" produce the same
                    // offline state but have opposite causes, and without this
                    // the first one is completely silent.
                    log::debug!("{id}: peer closed the connection");
                    fsm.handle_input(Input::Closed, now_since(base), &mut rng);
                }
                Ok(n) => fsm.handle_input(Input::Received(&rbuf[..n]), now_since(base), &mut rng),
                Err(e) => {
                    log::debug!("{id}: read error: {e}");
                    fsm.handle_input(Input::Closed, now_since(base), &mut rng);
                }
            },
            _ = sleep_until(deadline.unwrap_or_else(TokioInstant::now)), if deadline.is_some() => {
                fsm.handle_timeout(now_since(base), &mut rng);
            }
        }

        settle(&id, &mut fsm, &mut stream, &sinks, base, &mut rng).await;
        // The handshake finished, timed out, or the link dropped: in every case
        // the establishment window is over and the slot belongs to the next
        // device in line.
        if !fsm.is_establishing() {
            drop(permit.take());
        }
    }
}

/// Queue for an establishment permit while staying responsive on the command
/// channel. Returns `None` if the device was closed while waiting — a shutdown
/// must not sit behind a fleet's worth of handshakes.
///
/// The acquire future is pinned across the whole wait rather than re-created per
/// loop turn: tokio's semaphore queue is FIFO, so a future dropped and remade
/// goes to the back of it. Re-creating it would starve exactly the devices this
/// cap exists for — a down device linked to discovery is rewoken every time it
/// announces, so under a saturated cap it would surrender its place on every
/// announcement and could queue indefinitely while others pass it.
async fn await_permit(
    limiter: &ConnectLimiter,
    cmd_rx: &mut mpsc::Receiver<Cmd>,
    addr: &mut String,
) -> Option<OwnedSemaphorePermit> {
    let acquire = limiter.acquire();
    tokio::pin!(acquire);
    loop {
        tokio::select! {
            p = &mut acquire => return Some(p),
            cmd = cmd_rx.recv() => match cmd {
                // Shutdown, or every handle dropped: abandon the slot request.
                Some(Cmd::Close) | None => return None,
                // A rewake may carry a freshly-discovered address. Adopt it so
                // the dial we're queued for targets the *current* IP rather than
                // the stale one. The `ConnectNow` itself is a no-op — the FSM is
                // already in `Connecting`, which is why we're here.
                Some(Cmd::ConnectNow { addr: new_addr }) => {
                    if let Some(a) = new_addr {
                        *addr = a;
                    }
                }
                // Dropped exactly as the main loop drops a `Fire` while down:
                // the caller reads device state off the listener bus.
                Some(Cmd::Fire { .. }) => {}
            },
        }
    }
}

/// One socket read into `buf`. Split out so the `select!` precondition
/// (`if stream.is_some()`) gates the `unwrap`.
async fn read_some(stream: &mut Option<TcpStream>, buf: &mut [u8]) -> std::io::Result<usize> {
    stream
        .as_mut()
        .expect("guarded by `if stream.is_some()`")
        .read(buf)
        .await
}

/// Push everything the FSM produced out to the world: bytes to the socket, events
/// to the listener bus. Re-runs once if a write fails (feeding the core `Closed`,
/// which enqueues `Disconnected` for us to dispatch), so the loop runs at most twice
/// and always leaves the FSM's queues empty.
async fn settle(
    id: &str,
    fsm: &mut Device,
    stream: &mut Option<TcpStream>,
    sinks: &Sinks,
    base: TokioInstant,
    rng: &mut StdRng,
) {
    loop {
        // Bytes out. A write failure is just another `Closed` input to the core.
        if let Err(e) = flush_tx(id, fsm, stream).await {
            log::debug!("{id}: write error: {e}");
            *stream = None;
            fsm.handle_input(Input::Closed, now_since(base), rng);
            // The Closed produced a Disconnected event; dispatch it next turn.
            continue;
        }
        // Events out. If the core tore the connection down, drop the socket so the
        // next dial gets a fresh one.
        if dispatch_events(id, fsm, sinks) {
            *stream = None;
        }
        return;
    }
}

/// Drain `poll_transmit` to the socket. Errors surface for the `Closed` re-feed.
async fn flush_tx(
    id: &str,
    fsm: &mut Device,
    stream: &mut Option<TcpStream>,
) -> std::io::Result<()> {
    while let Some(bytes) = fsm.poll_transmit() {
        // Pairs with the `rx` line in `dispatch_events`: together they give a
        // full wire transcript at `debug`, which is what a device that hangs up
        // on a particular frame (a keepalive it dislikes, say) needs to be
        // diagnosed. The frame is on the wire, so it is shown raw — decoding it
        // here would hide exactly the malformation being hunted.
        log::debug!("{id}: tx {} bytes: {:?}", bytes.len(), DebugBytes(&bytes));
        // No socket to write to (torn down mid-drain) → drop the bytes; the core
        // re-establishes state on the next connect.
        if let Some(s) = stream.as_mut() {
            s.write_all(&bytes).await?;
        }
    }
    Ok(())
}

/// Publish a value on a state `watch`, waking consumers **only on an actual
/// change**.
///
/// [`watch::Sender::send`] notifies on every call, even when the value it writes
/// is the one already there. These channels carry *state* — is the link up, why
/// won't it come up — and their consumers are documented as reacting to
/// transitions. A device that accepts TCP but fails its handshake tears down
/// once per retry, so the plain form republishes the same `false` on every
/// backoff round, forever: a supervisor publishing an online/offline event would
/// emit a fresh OFFLINE per device per retry for as long as the fleet is down.
///
/// The sender is only gone when the actor itself is, which consumers see as a
/// `changed()` error — so suppressing a no-op write loses nothing.
fn publish_state<T: PartialEq>(tx: &watch::Sender<T>, value: T) {
    tx.send_if_modified(|current| {
        if *current == value {
            false
        } else {
            *current = value;
            true
        }
    });
}

/// Drain `poll_event`, fanning each response out to the listener bus.
/// Returns `true` if a `Disconnected` was seen (the connection was torn down).
fn dispatch_events(id: &str, fsm: &mut Device, sinks: &Sinks) -> bool {
    let mut tore_down = false;
    while let Some(ev) = fsm.poll_event() {
        match ev {
            Event::Ready => {
                publish_state(&sinks.conn, true);
                // A healthy connection clears any stale auth-failure diagnostic.
                publish_state(&sinks.autherr, None);
            }
            Event::Response(msg) => {
                // One line per decoded frame, for diagnosing a device whose
                // payloads come out wrong. The retcode is the tell: the decoder
                // splits it off by protocol rule, so a nonsense value means the
                // split was wrong and everything after it is misaligned. The
                // payload goes out as an escaped string — a *garbled* payload is
                // exactly the case worth seeing, so it must not be assumed UTF-8.
                log::debug!(
                    "{id}: rx cmd=0x{:02x} seqno={} retcode={:?} len={} payload={:?}",
                    msg.cmd,
                    msg.seqno,
                    msg.retcode,
                    msg.payload.len(),
                    DebugBytes(&msg.payload),
                );
                // Latch the last non-empty frame as the current status (a `watch`,
                // last-value-wins) so a consumer can read "current DPS" without
                // keeping up with the lossy bus; skip bare acks so an empty payload
                // doesn't clobber it. Then fan the frame out to the listener bus.
                if !msg.payload.is_empty() {
                    let _ = sinks.status.send(Some(msg.clone()));
                }
                let _ = sinks.bcast.send(msg);
            }
            Event::Disconnected => {
                tore_down = true;
                publish_state(&sinks.conn, false);
            }
            Event::ProtocolError(e) => {
                if e.is_auth_failure() {
                    // A CRC/HMAC/GCM failure means the payload didn't authenticate
                    // — almost always a wrong local key or protocol version. Surface
                    // it (0.3's ERR_KEY_OR_VER): publish it so `wait_connected`
                    // reports the reason instead of a bare timeout (this
                    // `ProtocolError` precedes the vaguer `Disconnected`), and
                    // warn-log it.
                    log::warn!(
                        "{id}: authentication failed ({e}): likely a wrong local key or \
                         protocol version"
                    );
                    publish_state(&sinks.autherr, Some(e));
                } else {
                    log::debug!("{id}: protocol error: {e}");
                }
            }
        }
    }
    tore_down
}

#[cfg(test)]
mod permit_tests {
    use super::*;

    /// A device queued for a permit keeps its place across the commands that
    /// arrive while it waits.
    ///
    /// This is the fairness the pinned acquire future buys. Re-creating that
    /// future per command would send the device to the back of the semaphore's
    /// FIFO queue, and the devices that get commands while down are exactly the
    /// ones registered with discovery — rewoken on every announcement — so under
    /// a saturated cap they could queue indefinitely while others pass them.
    ///
    /// Ordering is established by scheduler turns on a single-threaded runtime,
    /// not by wall clock: each spawned waiter runs until it parks in `acquire`,
    /// so the queue order is exactly the spawn order.
    #[tokio::test(flavor = "current_thread")]
    async fn a_waiting_device_keeps_its_queue_place_across_commands() {
        let limiter = ConnectLimiter::new(1);
        // Saturate the cap: both waiters below must queue.
        let held = limiter.acquire().await;

        let (won_tx, mut won_rx) = mpsc::channel::<&'static str>(2);
        let mut senders = Vec::new();
        for name in ["first", "second"] {
            let (cmd_tx, mut cmd_rx) = mpsc::channel::<Cmd>(4);
            senders.push(cmd_tx);
            let limiter = limiter.clone();
            let won_tx = won_tx.clone();
            tokio::spawn(async move {
                let mut addr = String::from("192.168.1.5:6668");
                if await_permit(&limiter, &mut cmd_rx, &mut addr)
                    .await
                    .is_some()
                {
                    let _ = won_tx.send(name).await;
                    // Hold the permit so the loser cannot also report a win.
                    std::future::pending::<()>().await;
                }
            });
            // Let the waiter reach its `acquire` before the next one is spawned,
            // so "first" really is first in the queue.
            tokio::task::yield_now().await;
        }

        // Rewakes for the device at the head of the queue — an announcement storm
        // is exactly the command traffic a down device sees.
        for _ in 0..8 {
            senders[0]
                .send(Cmd::ConnectNow { addr: None })
                .await
                .unwrap();
            tokio::task::yield_now().await;
        }

        drop(held);
        assert_eq!(
            won_rx.recv().await,
            Some("first"),
            "the device already at the head of the queue must get the freed permit; \
             it was overtaken, so its place was surrendered on every command"
        );
    }

    /// A rewake that arrives mid-wait still updates the dial target, so the dial
    /// the device was queued for lands on the freshly-announced IP.
    #[tokio::test(flavor = "current_thread")]
    async fn a_rewake_mid_wait_updates_the_address() {
        let limiter = ConnectLimiter::new(1);
        let held = limiter.acquire().await;
        let (cmd_tx, mut cmd_rx) = mpsc::channel::<Cmd>(4);

        let waiter = {
            let limiter = limiter.clone();
            tokio::spawn(async move {
                let mut addr = String::from("192.168.1.5:6668");
                let got = await_permit(&limiter, &mut cmd_rx, &mut addr).await;
                (got.is_some(), addr)
            })
        };
        tokio::task::yield_now().await;

        cmd_tx
            .send(Cmd::ConnectNow {
                addr: Some("192.168.1.9:6668".to_string()),
            })
            .await
            .unwrap();
        tokio::task::yield_now().await;
        drop(held);

        let (got_permit, addr) = waiter.await.unwrap();
        assert!(got_permit, "the waiter should have been granted the permit");
        assert_eq!(addr, "192.168.1.9:6668", "the new address was not adopted");
    }

    /// A close must not sit behind a fleet's worth of handshakes: it is answered
    /// while the device is still queued, without ever taking a permit.
    #[tokio::test(flavor = "current_thread")]
    async fn a_close_while_queued_abandons_the_slot_request() {
        let limiter = ConnectLimiter::new(1);
        let held = limiter.acquire().await;
        let (cmd_tx, mut cmd_rx) = mpsc::channel::<Cmd>(4);

        let waiter = {
            let limiter = limiter.clone();
            tokio::spawn(async move {
                let mut addr = String::from("192.168.1.5:6668");
                await_permit(&limiter, &mut cmd_rx, &mut addr)
                    .await
                    .is_some()
            })
        };
        tokio::task::yield_now().await;

        cmd_tx.send(Cmd::Close).await.unwrap();
        assert!(
            !waiter.await.unwrap(),
            "a queued device must abandon its slot request on Close"
        );
        drop(held);
        assert_eq!(limiter.available(), 1, "no permit should have been taken");
    }
}
