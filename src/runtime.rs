//! Global background runtime management.
//!
//! Provides a centralized Tokio runtime for executing background tasks and bridging sync/async code.

use crate::error::Result;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::runtime::{Builder, Runtime};
use tokio::sync::{Semaphore, SemaphorePermit};

static RUNTIME: OnceLock<Runtime> = OnceLock::new();

/// Optional global limit on how many devices may be *establishing* a connection
/// (TCP connect + session-key handshake) at the same instant — a connect-storm
/// guard. When a large fleet comes online, or reconnects en masse after a
/// network blip, the per-device connection tasks would otherwise all begin
/// their (CPU- and round-trip-heavy) handshakes at once; jitter spreads the
/// *start* of each attempt but, because connections are persistent, does not
/// bound the peak number of *concurrent in-flight handshakes*. This semaphore
/// can.
///
/// **Opt-in: there is no cap unless the consumer calls
/// [`set_connect_concurrency`].** The default is unbounded (current behavior) —
/// the benefit only materializes under slow real-device handshakes, which we
/// can't reproduce on fast loopback, so we don't change the default until a
/// real fleet validates it. Large-fleet consumers (e.g. a bridge) opt in.
///
/// When set, the permit is held ONLY across establishment and released the
/// instant the handshake finishes (or fails) — never for the connection's
/// lifetime. Idle established connections are cheap (a ~7s heartbeat) and must
/// not consume a permit, otherwise a fleet larger than the permit count would
/// deadlock with the surplus devices never able to connect.
static CONNECT_SEM: OnceLock<Semaphore> = OnceLock::new();

/// The configured cap, mirrored for reporting via [`connect_concurrency`].
/// 0 means "unset" → unbounded (no cap engaged).
static CONNECT_LIMIT: AtomicUsize = AtomicUsize::new(0);

/// Sets the global cap on concurrent connection establishment, opting in to
/// the connect-storm guard.
///
/// The limit is fixed on first use, so call this **before** creating devices.
/// Returns `false` if the limiter was already initialized by a prior call (the
/// call is then a no-op). `n` is clamped to >= 1. Without this call there is no
/// cap (the default).
pub fn set_connect_concurrency(n: usize) -> bool {
    let n = n.max(1);
    let installed = CONNECT_SEM.set(Semaphore::new(n)).is_ok();
    if installed {
        CONNECT_LIMIT.store(n, Ordering::Relaxed);
    }
    installed
}

/// Returns the configured connect-concurrency cap, or 0 if unset (unbounded).
pub fn connect_concurrency() -> usize {
    CONNECT_LIMIT.load(Ordering::Relaxed)
}

/// Acquires a connect-establishment permit if a cap was configured; otherwise
/// `None` (unbounded — current default). The permit, when present, is held by
/// the caller across TCP connect + handshake and released on drop. Never errors
/// in practice — the semaphore is process-global and never closed.
pub(crate) async fn connect_permit() -> Option<SemaphorePermit<'static>> {
    match CONNECT_SEM.get() {
        Some(sem) => Some(
            sem.acquire()
                .await
                .expect("rustuya: connect semaphore is never closed"),
        ),
        None => None,
    }
}

/// Maximizes the file descriptor limit (Unix-like system only).
pub fn maximize_fd_limit() -> Result<()> {
    #[cfg(unix)]
    {
        use crate::error::TuyaError;
        use log::info;
        let (soft, hard) = rlimit::getrlimit(rlimit::Resource::NOFILE)
            .map_err(|e| TuyaError::io_other(format!("Failed to get rlimit: {e}")))?;

        if soft < hard {
            rlimit::setrlimit(rlimit::Resource::NOFILE, hard, hard)
                .map_err(|e| TuyaError::io_other(format!("Failed to set rlimit: {e}")))?;
            info!("File descriptor limit increased from {soft} to {hard}");
        }
    }
    Ok(())
}

/// Returns a reference to the lazily-initialized background runtime.
///
/// # Panics
///
/// Panics only if Tokio's multi-threaded runtime cannot be constructed
/// (effectively an unrecoverable resource-exhaustion failure on the host).
pub(crate) fn get_runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| {
        Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("rustuya: failed to construct background tokio runtime")
    })
}

pub(crate) fn spawn<F>(future: F) -> tokio::task::JoinHandle<()>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    // Always spawn on the library's own dedicated runtime.
    // Using the caller's runtime (try_current) caused background scanner/device
    // tasks to attach to the consumer app's runtime, preventing clean shutdown.
    get_runtime().spawn(future)
}
