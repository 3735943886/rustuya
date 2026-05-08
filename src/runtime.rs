//! Global background runtime management.
//!
//! Provides a centralized Tokio runtime for executing background tasks and bridging sync/async code.

use crate::error::Result;
use std::sync::OnceLock;
use tokio::runtime::{Builder, Runtime};

static RUNTIME: OnceLock<Runtime> = OnceLock::new();

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
