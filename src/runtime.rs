//! Global background runtime management.
//!
//! Provides a centralized Tokio runtime for executing background tasks and bridging sync/async code.
//!
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
            .map_err(|e| TuyaError::Io(format!("Failed to get rlimit: {}", e)))?;

        if soft < hard {
            rlimit::setrlimit(rlimit::Resource::NOFILE, hard, hard)
                .map_err(|e| TuyaError::Io(format!("Failed to set rlimit: {}", e)))?;
            info!("File descriptor limit increased from {} to {}", soft, hard);
        }
    }
    Ok(())
}

pub fn get_runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| {
        Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Failed to create Tuya background runtime")
    })
}

pub fn spawn<F>(future: F) -> tokio::task::JoinHandle<()>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn(future)
    } else {
        get_runtime().spawn(future)
    }
}
