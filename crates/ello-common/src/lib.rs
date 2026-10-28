//! Types, configuration, and filesystem layout shared across Ello Antivirus.

pub mod config;
pub mod paths;
pub mod verdict;

pub use config::Config;
pub use verdict::{Action, Confidence, Detection, DetectionKind, ScanOutcome, ScanStats};

/// Initializes process-wide logging from the `ELLO_LOG` env var (default `info`).
pub fn init_logging() {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter = EnvFilter::try_from_env("ELLO_LOG").unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = fmt().with_env_filter(filter).with_target(false).try_init();
}
