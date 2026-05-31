//! Tracing setup. The CLI logs to stderr; the TUI logs to a rolling file (never
//! to the terminal it owns, which would corrupt the alternate screen).

use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::EnvFilter;

use crate::config::Paths;

fn filter(verbose: bool) -> EnvFilter {
    EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new(if verbose { "armadillo=debug,info" } else { "warn" })
    })
}

/// Initialize stderr logging for the CLI paths.
pub fn init_cli(verbose: bool) {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter(verbose))
        .with_writer(std::io::stderr)
        .without_time()
        .try_init();
}

/// Initialize file logging for the TUI. The returned guard must be kept alive
/// for the lifetime of the program so buffered logs are flushed.
pub fn init_tui(verbose: bool) -> Option<WorkerGuard> {
    let _ = Paths::ensure();
    let appender = tracing_appender::rolling::daily(Paths::log_dir(), "armadillo.log");
    let (nb, guard) = tracing_appender::non_blocking(appender);
    let ok = tracing_subscriber::fmt()
        .with_env_filter(filter(verbose))
        .with_writer(nb)
        .with_ansi(false)
        .try_init()
        .is_ok();
    if ok {
        Some(guard)
    } else {
        None
    }
}
