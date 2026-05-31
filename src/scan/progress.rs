//! Progress plumbing shared by the CLI and TUI front-ends.
//!
//! Per the research-recommended hybrid concurrency model: rayon workers bump the
//! lock-free [`Counters`] for high-frequency stats (sampled per UI tick) and send
//! discrete [`ScanEvent`]s over a `crossbeam-channel` for events the UI must react
//! to individually (threats, completion, errors).

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::engine::verdict::Threat;

/// Lock-free counters updated by scan workers and sampled by the UI.
#[derive(Debug, Default)]
pub struct Counters {
    pub total: AtomicU64,
    pub scanned: AtomicU64,
    pub bytes: AtomicU64,
    pub threats: AtomicU64,
    pub skipped: AtomicU64,
    pub errors: AtomicU64,
}

impl Counters {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn snapshot(&self) -> CounterSnapshot {
        CounterSnapshot {
            scanned: self.scanned.load(Ordering::Relaxed),
            bytes: self.bytes.load(Ordering::Relaxed),
            threats: self.threats.load(Ordering::Relaxed),
            skipped: self.skipped.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
        }
    }
}

/// A consistent point-in-time read of the counters.
#[derive(Debug, Clone, Copy, Default)]
pub struct CounterSnapshot {
    pub scanned: u64,
    pub bytes: u64,
    pub threats: u64,
    pub skipped: u64,
    pub errors: u64,
}

/// Discrete events streamed from the scan engine to a front-end.
#[derive(Debug)]
pub enum ScanEvent {
    /// Enumeration finished; `total` files will be scanned.
    Started { total: u64 },
    /// A file produced a threat verdict (suspicious or malicious).
    Threat(Box<Threat>),
    /// A file could not be read/scanned.
    Error { path: PathBuf, message: String },
    /// The scan completed (naturally or via cancellation).
    Finished { cancelled: bool },
}
