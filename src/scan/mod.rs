//! Filesystem walk + parallel scan dispatch.
//!
//! Enumerates regular files under the requested roots (including hidden files —
//! malware hides in dotfiles), then scans them in parallel with rayon. Workers
//! bump lock-free [`Counters`] and stream [`ScanEvent`]s to the front-end, and
//! check a shared cancellation flag between files.

pub mod progress;
pub mod targets;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crossbeam_channel::Sender;
use ignore::WalkBuilder;
use rayon::prelude::*;

use crate::engine::{ScanEngine, ScanOutcome};
use progress::{Counters, ScanEvent};

/// What to scan.
#[derive(Debug, Clone)]
pub struct ScanRequest {
    pub roots: Vec<PathBuf>,
    pub excludes: Vec<PathBuf>,
    pub follow_symlinks: bool,
}

impl ScanRequest {
    pub fn new(roots: Vec<PathBuf>) -> Self {
        Self {
            roots,
            excludes: Vec::new(),
            follow_symlinks: false,
        }
    }

    pub fn with_excludes(mut self, excludes: Vec<PathBuf>) -> Self {
        self.excludes = excludes;
        self
    }
}

/// Enumerate all regular files under the request's roots, applying exclusions.
pub fn enumerate(request: &ScanRequest) -> Vec<(PathBuf, u64)> {
    let mut roots = request.roots.iter().filter(|p| p.exists());
    let first = match roots.next() {
        Some(r) => r,
        None => return Vec::new(),
    };
    let mut builder = WalkBuilder::new(first);
    for r in roots {
        builder.add(r);
    }
    builder
        .standard_filters(false) // scan everything: no .gitignore/hidden filtering
        .hidden(false)
        .follow_links(request.follow_symlinks)
        .same_file_system(false);

    // Always self-exclude: our own binary embeds the YARA rule strings (so it
    // would match its own signatures) and our data/quarantine vault holds known
    // threats we deliberately stored.
    let mut excludes = request.excludes.clone();
    if let Ok(exe) = std::env::current_exe() {
        excludes.push(exe);
    }
    excludes.push(crate::config::Paths::data_dir());
    let mut out = Vec::new();
    for result in builder.build() {
        let entry = match result {
            Ok(e) => e,
            Err(_) => continue,
        };
        let path = entry.path();
        if is_excluded(path, &excludes) {
            continue;
        }
        let is_file = entry.file_type().map(|t| t.is_file()).unwrap_or(false);
        if !is_file {
            continue;
        }
        let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
        out.push((path.to_path_buf(), size));
    }
    out
}

fn is_excluded(path: &Path, excludes: &[PathBuf]) -> bool {
    excludes.iter().any(|ex| path.starts_with(ex))
}

/// Run a scan to completion. Intended to be called on a dedicated thread; the
/// front-end drains `tx` and samples `counters` live. Blocks until done.
pub fn run_scan(
    engine: Arc<ScanEngine>,
    request: ScanRequest,
    tx: Sender<ScanEvent>,
    counters: Arc<Counters>,
    cancel: Arc<AtomicBool>,
) {
    let files = enumerate(&request);
    counters.total.store(files.len() as u64, Ordering::Relaxed);
    let _ = tx.send(ScanEvent::Started {
        total: files.len() as u64,
    });

    files.par_iter().for_each(|(path, size)| {
        if cancel.load(Ordering::Relaxed) {
            return;
        }
        match engine.scan_file(path) {
            ScanOutcome::Clean => {}
            ScanOutcome::Flagged(threat) => {
                counters.threats.fetch_add(1, Ordering::Relaxed);
                let _ = tx.send(ScanEvent::Threat(threat));
            }
            ScanOutcome::Skipped(reason) => {
                tracing::trace!(path = %path.display(), reason, "skipped");
                counters.skipped.fetch_add(1, Ordering::Relaxed);
            }
            ScanOutcome::Error(message) => {
                counters.errors.fetch_add(1, Ordering::Relaxed);
                let _ = tx.send(ScanEvent::Error {
                    path: path.clone(),
                    message,
                });
            }
        }
        counters.bytes.fetch_add(*size, Ordering::Relaxed);
        counters.scanned.fetch_add(1, Ordering::Relaxed);
    });

    let cancelled = cancel.load(Ordering::Relaxed);
    let _ = tx.send(ScanEvent::Finished { cancelled });
}
