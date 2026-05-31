//! The detection engine: orchestrates the five layers (hash → YARA → Mach-O →
//! code-signature trust → entropy/script heuristics) over a single file and
//! combines their findings into a [`Threat`] verdict.

pub mod filetype;
pub mod hashdb;
pub mod heuristics;
pub mod verdict;
pub mod yara;

use std::fs::File;
use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use memmap2::Mmap;

use filetype::FileClass;
use hashdb::HashDb;
use heuristics::{codesign, macho, scripts};
use verdict::{Detection, Engine, Severity, Threat, TrustTier};
use yara::YaraEngine;

/// Default ceiling on file size we will fully hash/scan (bytes).
pub const DEFAULT_MAX_FILE_SIZE: u64 = 512 * 1024 * 1024;

/// Tunable engine behavior.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub max_file_size: u64,
    /// Whether to run the (process-spawning) code-signature trust check.
    pub check_codesign: bool,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            max_file_size: DEFAULT_MAX_FILE_SIZE,
            check_codesign: true,
        }
    }
}

/// Per-file result.
pub enum ScanOutcome {
    Clean,
    Flagged(Box<Threat>),
    Skipped(&'static str),
    Error(String),
}

/// The composed scanner. Cheap to clone (engines are `Arc`-backed).
#[derive(Clone)]
pub struct ScanEngine {
    yara: YaraEngine,
    hashes: Arc<HashDb>,
    config: EngineConfig,
}

impl ScanEngine {
    pub fn new(yara: YaraEngine, hashes: HashDb, config: EngineConfig) -> Self {
        Self {
            yara,
            hashes: Arc::new(hashes),
            config,
        }
    }

    /// Build the engine from bundled definitions. (The CLI composes the engine
    /// via [`ScanEngine::new`] so it can layer updated defs on top; this all-in-one
    /// constructor is used by tests and embedders.)
    #[allow(dead_code)]
    pub fn bundled() -> Result<Self> {
        Ok(Self::new(
            YaraEngine::bundled()?,
            HashDb::bundled(),
            EngineConfig::default(),
        ))
    }

    pub fn yara(&self) -> &YaraEngine {
        &self.yara
    }

    pub fn hash_count(&self) -> usize {
        self.hashes.len()
    }

    /// Scan a single regular file.
    pub fn scan_file(&self, path: &Path) -> ScanOutcome {
        let file = match File::open(path) {
            Ok(f) => f,
            Err(e) => return ScanOutcome::Error(e.to_string()),
        };
        let size = match file.metadata() {
            Ok(m) => m.len(),
            Err(e) => return ScanOutcome::Error(e.to_string()),
        };
        if size == 0 {
            return ScanOutcome::Clean;
        }
        if size > self.config.max_file_size {
            return ScanOutcome::Skipped("file exceeds size cap");
        }

        // Prefer zero-copy mmap; fall back to a buffered read.
        let mmap = unsafe { Mmap::map(&file) }.ok();
        let fallback = if mmap.is_none() {
            std::fs::read(path).ok()
        } else {
            None
        };
        let data: &[u8] = match (&mmap, &fallback) {
            (Some(m), _) => &m[..],
            (None, Some(v)) => &v[..],
            (None, None) => return ScanOutcome::Error("could not read file".into()),
        };

        let mut detections: Vec<Detection> = Vec::new();
        let mut trust = TrustTier::Unknown;

        // --- Engine 1: exact hash signatures ---
        let sha256 = hashdb::sha256_hex(data);
        let md5 = hashdb::md5_hex(data);
        if let Some(hit) = self.hashes.lookup(&sha256, &md5) {
            detections.push(Detection::new(
                Engine::Hash,
                "known_malware_hash",
                100,
                Severity::Critical,
                true,
                format!("file digest matches a known-malware signature ({hit})"),
            ));
        }

        // --- Engine 2: YARA family/variant rules ---
        detections.extend(self.yara.scan(data));

        // --- Engine 3/4: structure + trust + heuristics, routed by file type ---
        let sample = &data[..data.len().min(8192)];
        let class = filetype::classify(sample, path);
        match class {
            FileClass::MachO => {
                let report = macho::analyze(data);
                detections.extend(report.detections);
                if self.config.check_codesign {
                    trust = codesign::classify(path, report.has_code_signature);
                } else if !report.has_code_signature {
                    trust = TrustTier::Unsigned;
                }
            }
            FileClass::Script | FileClass::Text => {
                detections.extend(scripts::scan_text(data));
            }
            FileClass::Archive | FileClass::Media | FileClass::OtherBinary | FileClass::Unknown => {
                // Whole-file entropy is deliberately NOT scored here: legitimate
                // data (game-asset bundles, icons, fonts, compressed/encrypted
                // resources) is routinely high-entropy, so it is a major
                // false-positive source. Packing is detected precisely on the
                // executable path instead — per-Mach-O-section `__text` entropy
                // in `heuristics::macho`.
            }
        }

        // Apple-signed code (anchor apple) is never malware-by-heuristic. Keep
        // only exact known-bad hash matches on it; drop YARA-family and heuristic
        // findings to eliminate false positives on system binaries.
        if trust == TrustTier::Apple {
            detections.retain(|d| d.engine == Engine::Hash);
        }

        match Threat::assemble(path.to_path_buf(), sha256, size, trust, detections) {
            Some(threat) => ScanOutcome::Flagged(Box::new(threat)),
            None => ScanOutcome::Clean,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::verdict::Verdict;

    /// End-to-end: the composed engine flags EICAR via both the hash and YARA
    /// layers, and leaves a benign file clean.
    #[test]
    fn engine_detects_eicar_and_passes_benign() {
        let engine = ScanEngine::bundled().expect("engine builds");
        let dir = tempfile::tempdir().unwrap();

        let eicar = dir.path().join("eicar.com");
        std::fs::write(
            &eicar,
            br#"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"#,
        )
        .unwrap();

        let benign = dir.path().join("notes.txt");
        std::fs::write(&benign, b"just some harmless notes\n").unwrap();

        match engine.scan_file(&eicar) {
            ScanOutcome::Flagged(t) => {
                assert_eq!(t.verdict, Verdict::Malicious);
                assert!(t.detections.iter().any(|d| d.engine == Engine::Hash));
                assert!(t.detections.iter().any(|d| d.engine == Engine::Yara));
            }
            _ => panic!("EICAR should be flagged malicious"),
        }

        assert!(matches!(engine.scan_file(&benign), ScanOutcome::Clean));
    }
}
