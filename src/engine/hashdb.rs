//! Known-malware hash database (Engine 1 of 5).
//!
//! Holds SHA-256 and MD5 hex digests of known-bad files for O(1) exact-match
//! lookup. Seeded from a small bundled list and extendable at runtime by
//! `armadillo update` (abuse.ch / URLhaus exports). BLAKE3 is used elsewhere for
//! fast internal fingerprinting, but external feeds are keyed on SHA-256/MD5.

use std::collections::HashSet;
use std::path::Path;

use anyhow::{Context, Result};
use md5::Md5;
use sha2::{Digest, Sha256};

/// A tiny bundled starter list. Includes the EICAR test-file SHA-256 so the
/// hash engine (not only YARA) detects the standard AV self-test. One token per
/// line; lines may be a bare hex digest or ClamAV `hash:size:name` form; `#`
/// starts a comment.
const BUNDLED_HASHES: &str = include_str!("../../data/hashes/bundled.hashes");

#[derive(Debug, Default)]
pub struct HashDb {
    sha256: HashSet<String>,
    md5: HashSet<String>,
}

impl HashDb {
    /// Load the bundled starter list.
    pub fn bundled() -> Self {
        let mut db = HashDb::default();
        db.ingest_str(BUNDLED_HASHES);
        db
    }

    /// Merge an additional hash file from disk (e.g. a downloaded feed).
    pub fn merge_file(&mut self, path: &Path) -> Result<usize> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading hash feed {}", path.display()))?;
        Ok(self.ingest_str(&text))
    }

    /// Parse hashes out of arbitrary feed text. Returns the count added.
    pub fn ingest_str(&mut self, text: &str) -> usize {
        let mut added = 0;
        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            // Accept bare hex, `hash:size:name` (ClamAV .hdb/.hsb), or CSV rows
            // (MalwareBazaar/URLhaus exports often carry both MD5 and SHA-256 on
            // one line) — ingest every digest-shaped token on the line.
            for tok in line.split([':', ',', ';', ' ', '\t', '"']) {
                if !is_hex_digest(tok) {
                    continue;
                }
                let h = tok.to_ascii_lowercase();
                let inserted = match h.len() {
                    32 => self.md5.insert(h),
                    64 => self.sha256.insert(h),
                    _ => continue,
                };
                if inserted {
                    added += 1;
                }
            }
        }
        added
    }

    pub fn len(&self) -> usize {
        self.sha256.len() + self.md5.len()
    }

    /// Serialize all digests, one per line (for writing a merged feed file).
    pub fn to_lines(&self) -> String {
        let mut out = String::with_capacity(self.len() * 65);
        out.push_str("# Armadillo merged hash feed\n");
        for h in &self.sha256 {
            out.push_str(h);
            out.push('\n');
        }
        for h in &self.md5 {
            out.push_str(h);
            out.push('\n');
        }
        out
    }

    /// Returns the matching digest string if `data` is known-bad.
    pub fn lookup(&self, sha256_hex: &str, md5_hex: &str) -> Option<String> {
        if self.sha256.contains(sha256_hex) {
            return Some(sha256_hex.to_string());
        }
        if self.md5.contains(md5_hex) {
            return Some(md5_hex.to_string());
        }
        None
    }
}

/// Compute the SHA-256 hex digest of `data`.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex_encode(&hasher.finalize())
}

/// Compute the MD5 hex digest of `data` (legacy feed compatibility only).
pub fn md5_hex(data: &[u8]) -> String {
    let mut hasher = Md5::new();
    hasher.update(data);
    hex_encode(&hasher.finalize())
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn is_hex_digest(s: &str) -> bool {
    // We match on MD5 (32) and SHA-256 (64) only, since those are what we hash
    // per file at scan time. (SHA-1 feeds exist but we don't compute SHA-1.)
    (s.len() == 32 || s.len() == 64) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eicar_sha256_is_known() {
        // The canonical EICAR test string's SHA-256.
        let eicar = br#"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"#;
        let h = sha256_hex(eicar);
        assert_eq!(
            h,
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        );
        let db = HashDb::bundled();
        assert!(db.lookup(&h, &md5_hex(eicar)).is_some());
    }

    #[test]
    fn parses_clamav_and_csv_forms() {
        let mut db = HashDb::default();
        let sha = "a".repeat(64);
        let input = format!(
            "# comment\n\
             44d88612fea8a8f36de82e1278abb02f:68:Eicar-Test-Signature\n\
             {sha},evil.bin\n"
        );
        let n = db.ingest_str(&input);
        assert_eq!(n, 2);
        assert!(db.md5.contains("44d88612fea8a8f36de82e1278abb02f"));
        assert!(db.sha256.contains(&sha));
    }
}
