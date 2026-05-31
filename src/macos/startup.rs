//! Shell-startup, cron, and periodic-script persistence audit.
//!
//! Reuses the script/obfuscation heuristics ([`crate::engine::heuristics::scripts`])
//! over these high-value files: a `curl … | bash` or `DYLD_INSERT_LIBRARIES`
//! line in `~/.zshenv` is a classic (e.g. DPRK) persistence technique.

use std::path::{Path, PathBuf};

use super::{severity_from_score, AuditCategory, AuditFinding, AUDIT_EMIT_THRESHOLD};
use crate::engine::heuristics::scripts;

/// Returns (findings, files inspected).
pub fn audit() -> (Vec<AuditFinding>, usize) {
    let mut findings = Vec::new();
    let mut inspected = 0;

    for (path, category) in targets() {
        if !path.is_file() {
            continue;
        }
        inspected += 1;
        if let Some(f) = inspect(&path, category) {
            findings.push(f);
        }
    }
    (findings, inspected)
}

fn targets() -> Vec<(PathBuf, AuditCategory)> {
    let mut v: Vec<(PathBuf, AuditCategory)> = Vec::new();

    // Shell-startup files (per-user).
    if let Some(home) = dirs::home_dir() {
        for name in [
            ".zshenv",
            ".zshrc",
            ".zprofile",
            ".zlogin",
            ".bash_profile",
            ".bashrc",
            ".profile",
            ".bash_login",
        ] {
            v.push((home.join(name), AuditCategory::ShellStartup));
        }
    }

    // System cron.
    v.push((PathBuf::from("/etc/crontab"), AuditCategory::Cron));
    for dir in ["/etc/cron.d", "/usr/lib/cron/tabs"] {
        if let Ok(rd) = std::fs::read_dir(dir) {
            for e in rd.flatten() {
                v.push((e.path(), AuditCategory::Cron));
            }
        }
    }

    // Periodic scripts (normally Apple/admin; flag droppers).
    for dir in ["/etc/periodic/daily", "/etc/periodic/weekly", "/etc/periodic/monthly"] {
        if let Ok(rd) = std::fs::read_dir(dir) {
            for e in rd.flatten() {
                v.push((e.path(), AuditCategory::Periodic));
            }
        }
    }

    v
}

fn inspect(path: &Path, category: AuditCategory) -> Option<AuditFinding> {
    let content = std::fs::read(path).ok()?;
    let detections = scripts::scan_text(&content);
    let score: u32 = detections.iter().map(|d| d.score).sum();
    // Require a real dropper/obfuscation signal — a lone low-signal `eval` in a
    // normal shell rc (e.g. `eval "$(brew shellenv)"`) must not trip the audit.
    if detections.is_empty() || score < AUDIT_EMIT_THRESHOLD {
        return None;
    }
    let reasons = detections
        .into_iter()
        .map(|d| format!("{}: {}", d.name, d.reason))
        .collect();
    Some(AuditFinding {
        category,
        location: path.to_path_buf(),
        title: path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default(),
        severity: severity_from_score(score),
        reasons,
    })
}
