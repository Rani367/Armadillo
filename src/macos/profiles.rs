//! Configuration-profile audit — adware (AdminPrefs / TechSignalSearch /
//! MainSearchPlatform families) installs `.mobileconfig` profiles to lock browser
//! settings. Best-effort: scans likely drop locations for profile files and
//! flags known adware identifiers or browser-setting enforcement.

use std::path::{Path, PathBuf};

use super::{AuditCategory, AuditFinding};
use crate::engine::verdict::Severity;

const ADWARE_MARKERS: &[&str] = &[
    "TechSignalSearch",
    "MainSearchPlatform",
    "AdminPrefs",
    "SearchProvider",
    "PayloadType",
];

/// Returns (findings, files inspected).
pub fn audit() -> (Vec<AuditFinding>, usize) {
    let mut findings = Vec::new();
    let mut inspected = 0;

    for path in candidate_files() {
        inspected += 1;
        if let Some(f) = inspect(&path) {
            findings.push(f);
        }
    }
    (findings, inspected)
}

fn candidate_files() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = vec![
        PathBuf::from("/Library/Managed Preferences"),
        PathBuf::from("/var/db/ConfigurationProfiles/Store"),
    ];
    if let Some(home) = dirs::home_dir() {
        dirs.push(home.join("Downloads"));
        dirs.push(home.join("Library/Managed Preferences"));
    }

    let mut files = Vec::new();
    for dir in dirs {
        if let Ok(rd) = std::fs::read_dir(&dir) {
            for e in rd.flatten() {
                let p = e.path();
                let is_profile = matches!(
                    p.extension().and_then(|x| x.to_str()),
                    Some("mobileconfig")
                ) || p.to_string_lossy().contains("com.apple.Safari")
                    || p.to_string_lossy().contains("com.google.Chrome");
                if p.is_file() && is_profile {
                    files.push(p);
                }
            }
        }
    }
    files
}

fn inspect(path: &Path) -> Option<AuditFinding> {
    let data = std::fs::read(path).ok()?;
    let text = String::from_utf8_lossy(&data);
    let mut reasons = Vec::new();
    for marker in ADWARE_MARKERS {
        if text.contains(marker) {
            reasons.push(format!("references '{marker}'"));
        }
    }
    // Browser-setting enforcement keys inside a profile.
    if text.contains("HomePage") || text.contains("SearchProviderIdentifier") {
        reasons.push("enforces browser homepage/search settings".into());
    }
    if reasons.len() < 2 {
        // Require more than a single weak marker to flag (precision control).
        return None;
    }
    Some(AuditFinding {
        category: AuditCategory::Profile,
        location: path.to_path_buf(),
        title: path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default(),
        severity: Severity::Medium,
        reasons,
    })
}
