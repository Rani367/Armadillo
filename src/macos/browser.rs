//! Browser hijack audit — auto-installed extensions and enforced search/homepage
//! policies are the lock-in mechanism used by Adload/Genieo/Pirrit-style adware.
//! Conservative, best-effort checks over well-known locations.

use std::path::{Path, PathBuf};

use super::{AuditCategory, AuditFinding};
use crate::engine::verdict::Severity;

/// Returns (findings, locations inspected).
pub fn audit() -> (Vec<AuditFinding>, usize) {
    let mut findings = Vec::new();
    let mut inspected = 0;
    let home = dirs::home_dir();

    // Chrome auto-installed "External Extensions" (force-installed add-ons).
    let mut chrome_ext_dirs = vec![PathBuf::from(
        "/Library/Application Support/Google/Chrome/External Extensions",
    )];
    if let Some(h) = &home {
        chrome_ext_dirs.push(h.join("Library/Application Support/Google/Chrome/External Extensions"));
    }
    for dir in chrome_ext_dirs {
        inspected += 1;
        if let Ok(rd) = std::fs::read_dir(&dir) {
            let jsons: Vec<_> = rd
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("json"))
                .collect();
            if !jsons.is_empty() {
                findings.push(AuditFinding {
                    category: AuditCategory::Browser,
                    location: dir,
                    title: "Chrome force-installed extensions".into(),
                    severity: Severity::Medium,
                    reasons: vec![format!(
                        "{} external-extension manifest(s) auto-install add-ons without user consent",
                        jsons.len()
                    )],
                });
            }
        }
    }

    // Chrome managed-policy search/homepage enforcement.
    inspected += 1;
    let chrome_policy = PathBuf::from("/Library/Managed Preferences/com.google.Chrome.plist");
    if let Some(f) = check_policy_plist(&chrome_policy, "Chrome") {
        findings.push(f);
    }

    // Firefox enterprise policies pinning search/homepage.
    let mut ff_policies = vec![PathBuf::from(
        "/Applications/Firefox.app/Contents/Resources/distribution/policies.json",
    )];
    if let Some(h) = &home {
        ff_policies.push(h.join("Library/Application Support/Mozilla/ManagedStorage"));
    }
    for p in ff_policies {
        inspected += 1;
        if let Some(f) = check_firefox_policies(&p) {
            findings.push(f);
        }
    }

    (findings, inspected)
}

fn check_policy_plist(path: &Path, browser: &str) -> Option<AuditFinding> {
    let value = plist::Value::from_file(path).ok()?;
    let dict = value.as_dictionary()?;
    let mut reasons = Vec::new();
    for key in [
        "HomepageLocation",
        "DefaultSearchProviderSearchURL",
        "DefaultSearchProviderEnabled",
        "NewTabPageLocation",
    ] {
        if dict.contains_key(key) {
            reasons.push(format!("managed policy enforces '{key}'"));
        }
    }
    if reasons.is_empty() {
        return None;
    }
    Some(AuditFinding {
        category: AuditCategory::Browser,
        location: path.to_path_buf(),
        title: format!("{browser} search/homepage locked by managed policy"),
        severity: Severity::Medium,
        reasons,
    })
}

fn check_firefox_policies(path: &Path) -> Option<AuditFinding> {
    let text = std::fs::read_to_string(path).ok()?;
    let lowered = text.to_ascii_lowercase();
    let mut reasons = Vec::new();
    if lowered.contains("searchengines") || lowered.contains("defaultsearch") {
        reasons.push("policy pins the default search engine".into());
    }
    if lowered.contains("homepage") {
        reasons.push("policy pins the homepage".into());
    }
    if reasons.is_empty() {
        return None;
    }
    Some(AuditFinding {
        category: AuditCategory::Browser,
        location: path.to_path_buf(),
        title: "Firefox search/homepage locked by enterprise policy".into(),
        severity: Severity::Medium,
        reasons,
    })
}
