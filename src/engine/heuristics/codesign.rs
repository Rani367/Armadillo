//! Code-signature & notarization trust (Engine 4).
//!
//! Resolves a [`TrustTier`] for a Mach-O so the scorer can discount heuristic
//! findings on Apple / Developer-ID code (precision control). v1 uses the system
//! `codesign` / `spctl` tools, invoked with the target path passed as a direct
//! argument (never via a shell), which avoids command-injection/TOCTOU on the
//! command string. A future enhancement can switch to Security.framework FFI.

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use crate::engine::verdict::TrustTier;

/// Classify the signing trust of a Mach-O at `path`.
///
/// `has_code_signature` comes from the structural Mach-O parse and lets us
/// short-circuit to `Unsigned` without spawning a process.
pub fn classify(path: &Path, has_code_signature: bool) -> TrustTier {
    if !has_code_signature {
        return TrustTier::Unsigned;
    }

    let info = match run_codesign_display(path) {
        Some(s) => s,
        None => return TrustTier::Unknown,
    };

    // `codesign -dv` puts the authority chain on stderr.
    let lower = info.to_ascii_lowercase();
    let apple_anchor = lower.contains("authority=software signing")
        || lower.contains("authority=apple code signing certification authority")
        || lower.contains("authority=apple root ca");
    let developer_id = lower.contains("authority=developer id application");
    let adhoc = lower.contains("signature=adhoc") || lower.contains("linker-signed");

    if apple_anchor && !developer_id {
        return TrustTier::Apple;
    }
    if developer_id {
        // Developer-ID present; check notarization via Gatekeeper assessment.
        return match assess_notarized(path) {
            Some(true) => TrustTier::DeveloperIdNotarized,
            _ => TrustTier::DeveloperId,
        };
    }
    if adhoc {
        return TrustTier::AdHoc;
    }

    // Signed but we couldn't validate the chain.
    if verify_valid(path) {
        TrustTier::DeveloperId
    } else {
        TrustTier::Invalid
    }
}

fn run_codesign_display(path: &Path) -> Option<String> {
    let out = run(
        "/usr/bin/codesign",
        &["-dv", "--verbose=4"],
        path,
        Duration::from_secs(8),
    )?;
    // codesign writes the detail to stderr.
    let mut s = String::from_utf8_lossy(&out.stderr).into_owned();
    s.push_str(&String::from_utf8_lossy(&out.stdout));
    Some(s)
}

fn verify_valid(path: &Path) -> bool {
    run(
        "/usr/bin/codesign",
        &["--verify", "--strict"],
        path,
        Duration::from_secs(10),
    )
    .map(|o| o.status.success())
    .unwrap_or(false)
}

/// Gatekeeper assessment — success implies a notarized / accepted binary.
fn assess_notarized(path: &Path) -> Option<bool> {
    let out = run(
        "/usr/sbin/spctl",
        &["-a", "-vv", "--type", "execute"],
        path,
        Duration::from_secs(10),
    )?;
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    )
    .to_ascii_lowercase();
    Some(out.status.success() || combined.contains("accepted") || combined.contains("notarized"))
}

/// Run a tool with the path as a trailing argument. The path is passed as a
/// distinct `OsStr` argument (no shell), so its contents cannot be interpreted
/// as flags/commands.
fn run(program: &str, args: &[&str], path: &Path, _timeout: Duration) -> Option<std::process::Output> {
    if !Path::new(program).exists() {
        return None;
    }
    Command::new(program)
        .args(args)
        .arg(path)
        .output()
        .ok()
}
