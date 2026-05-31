//! macOS persistence & adware audit (Engine 5).
//!
//! Where Mac malware actually lives: LaunchAgents/Daemons, shell-startup files,
//! cron/periodic jobs, browser hijacks, and configuration profiles. Each check
//! scores on *combinations* of traits (a temp-dir program path AND auto-restart
//! AND an Apple-spoofing label) rather than presence alone, to keep precision
//! high — legitimate software uses all of these mechanisms too.

pub mod browser;
pub mod launchd;
pub mod profiles;
pub mod startup;

use std::path::PathBuf;

use owo_colors::OwoColorize;
use serde::Serialize;

use crate::engine::verdict::Severity;

/// Which persistence/adware surface a finding came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditCategory {
    LaunchAgent,
    LaunchDaemon,
    ShellStartup,
    Cron,
    Periodic,
    Profile,
    Browser,
}

impl AuditCategory {
    pub fn label(self) -> &'static str {
        match self {
            AuditCategory::LaunchAgent => "launch-agent",
            AuditCategory::LaunchDaemon => "launch-daemon",
            AuditCategory::ShellStartup => "shell-startup",
            AuditCategory::Cron => "cron",
            AuditCategory::Periodic => "periodic",
            AuditCategory::Profile => "config-profile",
            AuditCategory::Browser => "browser",
        }
    }
}

/// A single suspicious persistence/adware artifact.
#[derive(Debug, Clone, Serialize)]
pub struct AuditFinding {
    pub category: AuditCategory,
    pub location: PathBuf,
    pub title: String,
    pub severity: Severity,
    pub reasons: Vec<String>,
}

/// Full audit result.
#[derive(Debug, Serialize)]
pub struct AuditReport {
    pub findings: Vec<AuditFinding>,
    pub inspected: usize,
}

impl AuditReport {
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".into())
    }

    pub fn print_human(&self, color: bool) {
        println!();
        if self.findings.is_empty() {
            let msg = "✓ No suspicious persistence or adware artifacts found.";
            println!("{}", if color { msg.green().bold().to_string() } else { msg.to_string() });
        } else {
            let mut findings = self.findings.clone();
            findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
            for f in &findings {
                let sev = sev_tag(f.severity, color);
                let cat = if color {
                    f.category.label().cyan().to_string()
                } else {
                    f.category.label().to_string()
                };
                println!("[{sev}] {cat}  {}", f.title);
                println!("      {}", f.location.display());
                for r in &f.reasons {
                    println!("      • {r}");
                }
                println!();
            }
        }
        println!("{}", if color { "──────── audit summary ────────".dimmed().to_string() } else { "──────── audit summary ────────".to_string() });
        println!("  items inspected : {}", self.inspected);
        println!("  suspicious      : {}", self.findings.len());
        println!();
    }
}

/// Run the full macOS audit.
pub fn run_audit() -> AuditReport {
    let mut findings = Vec::new();
    let mut inspected = 0usize;

    let (mut f, n) = launchd::audit();
    findings.append(&mut f);
    inspected += n;

    let (mut f, n) = startup::audit();
    findings.append(&mut f);
    inspected += n;

    let (mut f, n) = browser::audit();
    findings.append(&mut f);
    inspected += n;

    let (mut f, n) = profiles::audit();
    findings.append(&mut f);
    inspected += n;

    AuditReport { findings, inspected }
}

/// Map an accumulated suspicion score to a severity.
pub(crate) fn severity_from_score(score: u32) -> Severity {
    if score >= 70 {
        Severity::Critical
    } else if score >= 50 {
        Severity::High
    } else if score >= 25 {
        Severity::Medium
    } else {
        Severity::Low
    }
}

/// True if a program path lives in a genuinely anomalous staging location for a
/// persistent launch item. Deliberately narrow: `~/Library/Application Support`
/// and `~/Library/Caches` are excluded because the vast majority of *legitimate*
/// per-user agents (Google, Steam, Dropbox, …) run from there — flagging those
/// would bury real detections in noise.
pub(crate) fn is_writable_path(path: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "/tmp/",
        "/private/tmp/",
        "/var/folders/",
        "/private/var/folders/",
        "/Users/Shared/",
    ];
    if PREFIXES.iter().any(|p| path.starts_with(p)) {
        return true;
    }
    if let Some(home) = dirs::home_dir() {
        let home = home.to_string_lossy();
        // A launch item running out of Downloads is genuinely odd.
        if path.starts_with(&format!("{home}/Downloads/")) {
            return true;
        }
    }
    false
}

/// Minimum accumulated score for an audit check to emit a finding. Below this we
/// stay silent (a single weak trait like RunAtLoad+KeepAlive is not suspicious).
pub(crate) const AUDIT_EMIT_THRESHOLD: u32 = 25;

fn sev_tag(sev: Severity, color: bool) -> String {
    let s = sev.label().to_uppercase();
    if !color {
        return s;
    }
    match sev {
        Severity::Critical | Severity::High => s.red().bold().to_string(),
        Severity::Medium => s.yellow().bold().to_string(),
        _ => s.cyan().to_string(),
    }
}
