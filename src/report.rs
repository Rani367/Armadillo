//! Human-readable and JSON reporting of scan results.

use owo_colors::OwoColorize;
use serde::Serialize;

use crate::engine::verdict::{Severity, Threat, Verdict};

/// Aggregated outcome of a scan run.
#[derive(Debug, Serialize)]
pub struct ScanReport {
    pub kind: String,
    pub threats: Vec<Threat>,
    pub files_scanned: u64,
    pub bytes_scanned: u64,
    pub skipped: u64,
    pub errors: u64,
    pub cancelled: bool,
    pub duration_secs: f64,
}

impl ScanReport {
    pub fn malicious(&self) -> usize {
        self.threats
            .iter()
            .filter(|t| t.verdict == Verdict::Malicious)
            .count()
    }

    pub fn suspicious(&self) -> usize {
        self.threats
            .iter()
            .filter(|t| t.verdict == Verdict::Suspicious)
            .count()
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".into())
    }

    /// Print the full report (per-threat blocks + summary) to stdout.
    pub fn print_human(&self, color: bool) {
        println!();
        if self.threats.is_empty() {
            let msg = "✓ No threats found.";
            println!("{}", if color { msg.green().bold().to_string() } else { msg.to_string() });
        } else {
            for t in &self.threats {
                print_threat(t, color);
            }
        }
        self.print_summary(color);
    }

    /// Print only the summary block (used after interactive triage already
    /// printed each threat).
    pub fn print_summary(&self, color: bool) {
        println!();
        println!("{}", dim("──────── scan summary ────────", color));
        println!("  scan type      : {}", self.kind);
        println!("  files scanned  : {}", self.files_scanned);
        println!("  data scanned   : {}", human_bytes(self.bytes_scanned));
        println!(
            "  threats        : {} malicious, {} suspicious",
            paint_count(self.malicious(), Severity::Critical, color),
            paint_count(self.suspicious(), Severity::Medium, color),
        );
        if self.skipped > 0 {
            println!("  skipped        : {} (size cap / unreadable)", self.skipped);
        }
        if self.errors > 0 {
            println!("  errors         : {}", self.errors);
        }
        if self.cancelled {
            println!("  {}", "scan was cancelled before completion".yellow());
        }
        println!("  elapsed        : {:.2}s", self.duration_secs);
        println!();
    }
}

/// Print a single threat block (used live during a scan and in the report).
pub fn print_threat(t: &Threat, color: bool) {
    let verdict = verdict_tag(t.verdict, color);
    let sev = severity_tag(t.severity, color);
    println!("{verdict} [{sev}] {}", t.path.display().bold_if(color));
    println!("      score {} · trust {} · {}", t.score, t.trust.label(), short_hash(&t.sha256));
    for d in &t.detections {
        println!(
            "      {} {} — {}",
            "•".dim_if(color),
            format!("{}:{}", d.engine.label(), d.name).cyan_if(color),
            d.reason,
        );
    }
}

fn verdict_tag(v: Verdict, color: bool) -> String {
    let s = format!(" {} ", v.label().to_uppercase());
    if !color {
        return format!("[{}]", v.label().to_uppercase());
    }
    match v {
        Verdict::Malicious => s.on_red().white().bold().to_string(),
        Verdict::Suspicious => s.on_yellow().black().bold().to_string(),
        Verdict::Clean => s.on_green().black().to_string(),
    }
}

fn severity_tag(sev: Severity, color: bool) -> String {
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

fn paint_count(n: usize, sev: Severity, color: bool) -> String {
    if !color || n == 0 {
        return n.to_string();
    }
    match sev {
        Severity::Critical | Severity::High => n.red().bold().to_string(),
        _ => n.yellow().bold().to_string(),
    }
}

fn dim(s: &str, color: bool) -> String {
    if color {
        s.dimmed().to_string()
    } else {
        s.to_string()
    }
}

fn short_hash(h: &str) -> String {
    if h.len() > 16 {
        format!("sha256:{}…", &h[..16])
    } else {
        h.to_string()
    }
}

/// Format a byte count in human units.
pub fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut size = n as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} B")
    } else {
        format!("{size:.1} {}", UNITS[unit])
    }
}

/// Small extension trait so call sites stay readable with a runtime color flag.
trait PaintIf: Sized + std::fmt::Display {
    fn bold_if(self, color: bool) -> String {
        if color {
            self.bold().to_string()
        } else {
            self.to_string()
        }
    }
    fn dim_if(self, color: bool) -> String {
        if color {
            self.dimmed().to_string()
        } else {
            self.to_string()
        }
    }
    fn cyan_if(self, color: bool) -> String {
        if color {
            self.cyan().to_string()
        } else {
            self.to_string()
        }
    }
}

impl<T: std::fmt::Display> PaintIf for T {}
