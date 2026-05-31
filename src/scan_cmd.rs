//! The `scan` CLI command: drives a scan with a live `indicatif` progress bar and
//! interactive per-threat triage (the user's chosen default behaviour).

use std::io::{BufRead, IsTerminal, Write};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use crossbeam_channel::RecvTimeoutError;
use indicatif::{ProgressBar, ProgressStyle};
use owo_colors::OwoColorize;

use crate::engine::verdict::Threat;
use crate::engine::ScanEngine;
use crate::report::{self, ScanReport};
use crate::scan::progress::{Counters, ScanEvent};
use crate::scan::{self, ScanRequest};
use crate::quarantine;

/// Options forwarded from the CLI to the scan runner.
pub struct ScanCliOpts {
    pub json: bool,
    pub no_prompt: bool,
    pub quarantine_all: bool,
}

/// Run a scan and handle reporting/triage. Returns the process exit code.
pub fn run(
    engine: Arc<ScanEngine>,
    request: ScanRequest,
    kind: &str,
    opts: ScanCliOpts,
    color: bool,
) -> Result<i32> {
    let counters = Counters::new();
    let cancel = Arc::new(AtomicBool::new(false));
    let (tx, rx) = crossbeam_channel::unbounded::<ScanEvent>();

    let start = Instant::now();

    // Background scanning thread (rayon runs inside).
    let scan_handle = {
        let engine = engine.clone();
        let counters = counters.clone();
        let cancel = cancel.clone();
        std::thread::spawn(move || scan::run_scan(engine, request, tx, counters, cancel))
    };

    // Live progress (suppressed in JSON mode / when not a TTY).
    let show_bar = !opts.json && std::io::stderr().is_terminal();
    let pb = if show_bar {
        let pb = ProgressBar::new_spinner();
        pb.set_message("enumerating files…");
        pb.enable_steady_tick(Duration::from_millis(120));
        Some(pb)
    } else {
        None
    };

    let mut threats: Vec<Threat> = Vec::new();
    let mut cancelled = false;

    loop {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(ScanEvent::Started { total }) => {
                if let Some(pb) = &pb {
                    pb.set_length(total);
                    pb.set_style(
                        ProgressStyle::with_template(
                            "{spinner:.cyan} [{bar:40.cyan/blue}] {pos}/{len} files · {msg}",
                        )
                        .unwrap()
                        .progress_chars("=>-"),
                    );
                }
            }
            Ok(ScanEvent::Threat(t)) => threats.push(*t),
            Ok(ScanEvent::Error { path, message }) => {
                tracing::debug!(path = %path.display(), message, "scan error");
            }
            Ok(ScanEvent::Finished { cancelled: c }) => {
                cancelled = c;
                break;
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
        if let Some(pb) = &pb {
            let snap = counters.snapshot();
            pb.set_position(snap.scanned);
            pb.set_message(format!("{} threats", snap.threats));
        }
    }

    let _ = scan_handle.join();
    if let Some(pb) = &pb {
        pb.finish_and_clear();
    }

    // Sort: malicious first, then by score.
    threats.sort_by(|a, b| {
        b.verdict
            .label()
            .cmp(a.verdict.label())
            .then(b.score.cmp(&a.score))
    });

    let snap = counters.snapshot();
    let report = ScanReport {
        kind: kind.to_string(),
        threats,
        files_scanned: snap.scanned,
        bytes_scanned: snap.bytes,
        skipped: snap.skipped,
        errors: snap.errors,
        cancelled,
        duration_secs: start.elapsed().as_secs_f64(),
    };

    if opts.json {
        println!("{}", report.to_json());
        return Ok(exit_code(&report));
    }

    let stdin_tty = std::io::stdin().is_terminal();
    if opts.quarantine_all && !report.threats.is_empty() {
        println!();
        for t in &report.threats {
            report::print_threat(t, color);
            auto_quarantine(t, color);
        }
        report.print_summary(color);
    } else if !opts.no_prompt && stdin_tty && !report.threats.is_empty() {
        println!();
        triage(&report.threats, color)?;
        report.print_summary(color);
    } else {
        report.print_human(color);
    }

    Ok(exit_code(&report))
}

fn exit_code(report: &ScanReport) -> i32 {
    if report.malicious() > 0 {
        1
    } else if report.suspicious() > 0 {
        2
    } else {
        0
    }
}

/// Interactive per-threat triage.
fn triage(threats: &[Threat], color: bool) -> Result<()> {
    let stdin = std::io::stdin();
    let mut always = false;

    for t in threats {
        report::print_threat(t, color);
        if always {
            auto_quarantine(t, color);
            continue;
        }
        loop {
            print!(
                "   action [{}]uarantine / [{}]elete / [{}]gnore / [{}]lways-quarantine (Enter=ignore): ",
                "q".cyan(),
                "d".red(),
                "i".green(),
                "a".yellow()
            );
            std::io::stdout().flush()?;
            let mut line = String::new();
            stdin.lock().read_line(&mut line)?;
            match line.trim().to_ascii_lowercase().as_str() {
                "q" => {
                    do_quarantine(t, color);
                    break;
                }
                "d" => {
                    do_delete(t, color);
                    break;
                }
                "a" => {
                    always = true;
                    do_quarantine(t, color);
                    break;
                }
                "" | "i" => {
                    println!("   {} left in place", "ignored —".dimmed());
                    break;
                }
                _ => println!("   please choose q, d, i, or a"),
            }
        }
        println!();
    }
    Ok(())
}

fn auto_quarantine(t: &Threat, color: bool) {
    do_quarantine(t, color);
}

fn do_quarantine(t: &Threat, _color: bool) {
    match quarantine::quarantine_threat(t) {
        Ok(entry) => println!(
            "   {} quarantined → id {}",
            "✓".green(),
            &entry.id[..8]
        ),
        Err(e) => println!("   {} could not quarantine: {e}", "✗".red()),
    }
}

fn do_delete(t: &Threat, _color: bool) {
    match std::fs::remove_file(&t.path) {
        Ok(()) => println!("   {} deleted", "✓".green()),
        Err(e) => println!("   {} could not delete: {e}", "✗".red()),
    }
}

