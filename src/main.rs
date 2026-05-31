//! Armadillo — a blazing-fast macOS antivirus (CLI + TUI).

mod cli;
mod config;
mod engine;
mod logging;
mod macos;
mod quarantine;
mod report;
mod scan;
mod scan_cmd;
mod tui;
mod update;

use std::io::IsTerminal;
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use owo_colors::OwoColorize;

use cli::{AuditArgs, Cli, Command, QuarantineCmd, ScanArgs};
use config::{Paths, Settings};
use engine::hashdb::HashDb;
use engine::yara::YaraEngine;
use engine::{EngineConfig, ScanEngine};
use scan::{targets, ScanRequest};
use scan_cmd::ScanCliOpts;

fn main() {
    let cli = Cli::parse();
    let color = !cli.global.no_color && std::io::stdout().is_terminal();

    // The TUI logs to a file; everything else logs to stderr.
    let _guard = if matches!(cli.command, Command::Tui) {
        logging::init_tui(cli.global.verbose)
    } else {
        logging::init_cli(cli.global.verbose);
        None
    };

    if let Err(e) = run(cli, color) {
        eprintln!("{} {e:#}", "error:".red().bold());
        std::process::exit(2);
    }
}

fn run(cli: Cli, color: bool) -> Result<()> {
    let _ = Paths::ensure();
    // On first run, drop a config template the user can edit (abuse.ch key, etc.).
    if !Paths::config_file().exists() {
        let _ = Settings::default().save();
    }
    let settings = Settings::load();

    match cli.command {
        Command::Scan(args) => cmd_scan(args, &settings, color),
        Command::Quarantine { action } => cmd_quarantine(action, color),
        Command::Status => cmd_status(),
        Command::Audit(args) => cmd_audit(args, color),
        Command::Update(args) => update::run(args.dry_run, color),
        Command::Tui => {
            let engine = load_engine(false, &settings)?;
            tui::run(Arc::new(engine))
        }
    }
}

fn cmd_scan(args: ScanArgs, settings: &Settings, color: bool) -> Result<()> {
    let engine = load_engine(args.no_codesign, settings)?;
    let (request, kind) = build_request(&args, settings);

    if request.roots.is_empty() {
        println!("nothing to scan (no matching paths exist).");
        return Ok(());
    }

    let opts = ScanCliOpts {
        json: args.json,
        no_prompt: args.no_prompt,
        quarantine_all: args.quarantine_all,
    };
    let code = scan_cmd::run(Arc::new(engine), request, kind, opts, color)?;
    std::process::exit(code);
}

fn build_request(args: &ScanArgs, settings: &Settings) -> (ScanRequest, &'static str) {
    if let Some(path) = &args.path {
        (ScanRequest::new(vec![path.clone()]), "custom")
    } else if args.full {
        let mut excludes = targets::default_excludes();
        excludes.extend(settings.extra_excludes.clone());
        (
            ScanRequest::new(targets::full_targets()).with_excludes(excludes),
            "full",
        )
    } else {
        (ScanRequest::new(targets::quick_targets()), "quick")
    }
}

/// Build the engine: bundled rules compiled fresh + any user custom rules, plus
/// bundled hashes merged with any downloaded hash feeds.
fn load_engine(no_codesign: bool, settings: &Settings) -> Result<ScanEngine> {
    let custom = update::custom_rules();
    let yara = YaraEngine::with_extra(&custom).or_else(|_| YaraEngine::bundled())?;

    let mut hashes = HashDb::bundled();
    if let Ok(rd) = std::fs::read_dir(Paths::defs_dir()) {
        for entry in rd.flatten() {
            let p = entry.path();
            if p.extension().and_then(|e| e.to_str()) == Some("hashes") {
                let _ = hashes.merge_file(&p);
            }
        }
    }

    let config = EngineConfig {
        check_codesign: !no_codesign,
        max_file_size: settings.max_file_size,
    };
    Ok(ScanEngine::new(yara, hashes, config))
}

fn cmd_quarantine(action: QuarantineCmd, color: bool) -> Result<()> {
    match action {
        QuarantineCmd::List => {
            let items = quarantine::list()?;
            if items.is_empty() {
                println!("quarantine is empty.");
                return Ok(());
            }
            println!("{} quarantined item(s):", items.len());
            for e in items {
                let short = &e.id[..8];
                let id = if color {
                    short.cyan().to_string()
                } else {
                    short.to_string()
                };
                println!(
                    "  {id}  {}  [{}]  {}",
                    e.quarantined_at,
                    e.verdict,
                    e.original_path.display()
                );
            }
        }
        QuarantineCmd::Restore { id } => {
            let dest = quarantine::restore(&id)?;
            println!("{} restored to {}", "✓".green_if(color), dest.display());
        }
        QuarantineCmd::Delete { id } => {
            quarantine::delete(&id)?;
            println!("{} deleted", "✓".green_if(color));
        }
        QuarantineCmd::Add { path } => {
            let entry = quarantine::quarantine_manual(&path)?;
            println!(
                "{} quarantined {} → id {}",
                "✓".green_if(color),
                path.display(),
                &entry.id[..8]
            );
        }
    }
    Ok(())
}

fn cmd_audit(args: AuditArgs, color: bool) -> Result<()> {
    let report = macos::run_audit();
    if args.json {
        println!("{}", report.to_json());
    } else {
        report.print_human(color);
    }
    // Nonzero exit if anything suspicious turned up.
    if !report.findings.is_empty() {
        std::process::exit(1);
    }
    Ok(())
}

fn cmd_status() -> Result<()> {
    let settings = Settings::load();
    let state = config::State::load();
    let engine = load_engine(true, &settings)?;
    let quarantined = quarantine::list().map(|v| v.len()).unwrap_or(0);

    let custom = update::custom_rules();
    let defs_source = if custom.is_empty() {
        "bundled".to_string()
    } else {
        format!("bundled + {} custom rule file(s)", custom.len())
    };

    println!("Armadillo — status");
    println!("  definitions   : {defs_source}");
    println!("  YARA rules    : {}", engine.yara().rule_count());
    println!("  hash sigs     : {}", engine.hash_count());
    println!(
        "  last update   : {}",
        state.last_update.as_deref().unwrap_or("never")
    );
    println!("  quarantined   : {quarantined}");
    println!(
        "  abuse.ch key  : {}",
        if settings.abuse_ch_auth_key.is_some() {
            "configured"
        } else {
            "not set"
        }
    );
    println!("  data dir      : {}", Paths::data_dir().display());
    println!("  config file   : {}", Paths::config_file().display());
    Ok(())
}

/// Small helper so call sites can color a value behind a runtime flag.
trait GreenIf: std::fmt::Display + Sized {
    fn green_if(self, color: bool) -> String {
        if color {
            self.green().to_string()
        } else {
            self.to_string()
        }
    }
}
impl<T: std::fmt::Display> GreenIf for T {}
