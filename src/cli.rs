//! Command-line surface (clap derive).

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "armadillo",
    version,
    about = "Armadillo — a blazing-fast macOS antivirus (CLI + TUI)",
    long_about = "Armadillo scans for malware, spyware, ransomware and adware using a \
                  defense-in-depth engine: known-bad hashes, YARA rules, heuristics \
                  (entropy / Mach-O / code-signature), and a macOS persistence audit."
)]
pub struct Cli {
    #[command(flatten)]
    pub global: GlobalOpts,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Args)]
pub struct GlobalOpts {
    /// Verbose logging.
    #[arg(long, short, global = true)]
    pub verbose: bool,
    /// Disable colored output.
    #[arg(long, global = true)]
    pub no_color: bool,
}

#[derive(Subcommand)]
pub enum Command {
    /// Scan files for malware (defaults to a quick scan of high-signal locations).
    Scan(ScanArgs),
    /// Audit macOS persistence & adware locations (no file-content scan).
    Audit(AuditArgs),
    /// Launch the interactive TUI dashboard.
    Tui,
    /// Manage the quarantine vault.
    Quarantine {
        #[command(subcommand)]
        action: QuarantineCmd,
    },
    /// Update malware definitions (YARA rules + hash feeds).
    Update(UpdateArgs),
    /// Show definition version, last scan, and counts.
    Status,
}

#[derive(Args)]
pub struct ScanArgs {
    /// Path to scan (file or directory). Overrides --quick/--full.
    pub path: Option<PathBuf>,
    /// Quick scan of high-signal locations (the default).
    #[arg(long, conflicts_with_all = ["full", "path"])]
    pub quick: bool,
    /// Full system scan.
    #[arg(long, conflicts_with_all = ["quick", "path"])]
    pub full: bool,
    /// Emit machine-readable JSON instead of the interactive report.
    #[arg(long)]
    pub json: bool,
    /// Report only; never prompt or modify files.
    #[arg(long)]
    pub no_prompt: bool,
    /// Automatically quarantine every detection (no prompt).
    #[arg(long, conflicts_with = "no_prompt")]
    pub quarantine_all: bool,
    /// Skip the (slower, process-spawning) code-signature trust check.
    #[arg(long)]
    pub no_codesign: bool,
}

#[derive(Args)]
pub struct AuditArgs {
    /// Emit machine-readable JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Args)]
pub struct UpdateArgs {
    /// Only print what would be fetched; do not write anything.
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Subcommand)]
pub enum QuarantineCmd {
    /// List quarantined items.
    List,
    /// Restore a quarantined item by id (or unique id prefix).
    Restore {
        id: String,
    },
    /// Permanently delete a quarantined item.
    Delete {
        id: String,
    },
    /// Manually quarantine a file.
    Add {
        path: PathBuf,
    },
}
