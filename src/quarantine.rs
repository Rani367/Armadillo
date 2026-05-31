//! Quarantine vault: neutralizes a threat by moving it into a private store with
//! its executable bits stripped, recording enough metadata for a faithful,
//! reversible restore.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config::Paths;
use crate::engine::verdict::Threat;

/// Metadata persisted alongside each quarantined payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineEntry {
    pub id: String,
    pub original_path: PathBuf,
    pub sha256: String,
    pub size: u64,
    /// Original unix mode, so restore re-applies the exact permissions.
    pub original_mode: u32,
    pub quarantined_at: String,
    pub verdict: String,
    pub detections: Vec<String>,
}

impl QuarantineEntry {
    fn dir(&self) -> PathBuf {
        Paths::quarantine_dir().join(&self.id)
    }
    fn payload(&self) -> PathBuf {
        self.dir().join("payload")
    }
    fn meta_path(&self) -> PathBuf {
        self.dir().join("metadata.json")
    }
}

/// Move a flagged file into the vault.
pub fn quarantine_threat(threat: &Threat) -> Result<QuarantineEntry> {
    let detections = threat
        .detections
        .iter()
        .map(|d| format!("{}:{} — {}", d.engine.label(), d.name, d.reason))
        .collect();
    quarantine_path(
        &threat.path,
        &threat.sha256,
        threat.verdict.label(),
        detections,
    )
}

/// Manually quarantine an arbitrary path.
pub fn quarantine_manual(path: &Path) -> Result<QuarantineEntry> {
    let data = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let sha256 = crate::engine::hashdb::sha256_hex(&data);
    quarantine_path(path, &sha256, "manual", vec!["manually quarantined".into()])
}

fn quarantine_path(
    path: &Path,
    sha256: &str,
    verdict: &str,
    detections: Vec<String>,
) -> Result<QuarantineEntry> {
    Paths::ensure()?;
    let meta = std::fs::symlink_metadata(path)
        .with_context(|| format!("stat {}", path.display()))?;
    if !meta.is_file() {
        bail!("{} is not a regular file", path.display());
    }

    let entry = QuarantineEntry {
        id: Uuid::new_v4().to_string(),
        original_path: path.to_path_buf(),
        sha256: sha256.to_string(),
        size: meta.len(),
        original_mode: meta.permissions().mode(),
        quarantined_at: chrono::Local::now().to_rfc3339(),
        verdict: verdict.to_string(),
        detections,
    };

    std::fs::create_dir_all(entry.dir())?;
    move_file(path, &entry.payload())
        .with_context(|| format!("moving {} into quarantine", path.display()))?;

    // Strip all execute/write bits on the stored payload so it cannot run.
    let mut perms = std::fs::metadata(entry.payload())?.permissions();
    perms.set_mode(0o400);
    std::fs::set_permissions(entry.payload(), perms)?;

    let json = serde_json::to_string_pretty(&entry)?;
    std::fs::write(entry.meta_path(), json)?;
    Ok(entry)
}

/// List all quarantined entries (newest first).
pub fn list() -> Result<Vec<QuarantineEntry>> {
    let dir = Paths::quarantine_dir();
    let mut out = Vec::new();
    if !dir.exists() {
        return Ok(out);
    }
    for ent in std::fs::read_dir(&dir)? {
        let ent = ent?;
        let meta_path = ent.path().join("metadata.json");
        if let Ok(text) = std::fs::read_to_string(&meta_path) {
            if let Ok(entry) = serde_json::from_str::<QuarantineEntry>(&text) {
                out.push(entry);
            }
        }
    }
    out.sort_by(|a, b| b.quarantined_at.cmp(&a.quarantined_at));
    Ok(out)
}

fn find(id: &str) -> Result<QuarantineEntry> {
    // Accept a unique id prefix for convenience.
    let matches: Vec<_> = list()?
        .into_iter()
        .filter(|e| e.id == id || e.id.starts_with(id))
        .collect();
    match matches.len() {
        0 => Err(anyhow!("no quarantine entry matching '{id}'")),
        1 => Ok(matches.into_iter().next().unwrap()),
        _ => Err(anyhow!("ambiguous id '{id}' — provide more characters")),
    }
}

/// Restore a quarantined file to its original location with original permissions.
pub fn restore(id: &str) -> Result<PathBuf> {
    let entry = find(id)?;
    let dest = &entry.original_path;
    if dest.exists() {
        bail!("refusing to restore: {} already exists", dest.display());
    }
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    move_file(&entry.payload(), dest)?;
    let mut perms = std::fs::metadata(dest)?.permissions();
    perms.set_mode(entry.original_mode);
    std::fs::set_permissions(dest, perms)?;
    std::fs::remove_dir_all(entry.dir())?;
    Ok(dest.clone())
}

/// Permanently delete a quarantined entry.
pub fn delete(id: &str) -> Result<()> {
    let entry = find(id)?;
    std::fs::remove_dir_all(entry.dir())?;
    Ok(())
}

/// Move a file, falling back to copy+remove across filesystems (EXDEV).
fn move_file(from: &Path, to: &Path) -> Result<()> {
    match std::fs::rename(from, to) {
        Ok(()) => Ok(()),
        Err(_) => {
            std::fs::copy(from, to)
                .with_context(|| format!("copying {} -> {}", from.display(), to.display()))?;
            std::fs::remove_file(from)
                .with_context(|| format!("removing original {}", from.display()))?;
            Ok(())
        }
    }
}
