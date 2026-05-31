//! Filesystem locations and persisted settings.

use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Resolves Armadillo's standard directories under the user's home.
pub struct Paths;

impl Paths {
    /// `~/Library/Application Support/armadillo` (or platform data dir).
    pub fn data_dir() -> PathBuf {
        dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("armadillo")
    }

    /// `~/.config/armadillo` (or platform config dir).
    pub fn config_dir() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("armadillo")
    }

    /// Quarantine vault root.
    pub fn quarantine_dir() -> PathBuf {
        Self::data_dir().join("quarantine")
    }

    /// Updated-definitions directory (preferred over bundled when present).
    pub fn defs_dir() -> PathBuf {
        Self::data_dir().join("defs")
    }

    pub fn log_dir() -> PathBuf {
        Self::data_dir().join("logs")
    }

    pub fn config_file() -> PathBuf {
        Self::config_dir().join("config.json")
    }

    pub fn state_file() -> PathBuf {
        Self::data_dir().join("state.json")
    }

    /// Create the data/config/quarantine/defs directories if missing.
    pub fn ensure() -> Result<()> {
        for dir in [
            Self::data_dir(),
            Self::config_dir(),
            Self::quarantine_dir(),
            Self::defs_dir(),
            Self::log_dir(),
        ] {
            std::fs::create_dir_all(&dir)
                .with_context(|| format!("creating {}", dir.display()))?;
        }
        Ok(())
    }
}

/// Persisted user settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Free abuse.ch Auth-Key for MalwareBazaar/ThreatFox feeds (optional).
    pub abuse_ch_auth_key: Option<String>,
    /// Additional paths to exclude from full scans.
    pub extra_excludes: Vec<PathBuf>,
    /// Max file size (bytes) to scan.
    pub max_file_size: u64,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            abuse_ch_auth_key: None,
            extra_excludes: Vec::new(),
            max_file_size: crate::engine::DEFAULT_MAX_FILE_SIZE,
        }
    }
}

impl Settings {
    pub fn load() -> Self {
        let path = Paths::config_file();
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) -> Result<()> {
        Paths::ensure()?;
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(Paths::config_file(), json).context("writing config")?;
        Ok(())
    }
}

/// Persisted runtime state (definition version, last update / scan).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    pub last_update: Option<String>,
    pub feed_hash_count: u64,
    pub rules_updated: bool,
    pub last_scan: Option<String>,
}

impl State {
    pub fn load() -> Self {
        std::fs::read_to_string(Paths::state_file())
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) -> Result<()> {
        Paths::ensure()?;
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(Paths::state_file(), json).context("writing state")?;
        Ok(())
    }
}
