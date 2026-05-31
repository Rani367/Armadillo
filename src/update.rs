//! `armadillo update` — refresh malware definitions.
//!
//! Two pure-Rust update paths, both with graceful offline degradation:
//!   1. **Hash feeds** — download known-bad hash lists (abuse.ch URLhaus is open;
//!      MalwareBazaar/ThreatFox need a free Auth-Key) and merge them into a
//!      `feed.hashes` file the engine loads on top of the bundled list.
//!   2. **Rules** — (re)compile the bundled YARA rules together with any user
//!      `*.yar` files dropped in `<defs>/custom/`, serialized to `rules.yarac`.
//!
//! Downloads use `reqwest` with the rustls TLS backend (no OpenSSL).

use std::time::Duration;

use anyhow::{Context, Result};
use owo_colors::OwoColorize;

use crate::config::{Paths, Settings, State};
use crate::engine::hashdb::HashDb;
use crate::engine::yara::YaraEngine;

/// (display name, url) hash feeds to pull.
fn hash_feeds(settings: &Settings) -> Vec<(&'static str, String)> {
    let mut feeds = vec![(
        "URLhaus payloads (open)",
        "https://urlhaus.abuse.ch/downloads/payloads/".to_string(),
    )];
    if settings.abuse_ch_auth_key.is_some() {
        feeds.push((
            "MalwareBazaar SHA-256 (recent)",
            "https://bazaar.abuse.ch/export/txt/sha256/recent/".to_string(),
        ));
    }
    feeds
}

pub fn run(dry_run: bool, color: bool) -> Result<()> {
    Paths::ensure()?;
    let settings = Settings::load();
    let feeds = hash_feeds(&settings);

    println!("{}", header("Armadillo — updating definitions", color));

    if dry_run {
        println!("  (dry-run) would fetch {} hash feed(s):", feeds.len());
        for (name, url) in &feeds {
            println!("    • {name}: {url}");
        }
        println!("  (dry-run) would recompile YARA rules (bundled + custom).");
        return Ok(());
    }

    // ---- 1. hash feeds ----
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent(concat!("armadillo/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("building HTTP client")?;

    let mut db = HashDb::default();
    let mut any_feed_ok = false;
    for (name, url) in &feeds {
        match fetch(&client, url, settings.abuse_ch_auth_key.as_deref()) {
            Ok(text) => {
                let added = db.ingest_str(&text);
                any_feed_ok = true;
                println!("  {} {name}: +{added} hashes", "✓".green_if(color));
            }
            Err(e) => println!("  {} {name}: {e}", "✗".red_if(color)),
        }
    }

    if any_feed_ok && db.len() > 0 {
        let path = Paths::defs_dir().join("feed.hashes");
        std::fs::write(&path, db.to_lines())
            .with_context(|| format!("writing {}", path.display()))?;
        println!("  merged {} hashes → {}", db.len(), path.display());
    } else if !any_feed_ok {
        println!(
            "  {} no hash feeds reachable (offline?) — keeping existing definitions",
            "!".yellow_if(color)
        );
    }

    // ---- 2. YARA rules (bundled + user custom) ----
    // Rules are compiled fresh at every startup, so here we just validate that
    // the bundled set plus any user `<defs>/custom/*.yar` files compile cleanly.
    let custom = custom_rules();
    match YaraEngine::with_extra(&custom) {
        Ok(engine) => println!(
            "  {} {} YARA rule(s) compile ({} custom file(s))",
            "✓".green_if(color),
            engine.rule_count(),
            custom.len()
        ),
        Err(e) => println!("  {} custom rule compilation failed: {e}", "✗".red_if(color)),
    }

    // ---- 3. record state ----
    let mut state = State::load();
    state.last_update = Some(chrono::Local::now().to_rfc3339());
    state.feed_hash_count = db.len() as u64;
    state.rules_updated = !custom.is_empty();
    state.save()?;

    println!("{}", "definitions updated.".green_if(color));
    Ok(())
}

/// Read any user-supplied `*.yar` rule files from `<defs>/custom/`.
pub fn custom_rules() -> Vec<(String, String)> {
    let dir = Paths::defs_dir().join("custom");
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&dir) {
        for entry in rd.flatten() {
            let p = entry.path();
            if p.extension().and_then(|e| e.to_str()) == Some("yar")
                || p.extension().and_then(|e| e.to_str()) == Some("yara")
            {
                if let Ok(src) = std::fs::read_to_string(&p) {
                    let ns = p
                        .file_stem()
                        .map(|s| format!("custom_{}", s.to_string_lossy()))
                        .unwrap_or_else(|| "custom".into());
                    out.push((ns, src));
                }
            }
        }
    }
    out
}

fn fetch(
    client: &reqwest::blocking::Client,
    url: &str,
    auth_key: Option<&str>,
) -> Result<String> {
    let mut req = client.get(url);
    if url.contains("abuse.ch") {
        if let Some(key) = auth_key {
            req = req.header("Auth-Key", key);
        }
    }
    let resp = req.send().with_context(|| format!("GET {url}"))?;
    if !resp.status().is_success() {
        anyhow::bail!("HTTP {}", resp.status());
    }
    resp.text().context("reading response body")
}

/// Local color helpers (kept here to avoid leaking a trait across modules).
trait PaintIf: std::fmt::Display + Sized {
    fn green_if(self, color: bool) -> String {
        if color {
            self.green().to_string()
        } else {
            self.to_string()
        }
    }
    fn red_if(self, color: bool) -> String {
        if color {
            self.red().to_string()
        } else {
            self.to_string()
        }
    }
    fn yellow_if(self, color: bool) -> String {
        if color {
            self.yellow().to_string()
        } else {
            self.to_string()
        }
    }
}
impl<T: std::fmt::Display> PaintIf for T {}

fn header(s: &str, color: bool) -> String {
    if color {
        s.bold().to_string()
    } else {
        s.to_string()
    }
}
