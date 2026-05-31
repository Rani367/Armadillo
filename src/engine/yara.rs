//! YARA pattern engine (Engine 2) backed by `yara-x` (VirusTotal's pure-Rust
//! implementation). Catches malware families & variants, not just exact files.
//!
//! Rule *sources* are embedded at build time and compiled once at startup; a
//! single `Rules` object (Send + Sync) is shared behind an `Arc`, and each scan
//! creates its own `Scanner` (which is `!Send`, hence one per call/thread).

use std::sync::Arc;

use anyhow::{anyhow, Result};
use yara_x::{Compiler, Rules, Scanner};

use crate::engine::verdict::{Detection, Engine, Severity};

/// Bundled rule sources: (namespace, YARA source text).
const BUNDLED_RULES: &[(&str, &str)] = &[
    ("eicar", include_str!("../../rules/eicar.yar")),
    ("macos", include_str!("../../rules/macos_malware.yar")),
];

#[derive(Clone)]
pub struct YaraEngine {
    rules: Arc<Rules>,
    rule_count: usize,
}

impl YaraEngine {
    /// Compile the bundled rule set.
    pub fn bundled() -> Result<Self> {
        Self::with_extra(&[])
    }

    /// Compile the bundled rules plus any extra `(namespace, source)` rule files
    /// (user rules from `<defs>/custom/`). Compilation is fast, so this runs
    /// fresh on every startup — there is no persisted blob to go stale when the
    /// bundled rules are upgraded.
    pub fn with_extra(extra: &[(String, String)]) -> Result<Self> {
        let mut compiler = Compiler::new();
        for (ns, src) in BUNDLED_RULES {
            compiler.new_namespace(ns);
            compiler
                .add_source(*src)
                .map_err(|e| anyhow!("compiling bundled namespace '{ns}': {e}"))?;
        }
        for (ns, src) in extra {
            compiler.new_namespace(ns.as_str());
            compiler
                .add_source(src.as_str())
                .map_err(|e| anyhow!("compiling custom rule '{ns}': {e}"))?;
        }
        let rules = compiler.build();
        let rule_count = rules.iter().count();
        Ok(Self {
            rules: Arc::new(rules),
            rule_count,
        })
    }

    pub fn rule_count(&self) -> usize {
        self.rule_count
    }

    /// Scan a byte slice and return any matching rules as definitive detections.
    pub fn scan(&self, data: &[u8]) -> Vec<Detection> {
        let mut scanner = Scanner::new(&self.rules);
        let mut out = Vec::new();
        if let Ok(results) = scanner.scan(data) {
            for rule in results.matching_rules() {
                let id = rule.identifier().to_string();
                let severity = if id.to_ascii_uppercase().contains("EICAR") {
                    Severity::Critical
                } else {
                    Severity::High
                };
                out.push(Detection::new(
                    Engine::Yara,
                    id.clone(),
                    100,
                    severity,
                    true,
                    format!("matched YARA rule '{id}'"),
                ));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_rules_compile() {
        let eng = YaraEngine::bundled().expect("rules compile");
        assert!(eng.rule_count() >= 3);
    }

    #[test]
    fn detects_eicar() {
        let eng = YaraEngine::bundled().unwrap();
        let eicar = br#"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"#;
        let dets = eng.scan(eicar);
        assert!(dets.iter().any(|d| d.name.contains("EICAR")), "got {dets:?}");
    }
}
