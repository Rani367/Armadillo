//! Core detection vocabulary shared across every engine and front-end:
//! [`Detection`]s contributed by individual engines combine into a weighted
//! [`Threat`] with a final [`Verdict`]. A signer [`TrustTier`] is applied to
//! keep heuristic false-positives under control.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Which detection engine produced a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Engine {
    /// Exact known-malware hash match (SHA-256 / MD5).
    Hash,
    /// YARA pattern rule (`yara-x`).
    Yara,
    /// Shannon-entropy / packing heuristic.
    Entropy,
    /// Mach-O structural red flag.
    MachO,
    /// Code-signature / notarization trust.
    CodeSign,
    /// Script / obfuscation heuristic.
    Script,
    /// macOS persistence / adware audit.
    Persistence,
}

impl Engine {
    pub fn label(self) -> &'static str {
        match self {
            Engine::Hash => "hash",
            Engine::Yara => "yara",
            Engine::Entropy => "entropy",
            Engine::MachO => "mach-o",
            Engine::CodeSign => "codesign",
            Engine::Script => "script",
            Engine::Persistence => "persistence",
        }
    }
}

/// Confidence severity for a single detection or an overall threat.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

/// Final classification of a scanned file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Clean,
    Suspicious,
    Malicious,
}

impl Verdict {
    pub fn label(self) -> &'static str {
        match self {
            Verdict::Clean => "clean",
            Verdict::Suspicious => "suspicious",
            Verdict::Malicious => "malicious",
        }
    }
}

/// Code-signature trust tier — modulates heuristic scoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustTier {
    /// Signed by Apple (`anchor apple`). Heuristics suppressed.
    Apple,
    /// Valid Developer-ID and notarized. Heuristics strongly downweighted.
    DeveloperIdNotarized,
    /// Valid Developer-ID, notarization unknown/unverified.
    DeveloperId,
    /// Ad-hoc or linker-signed (no cert chain). Weak signal only.
    AdHoc,
    /// No code signature at all.
    Unsigned,
    /// Signature present but invalid / revoked.
    Invalid,
    /// Not a Mach-O, or trust could not be evaluated.
    Unknown,
}

impl TrustTier {
    pub fn label(self) -> &'static str {
        match self {
            TrustTier::Apple => "apple",
            TrustTier::DeveloperIdNotarized => "developer-id+notarized",
            TrustTier::DeveloperId => "developer-id",
            TrustTier::AdHoc => "ad-hoc",
            TrustTier::Unsigned => "unsigned",
            TrustTier::Invalid => "invalid",
            TrustTier::Unknown => "unknown",
        }
    }

    /// Multiplier applied to *heuristic* scores for this trust tier.
    /// Apple/Developer-ID code is overwhelmingly benign, so we discount
    /// entropy / Mach-O / script findings on it to avoid false positives.
    /// Hash and YARA matches are NOT discounted (handled separately).
    fn heuristic_multiplier(self) -> f32 {
        match self {
            TrustTier::Apple => 0.0,
            TrustTier::DeveloperIdNotarized => 0.15,
            TrustTier::DeveloperId => 0.4,
            TrustTier::AdHoc => 1.0,
            TrustTier::Unsigned => 1.25,
            TrustTier::Invalid => 1.5,
            TrustTier::Unknown => 1.0,
        }
    }
}

/// A single contribution from one engine toward a file's overall score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detection {
    pub engine: Engine,
    /// Rule id / signature name / heuristic identifier.
    pub name: String,
    /// Points contributed toward the file's score.
    pub score: u32,
    pub severity: Severity,
    /// Whether this detection is, on its own, a definitive verdict
    /// (exact hash match or YARA family match) versus a heuristic signal.
    pub definitive: bool,
    /// Human-readable reason / reason code.
    pub reason: String,
}

impl Detection {
    pub fn new(
        engine: Engine,
        name: impl Into<String>,
        score: u32,
        severity: Severity,
        definitive: bool,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            engine,
            name: name.into(),
            score,
            severity,
            definitive,
            reason: reason.into(),
        }
    }
}

/// Heuristic score thresholds (after trust-tier modulation).
pub const SUSPICIOUS_THRESHOLD: u32 = 35;
pub const MALICIOUS_THRESHOLD: u32 = 70;

/// A flagged file: an aggregation of one or more [`Detection`]s with a final
/// [`Verdict`] and combined score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Threat {
    pub path: PathBuf,
    pub sha256: String,
    pub size: u64,
    pub trust: TrustTier,
    pub score: u32,
    pub verdict: Verdict,
    pub severity: Severity,
    pub detections: Vec<Detection>,
}

impl Threat {
    /// Combine a file's raw detections into a final verdict, applying the
    /// signer trust tier to heuristic (non-definitive) findings.
    pub fn assemble(
        path: PathBuf,
        sha256: String,
        size: u64,
        trust: TrustTier,
        detections: Vec<Detection>,
    ) -> Option<Self> {
        if detections.is_empty() {
            return None;
        }

        let has_definitive = detections.iter().any(|d| d.definitive);

        // Definitive findings (hash/YARA) count at full weight; heuristics are
        // scaled by the trust multiplier.
        let mult = trust.heuristic_multiplier();
        let mut score: f32 = 0.0;
        for d in &detections {
            if d.definitive {
                score += d.score as f32;
            } else {
                score += d.score as f32 * mult;
            }
        }
        let score = score.round() as u32;

        let verdict = if has_definitive || score >= MALICIOUS_THRESHOLD {
            Verdict::Malicious
        } else if score >= SUSPICIOUS_THRESHOLD {
            Verdict::Suspicious
        } else {
            Verdict::Clean
        };

        if verdict == Verdict::Clean {
            return None;
        }

        let severity = detections
            .iter()
            .map(|d| d.severity)
            .max()
            .unwrap_or(Severity::Low);

        Some(Threat {
            path,
            sha256,
            size,
            trust,
            score,
            verdict,
            severity,
            detections,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn det(engine: Engine, score: u32, definitive: bool) -> Detection {
        Detection::new(engine, "t", score, Severity::High, definitive, "r")
    }

    #[test]
    fn definitive_is_always_malicious() {
        let t = Threat::assemble(
            "/x".into(),
            "h".into(),
            10,
            TrustTier::Unknown,
            vec![det(Engine::Hash, 100, true)],
        )
        .unwrap();
        assert_eq!(t.verdict, Verdict::Malicious);
    }

    #[test]
    fn apple_trust_suppresses_heuristics() {
        // Strong heuristic score, but Apple-signed -> suppressed to Clean (None).
        let t = Threat::assemble(
            "/x".into(),
            "h".into(),
            10,
            TrustTier::Apple,
            vec![det(Engine::Entropy, 100, false)],
        );
        assert!(t.is_none());
    }

    #[test]
    fn unsigned_heuristics_can_reach_malicious() {
        let t = Threat::assemble(
            "/x".into(),
            "h".into(),
            10,
            TrustTier::Unsigned,
            vec![det(Engine::Entropy, 40, false), det(Engine::MachO, 40, false)],
        )
        .unwrap();
        // (40 + 40) * 1.25 = 100 >= MALICIOUS_THRESHOLD
        assert_eq!(t.verdict, Verdict::Malicious);
    }
}
