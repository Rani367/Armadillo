//! Mach-O structural red flags (Engine 3, binary path) via `goblin`.
//!
//! Conservative on purpose: we flag the high-signal, low-FP traits — encrypted
//! segments on a standalone macOS binary, a missing code signature, and a
//! high-entropy executable `__text` section — and report whether the binary is
//! code-signed so the caller can resolve a trust tier. We deliberately do NOT
//! score the mere presence of @rpath / weak dylibs (extremely common, noisy).

use goblin::mach::{Mach, MachO, SingleArch};

use super::entropy::{self, shannon_entropy};
use crate::engine::verdict::{Detection, Engine, Severity};

/// Result of inspecting a Mach-O (or fat) binary.
pub struct MachoReport {
    pub is_macho: bool,
    pub has_code_signature: bool,
    pub detections: Vec<Detection>,
}

impl MachoReport {
    fn empty() -> Self {
        Self {
            is_macho: false,
            has_code_signature: false,
            detections: Vec::new(),
        }
    }
}

/// Inspect raw bytes; handles both thin and fat/universal Mach-O.
pub fn analyze(bytes: &[u8]) -> MachoReport {
    let mut report = MachoReport::empty();
    match Mach::parse(bytes) {
        Ok(Mach::Binary(macho)) => {
            report.is_macho = true;
            analyze_one(&macho, &mut report);
        }
        Ok(Mach::Fat(multi)) => {
            report.is_macho = true;
            for i in 0..multi.narches {
                if let Ok(SingleArch::MachO(macho)) = multi.get(i) {
                    analyze_one(&macho, &mut report);
                }
            }
        }
        Err(_) => {}
    }
    report
}

fn analyze_one(macho: &MachO, report: &mut MachoReport) {
    use goblin::mach::load_command::CommandVariant;

    let mut has_cs = false;
    for lc in &macho.load_commands {
        match &lc.command {
            CommandVariant::CodeSignature(_) => has_cs = true,
            CommandVariant::EncryptionInfo32(e) if e.cryptid != 0 => {
                report.detections.push(Detection::new(
                    Engine::MachO,
                    "encrypted_segment",
                    40,
                    Severity::High,
                    false,
                    "Mach-O segment is encrypted (cryptid != 0) — abnormal for a standalone macOS binary",
                ));
            }
            CommandVariant::EncryptionInfo64(e) if e.cryptid != 0 => {
                report.detections.push(Detection::new(
                    Engine::MachO,
                    "encrypted_segment",
                    40,
                    Severity::High,
                    false,
                    "Mach-O segment is encrypted (cryptid != 0) — abnormal for a standalone macOS binary",
                ));
            }
            _ => {}
        }
    }
    report.has_code_signature |= has_cs;

    // Per-section entropy of executable text — the strong packing signal.
    for seg in &macho.segments {
        if let Ok(sections) = seg.sections() {
            for (sect, data) in sections {
                let name = sect.name().unwrap_or("");
                if name == "__text" && !data.is_empty() {
                    let h = shannon_entropy(data);
                    if h >= entropy::HIGH {
                        report.detections.push(Detection::new(
                            Engine::MachO,
                            "high_entropy_text",
                            30,
                            Severity::High,
                            false,
                            format!("__text section entropy {h:.2} — likely packed/obfuscated code"),
                        ));
                    } else if h >= entropy::SUSPICIOUS {
                        report.detections.push(Detection::new(
                            Engine::MachO,
                            "elevated_entropy_text",
                            15,
                            Severity::Medium,
                            false,
                            format!("__text section entropy {h:.2} — elevated"),
                        ));
                    }
                }
            }
        }
    }

    if !has_cs {
        report.detections.push(Detection::new(
            Engine::MachO,
            "missing_code_signature",
            25,
            Severity::Medium,
            false,
            "Mach-O has no LC_CODE_SIGNATURE (unsigned)",
        ));
    }
}
