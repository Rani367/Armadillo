//! Fast file-type gating. Decides which engines to run per file and — critically
//! for precision — which files are *expected* to have high entropy (archives,
//! media, encrypted blobs) so the entropy heuristic does not flag them.

/// Coarse classification used to route a file through the engines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileClass {
    /// Mach-O executable / dylib / bundle binary (incl. fat/universal).
    MachO,
    /// Shell / AppleScript / Python / Perl / other text script.
    Script,
    /// Compressed archive or installer container (expected high entropy).
    Archive,
    /// Image / audio / video (expected high entropy).
    Media,
    /// Other recognized binary (PE/ELF/doc/etc.).
    OtherBinary,
    /// Small/plain text that isn't obviously a script.
    Text,
    /// Unknown / unrecognized.
    Unknown,
}

const MACHO_MAGICS: [[u8; 4]; 5] = [
    [0xFE, 0xED, 0xFA, 0xCE], // MH_MAGIC (32, BE)
    [0xCE, 0xFA, 0xED, 0xFE], // MH_CIGAM (32, LE)
    [0xFE, 0xED, 0xFA, 0xCF], // MH_MAGIC_64 (BE)
    [0xCF, 0xFA, 0xED, 0xFE], // MH_CIGAM_64 (LE)
    [0xCA, 0xFE, 0xBA, 0xBE], // FAT_MAGIC (universal) — also Java .class, disambiguated below
];

/// Classify a file from a header sample (and optionally its path/name).
pub fn classify(sample: &[u8], path: &std::path::Path) -> FileClass {
    if sample.len() >= 4 {
        let head: [u8; 4] = [sample[0], sample[1], sample[2], sample[3]];
        if MACHO_MAGICS.contains(&head) {
            // CAFEBABE is ambiguous with Java .class; a Mach-O fat header has a
            // big-endian arch count in bytes 4..8 that is small (< 64).
            if head == [0xCA, 0xFE, 0xBA, 0xBE] {
                let narch = sample.get(4..8).map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]));
                if matches!(narch, Some(n) if n == 0 || n > 64) {
                    // Looks like a Java class file, not a Mach-O fat binary.
                } else {
                    return FileClass::MachO;
                }
            } else {
                return FileClass::MachO;
            }
        }
    }

    if let Some(kind) = infer::get(sample) {
        let mime = kind.mime_type();
        if mime.starts_with("image/") || mime.starts_with("audio/") || mime.starts_with("video/") {
            return FileClass::Media;
        }
        if is_archive_mime(mime) {
            return FileClass::Archive;
        }
        if mime == "application/x-mach-binary" {
            return FileClass::MachO;
        }
        if mime.starts_with("application/") {
            return FileClass::OtherBinary;
        }
    }

    // Shebang / scripty extension / mostly-text content.
    if sample.starts_with(b"#!") {
        return FileClass::Script;
    }
    if has_script_ext(path) {
        return FileClass::Script;
    }
    if looks_textual(sample) {
        return FileClass::Text;
    }

    FileClass::Unknown
}

fn is_archive_mime(mime: &str) -> bool {
    matches!(
        mime,
        "application/zip"
            | "application/gzip"
            | "application/x-bzip2"
            | "application/x-xz"
            | "application/x-tar"
            | "application/x-7z-compressed"
            | "application/x-rar-compressed"
            | "application/vnd.rar"
            | "application/x-apple-diskimage"
            | "application/x-compress"
            | "application/zstd"
    )
}

fn has_script_ext(path: &std::path::Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()).map(|e| e.to_ascii_lowercase()).as_deref(),
        Some("sh" | "bash" | "zsh" | "command" | "scpt" | "applescript" | "py" | "pl" | "rb" | "js" | "php")
    )
}

/// Heuristic: a sample is "textual" if it is valid UTF-8-ish with few NULs and
/// mostly printable/whitespace bytes.
fn looks_textual(sample: &[u8]) -> bool {
    if sample.is_empty() {
        return false;
    }
    let n = sample.len().min(4096);
    let window = &sample[..n];
    let nuls = window.iter().filter(|&&b| b == 0).count();
    if nuls > 0 {
        return false;
    }
    let printable = window
        .iter()
        .filter(|&&b| b == b'\n' || b == b'\r' || b == b'\t' || (0x20..=0x7e).contains(&b) || b >= 0x80)
        .count();
    printable * 100 / n >= 90
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn detects_macho_64() {
        let mut b = vec![0xCF, 0xFA, 0xED, 0xFE];
        b.extend_from_slice(&[0u8; 60]);
        assert_eq!(classify(&b, Path::new("x")), FileClass::MachO);
    }

    #[test]
    fn detects_shebang_script() {
        assert_eq!(classify(b"#!/bin/bash\necho hi\n", Path::new("x")), FileClass::Script);
    }

    #[test]
    fn plain_text_is_text() {
        assert_eq!(classify(b"hello world\nthis is text\n", Path::new("x.txt")), FileClass::Text);
    }
}
