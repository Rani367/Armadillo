//! Predefined scan target sets and default exclusions.

use std::path::PathBuf;

/// High-signal directories for a fast "quick scan". These are the payload
/// staging + no-privilege persistence spots favoured by macOS malware, chosen to
/// keep the quick scan genuinely quick (the heavy persistence locations are
/// covered separately by the macOS audit).
pub fn quick_targets() -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = Vec::new();
    if let Some(home) = dirs::home_dir() {
        v.push(home.join("Downloads"));
        v.push(home.join("Library/LaunchAgents"));
    }
    v.push(PathBuf::from("/tmp"));
    v.push(PathBuf::from("/private/tmp"));
    v.push(PathBuf::from("/Users/Shared"));
    v.push(PathBuf::from("/Library/LaunchAgents"));
    v.push(PathBuf::from("/Library/LaunchDaemons"));
    v.retain(|p| p.exists());
    v
}

/// Roots for a "full scan". Defaults to the whole volume minus SIP-protected /
/// pseudo paths (see [`default_excludes`]); the heavy, Apple-signed `/System`
/// tree is excluded by default for speed but can be scanned by passing it
/// explicitly.
pub fn full_targets() -> Vec<PathBuf> {
    vec![PathBuf::from("/")]
}

/// Paths excluded from a full scan by default: pseudo-filesystems, swap, caches
/// of our own making, and the SIP-protected system tree.
pub fn default_excludes() -> Vec<PathBuf> {
    let mut v = vec![
        PathBuf::from("/System"),
        PathBuf::from("/dev"),
        PathBuf::from("/Volumes"),
        PathBuf::from("/private/var/vm"),
        PathBuf::from("/.fseventsd"),
        PathBuf::from("/.Spotlight-V100"),
        PathBuf::from("/.DocumentRevisions-V100"),
        PathBuf::from("/private/var/folders/zz"),
    ];
    // Never scan our own quarantine vault / data dir.
    if let Some(data) = dirs::data_dir() {
        v.push(data.join("armadillo"));
    }
    v
}
