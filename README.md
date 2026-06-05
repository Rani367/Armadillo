# Armadillo

A macOS antivirus (CLI + TUI) written in Rust, with **zero system dependencies** — no ClamAV, no
libyara, no OpenSSL. The entire detection stack is pure Rust, so it builds and runs from a stock
toolchain with nothing else to install.

It scans for malware, spyware, ransomware, and adware using five independent detection engines
layered so that what one misses, another catches, plus a scoring system tuned to avoid false
alarms.

> One honest note: no antivirus can guarantee it stops every threat — perfect detection is
> impossible, and anything claiming 100% is overstating. What actually helps is layering several
> independent engines and keeping definitions fresh, which is what Armadillo does. Treat it as one
> strong layer of defense: keep macOS updated, keep backups, and stay skeptical of what you download.

## The five engines

| # | Engine | What it catches |
|---|--------|-----------------|
| 1 | Hash signatures (SHA-256 / MD5) | Exact known-malware files. Instant, zero false positives. |
| 2 | YARA rules ([`yara-x`](https://github.com/VirusTotal/yara-x)) | Malware families and variants, not just exact files. |
| 3 | Heuristics | Packed/encrypted binaries (per-section Shannon entropy), Mach-O red flags (encrypted segments, missing code signature), and obfuscated scripts (`curl … \| bash`, base64-decode-and-exec, fake password prompts). |
| 4 | Code-signature trust | Classifies Apple / Developer-ID-notarized / ad-hoc / unsigned, and discounts heuristic findings on trusted code to suppress false positives. |
| 5 | macOS persistence & adware audit | Where Mac malware actually hides: LaunchAgents/Daemons, shell-startup files, cron/periodic jobs, browser hijacks, configuration profiles. |

Each file's findings combine into a weighted score and a verdict of Clean / Suspicious / Malicious.
Hash and YARA matches are definitive; heuristics need corroboration before they can reach
"malicious" on their own, and Apple-signed code suppresses heuristic noise entirely.

## Install

Needs a stable Rust toolchain (1.82+). Nothing else.

```sh
git clone https://github.com/Rani367/Armadillo && cd Armadillo
cargo build --release
# binary at ./target/release/armadillo
```

## Usage

```sh
armadillo scan                 # quick scan of high-signal locations (default)
armadillo scan --full          # full system scan (skips /System & pseudo-fs by default)
armadillo scan ~/Downloads     # scan a specific path
armadillo scan <path> --json   # machine-readable output
armadillo scan <path> --no-prompt        # report only, never touch files
armadillo scan <path> --quarantine-all   # auto-quarantine every detection

armadillo audit                # persistence & adware audit (no file-content scan)
armadillo tui                  # interactive dashboard

armadillo quarantine list                # list the vault
armadillo quarantine restore <id>        # restore a file (id or unique prefix)
armadillo quarantine delete  <id>        # permanently delete
armadillo quarantine add     <path>      # manually quarantine a file

armadillo update               # refresh definitions (YARA rules + hash feeds)
armadillo update --dry-run     # show what would be fetched
armadillo status               # definition version, last update, counts

# global flags: --verbose, --no-color
```

By default, Armadillo prompts you per threat (quarantine / delete / ignore / always-quarantine).
Use `--no-prompt` for report-only or `--quarantine-all` to act automatically.

### Quarantine

Quarantining moves a file into a private vault
(`~/Library/Application Support/armadillo/quarantine`), strips its permissions so it can't run, and
records metadata for a byte-identical, reversible restore. Nothing is ever deleted without your
say-so.

## Definitions & updates

Armadillo ships with a bundled rule set (custom macOS-malware YARA rules, the EICAR self-test, and a
starter hash list) so it works offline on day one. `armadillo update`:

- **Hash feeds** — downloads known-bad hash lists. abuse.ch URLhaus is open; MalwareBazaar /
  ThreatFox need a free [Auth-Key](https://auth.abuse.ch/) in `config.json`.
- **Rules** — recompiles the bundled YARA rules with any of your own `*.yar` files dropped in
  `~/Library/Application Support/armadillo/defs/custom/`.

Downloads use rustls (no OpenSSL) and degrade gracefully when offline.

## Full Disk Access

Some locations (other processes' data, parts of `~/Library`, `TCC.db`) are protected by macOS. To
scan them, grant Full Disk Access to your terminal (or the `armadillo` binary) under *System
Settings → Privacy & Security → Full Disk Access*. Without it, Armadillo skips what it can't read
and reports it rather than failing hard.

## How it's built

One front-end-agnostic engine streams `ScanEvent`s and updates lock-free counters; both the CLI
(`indicatif` progress) and the TUI (`ratatui`) consume the same stream. Scanning is data-parallel
with `rayon`, files are read zero-copy via `mmap`.

```
src/
  engine/        # the five detection engines + scoring (verdict.rs)
    heuristics/  # entropy, mach-o, codesign, scripts
  scan/          # parallel walk + progress plumbing + target sets
  macos/         # persistence & adware audit (launchd, startup, browser, profiles)
  tui/           # ratatui dashboard
  scan_cmd.rs    # the `scan` command (progress + interactive triage)
  quarantine.rs  update.rs  report.rs  config.rs
rules/           # bundled YARA rule sources
data/hashes/     # bundled starter hash list
```

## Limitations

- macOS-only (Mach-O / launchd / macOS paths).
- Code-signature trust uses the system `codesign`/`spctl` tools; a native Security.framework path
  is planned.
- Hash-feed updates need network access and, for some feeds, a free abuse.ch key.
- No real-time/always-on background protection in this build — on-demand scan + audit only.
- Not a substitute for keeping macOS and its built-in XProtect up to date.

## Testing

```sh
cargo test                 # unit + engine integration tests (incl. the EICAR self-test)
cargo clippy --all-targets
```

To watch it catch something safely, use the standard (harmless) EICAR test file:

```sh
printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.com
armadillo scan /tmp/eicar.com --no-prompt
```

## License

MIT OR Apache-2.0 — see [LICENSE](LICENSE) and [LICENSE-APACHE](LICENSE-APACHE). Bundled
third-party YARA rules keep their own licenses (see `data/hashes/NOTICE-THIRDPARTY.md`). Apple's
XProtect rules are not redistributed.
