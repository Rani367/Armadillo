# Third-party content & attribution

Armadillo itself is licensed MIT OR Apache-2.0. This file tracks the provenance and license of
any bundled or fetched detection content.

## Bundled YARA rules (`rules/`)

- `eicar.yar` — detects the **EICAR** standard anti-virus test string. EICAR is a public,
  harmless industry test pattern (not malware). See <https://www.eicar.org/>.
- `macos_malware.yar` — original, conservative heuristics authored for Armadillo, informed by
  public threat reporting (Objective-See, Jamf Threat Labs, SentinelLabs, Microsoft). MIT/Apache-2.0.

## Bundled hash list (`data/hashes/bundled.hashes`)

- Contains the EICAR test-file MD5/SHA-256 (public test values) so the hash engine catches the
  self-test. Real coverage comes from `armadillo update`.

## Fetched at runtime via `armadillo update` (NOT redistributed in this repo)

- **abuse.ch** — URLhaus (open), MalwareBazaar / ThreatFox (free Auth-Key, fair-use). Commercial
  redistribution may require a Spamhaus Technology subscription. Each deployment must use its own key.
- **User-supplied YARA** dropped in `<defs>/custom/*.yar` retains its own upstream license.

## Explicitly NOT bundled (licensing)

- **ClamAV** signatures / libclamav (GPL).
- **Neo23x0/signature-base** (DRL 1.1) and **Elastic protections-artifacts** (Elastic License 2.0).
- **Apple XProtect** YARA rules — proprietary; may be read locally for defense-in-depth but never
  redistributed.

When adding a new rule source, record its exact license + commit here, and prefer permissively
licensed feeds (ReversingLabs MIT, InQuest MIT, bartblaze TLP:CLEAR, or the YARA-Forge permissive tier).
