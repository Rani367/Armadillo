//! Heuristic detection engines (entropy, Mach-O structure, code-signature trust,
//! script/obfuscation). These produce *scored* [`Detection`]s that the scorer in
//! [`crate::engine::verdict`] combines with the signer trust tier — never a
//! standalone verdict.

pub mod codesign;
pub mod entropy;
pub mod macho;
pub mod scripts;
