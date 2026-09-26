//! Kani proof harnesses for the KDF key derivation hierarchy.
//!
//! Note: MasterKey and DerivedKey both derive ZeroizeOnDrop, which uses
//! inline assembly in the `zeroize` crate. Kani 0.68 does not support
//! TerminatorKind::InlineAsm, so harnesses that construct MasterKey
//! fail unconditionally. This is a tooling limitation, not a code issue.
//!
//! The KDF properties are instead covered by:
//! - kdf_tests.rs: 14 unit tests covering all context separation properties,
//!   determinism, all named helpers, DerivedKey conversions, and edge cases.
//! - proptest_invariants.rs: random-input property tests using real HKDF outputs.
//!
//! This module is intentionally empty pending Kani support for inline assembly.
//! Track: https://github.com/model-checking/kani/issues/2
