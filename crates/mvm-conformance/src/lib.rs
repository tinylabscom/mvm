//! Library surface for the dev-only cucumber-rs BDD conformance harness.
//!
//! Currently empty. `cucumber` is a dev-dependency of this crate, and Cargo
//! never exposes a package's dev-dependencies to its own `[lib]` target —
//! only to the test binary that links it — so the `World` type and the
//! cucumber-attributed step definitions live under `tests/` instead (see
//! `tests/conformance.rs`). This module is where step logic that doesn't
//! need cucumber's macros belongs as it lands — e.g. helpers that drive the
//! `mvm-client` facade directly — so it can be unit-tested independent of
//! the cucumber runner and shared if a second test target ever needs it.
//! Not a dependency of any shipped crate.
