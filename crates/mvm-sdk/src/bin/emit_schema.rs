//! Emit the canonical Workload IR JSON Schema to stdout.
//!
//! The output is written in RFC 8785 canonical form (per ADR-0004) so that
//! schema freshness checks are deterministic across toolchain versions and
//! platforms. `just schema-gen` redirects this binary's stdout into
//! `schema/workload-ir-v0.json`; `just schema-check` compares fresh output
//! against the committed file.

use mvm_sdk::ir::{Workload, canonicalize};
use schemars::schema_for;

fn main() {
    let schema = schema_for!(Workload);
    let canonical = canonicalize(&schema).expect("canonicalize schema");
    println!("{canonical}");
}
