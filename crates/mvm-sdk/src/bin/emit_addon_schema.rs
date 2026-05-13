//! Emit the canonical Addon Manifest JSON Schema to stdout.
//!
//! Mirrors `mvm-ir/src/bin/emit_schema.rs`. Output is canonicalized
//! via `mvm_ir::canonicalize` so that schema-freshness checks are
//! deterministic across toolchain versions and platforms.

use mvm_ir::canonicalize;
use mvm_sdk::addon::AddonManifest;
use schemars::schema_for;

fn main() {
    let schema = schema_for!(AddonManifest);
    let canonical = canonicalize(&schema).expect("canonicalize addon-manifest schema");
    println!("{canonical}");
}
