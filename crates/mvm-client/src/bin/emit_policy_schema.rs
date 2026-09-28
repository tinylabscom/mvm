//! `emit_policy_schema` — print the JSON Schema of the authored policy
//! documents (profiles, groups, and the resolved manifest) to stdout.
//!
//! Generated from the Rust types the documents are parsed into, so the
//! published schema cannot describe a key the parser refuses.
//! `schema/policy-profiles-v0.json` is its committed output; a test under the
//! same feature fails when the two drift.
//!
//! Built only under `--features schema`, so `schemars` never enters a shipped
//! closure.

fn main() {
    println!(
        "{}",
        mvm_client::policy_profiles::model::json_schema_pretty()
    );
}
