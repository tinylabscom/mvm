//! `emit_instruction_trust_schema` — print the JSON Schema of the
//! instruction-file trust policy (`instruction-trust.toml`) to stdout.
//!
//! The schema is generated from the Rust types the policy is parsed into, so
//! the published document cannot describe a field the parser does not accept.
//! `schema/instruction-trust-policy-v0.json` is its committed output; a test
//! under the same feature fails when the two drift.
//!
//! Built only under `--features schema`, so `schemars` never enters a shipped
//! closure.

fn main() {
    println!(
        "{}",
        mvm_client::instruction_trust::policy::json_schema_pretty()
    );
}
