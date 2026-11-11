//! Emit the Rust-owned authored-policy schema for language SDK bindings.

use mvm_contract::policy::authored::{GroupFile, PolicyBody, ProfileFile};

#[derive(schemars::JsonSchema)]
struct AuthoredPolicyDocuments {
    #[schemars(rename = "profile")]
    _profile: ProfileFile,
    #[schemars(rename = "group")]
    _group: GroupFile,
    #[schemars(rename = "body")]
    _body: PolicyBody,
}

fn main() {
    let schema = schemars::schema_for!(AuthoredPolicyDocuments);
    println!(
        "{}",
        serde_json::to_string_pretty(&schema).expect("a JSON Schema always serializes")
    );
}
