//! Emit the authored PackSpec schema; this does not resolve or build a pack.
fn main() {
    let schema = schemars::schema_for!(mvm_contract::pack_spec::PackSpec);
    println!(
        "{}",
        serde_json::to_string_pretty(&schema).expect("schema JSON")
    );
}
