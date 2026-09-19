//! Emit the Rust-owned live runtime SDK contract as JSON Schema.

use schemars::JsonSchema;

#[derive(JsonSchema)]
struct Runtime {
    process_result: mvm_sdk::runtime::RuntimeProcessResult,
    process_event: mvm_sdk::runtime::RuntimeProcessEvent,
    fs_entry: mvm_sdk::runtime::RuntimeFsEntry,
    fs_stat: mvm_sdk::runtime::RuntimeFsStat,
}

fn main() {
    let schema = schemars::schema_for!(Runtime);
    let json = serde_json::to_string_pretty(&schema).expect("serialize runtime schema");
    println!("{json}");
}
