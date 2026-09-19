//! Emit the Rust-owned live runtime SDK contract as JSON Schema.

use schemars::JsonSchema;

#[derive(JsonSchema)]
struct Runtime {
    #[schemars(rename = "process_result")]
    _process_result: mvm_sdk::runtime::RuntimeProcessResult,
    #[schemars(rename = "process_event")]
    _process_event: mvm_sdk::runtime::RuntimeProcessEvent,
    #[schemars(rename = "fs_entry")]
    _fs_entry: mvm_sdk::runtime::RuntimeFsEntry,
    #[schemars(rename = "fs_stat")]
    _fs_stat: mvm_sdk::runtime::RuntimeFsStat,
}

fn main() {
    let schema = schemars::schema_for!(Runtime);
    let json = serde_json::to_string_pretty(&schema).expect("serialize runtime schema");
    println!("{json}");
}
