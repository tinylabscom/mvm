//! Emit the host-ABI JSON Schema to stdout — the SDK stub-codegen input.
//!
//! The document describes every dotted method's request and reply types
//! (see `mvm-hostlib`'s `registry` module). `cargo xtask gen-stubs` feeds it
//! to the pinned Python and TypeScript generators; the committed result is
//! drift-checked by `cargo xtask check-stubs`.

use anyhow::Context;

fn main() -> anyhow::Result<()> {
    let doc = mvm_hostlib::registry::schema_document().context("assembling the host-ABI schema")?;
    println!(
        "{}",
        serde_json::to_string_pretty(&doc).context("serializing the host-ABI schema")?
    );
    Ok(())
}
