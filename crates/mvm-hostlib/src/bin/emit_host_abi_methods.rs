//! Emit the host-ABI method-table manifest to stdout.
//!
//! The manifest names every dotted method with its schema key, admission
//! classification, and a one-line summary, plus the ABI version the table
//! was generated against. The SDK surface renderers turn it into the
//! per-language method modules; `cargo xtask check-stubs` drift-checks the
//! committed output.

use anyhow::Context;

fn main() -> anyhow::Result<()> {
    let manifest = mvm_hostlib::registry::method_manifest();
    println!(
        "{}",
        serde_json::to_string_pretty(&manifest).context("serializing the method manifest")?
    );
    Ok(())
}
