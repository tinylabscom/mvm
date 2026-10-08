//! In-guest declared-command tool helper (binary entry point).
//!
//! The library half lives in `mvm_agentd::tool_helper`; this is the thin
//! binary the guest init starts as [`TOOL_HELPER_IDENTITY`] after activation
//! has written the tool map. Without a map the helper serves nothing and the
//! guest runs no declared commands, which is the fail-closed posture for a
//! boot that skipped substitution.

#[cfg(target_os = "linux")]
use mvm_agentd::tool_helper::bind_and_serve;
#[cfg(target_os = "linux")]
use mvm_agentd::tool_map::{TOOL_MAP_PATH, ToolMap};

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("mvm-tool-helper: declared-command mediation runs only in a Linux guest");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn main() {
    let map = match std::fs::read(TOOL_MAP_PATH) {
        Ok(bytes) => match ToolMap::load(&bytes) {
            Ok(map) => map,
            Err(error) => {
                eprintln!(
                    "mvm-tool-helper: {TOOL_MAP_PATH}: {error}; declared commands stay refused"
                );
                // Serve an empty map: every shim request is refused as an
                // unknown path, which keeps fail-closed semantics without
                // trusting the corrupt file.
                ToolMap::default()
            }
        },
        Err(error) => {
            eprintln!("mvm-tool-helper: {TOOL_MAP_PATH}: {error}; declared commands stay refused");
            ToolMap::default()
        }
    };
    if let Err(error) = bind_and_serve(map) {
        eprintln!("mvm-tool-helper: serve: {error}");
        std::process::exit(1);
    }
}
