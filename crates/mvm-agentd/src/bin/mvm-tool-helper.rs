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
    use std::os::fd::FromRawFd;

    let ready_fd = std::env::var("MVM_TOOL_READY_FD")
        .ok()
        .and_then(|value| value.parse::<i32>().ok())
        .filter(|fd| *fd >= 3);
    let Some(ready_fd) = ready_fd else {
        eprintln!("mvm-tool-helper: missing readiness descriptor");
        std::process::exit(1);
    };
    // SAFETY: the parent passes this one live descriptor across exec and
    // gives ownership to the helper process.
    let ready = unsafe { std::os::fd::OwnedFd::from_raw_fd(ready_fd) };
    let map = match std::fs::read(TOOL_MAP_PATH) {
        Ok(bytes) => match ToolMap::load(&bytes) {
            Ok(map) => map,
            Err(error) => {
                eprintln!("mvm-tool-helper: {TOOL_MAP_PATH}: {error}");
                std::process::exit(1);
            }
        },
        Err(error) => {
            eprintln!("mvm-tool-helper: {TOOL_MAP_PATH}: {error}");
            std::process::exit(1);
        }
    };
    if let Err(error) = bind_and_serve(map, ready) {
        eprintln!("mvm-tool-helper: serve: {error}");
        std::process::exit(1);
    }
}
