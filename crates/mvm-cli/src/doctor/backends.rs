//! Per-backend host-component lines: for every installable backend whose
//! component files are staged beside this `mvmctl`, report presence, the
//! supervisor signature state, and whether the host OS fits the row's
//! support window. Rows with no files (firecracker, qemu, wasm) ship their
//! whole component set inside `mvmctl` itself, so there is nothing to check.

use mvm_core::vm_backend::BackendKind;

use super::Check;
use crate::host_binaries::backend_components::{
    BackendComponentSet, component_dirs, component_files_present, component_table, live_host,
    not_available_reason,
};

/// The doctor check name for one backend — a static string per kind so a
/// report can carry one line per installed backend.
const fn check_name(kind: BackendKind) -> &'static str {
    match kind {
        BackendKind::Firecracker => "backend components (firecracker)",
        BackendKind::Libkrun => "backend components (libkrun)",
        BackendKind::Qemu => "backend components (qemu)",
        BackendKind::Mock => "backend components (mock)",
        BackendKind::Hvf => "backend components (hvf)",
        BackendKind::Wasm => "backend components (wasm)",
        BackendKind::WebLinux => "backend components (web-linux)",
        BackendKind::AppleContainer => "backend components (apple-container)",
    }
}

/// The supervisor signature state of the row's binary components, as one
/// short phrase. Checked only on macOS, where the supervisors need their
/// hypervisor entitlement; elsewhere the binaries keep the signature the
/// archive's verified digest already covered.
fn signature_state(row: &BackendComponentSet, dirs: &[std::path::PathBuf]) -> String {
    #[cfg(target_os = "macos")]
    {
        let mut parts = Vec::new();
        for file in row.files.iter().filter(|file| {
            file.kind == crate::host_binaries::backend_components::ComponentKind::Binary
        }) {
            let path = dirs.iter().find_map(|dir| {
                let candidate = dir.join(file.path);
                candidate.is_file().then_some(candidate)
            });
            let state = match path {
                Some(path) => match mvm_vmm::host::codesign::entitlement_present(
                    &path,
                    mvm_vmm::host::codesign::RequiredEntitlement::Hypervisor,
                ) {
                    Some(true) => "signed (hypervisor entitlement)".to_string(),
                    Some(false) => format!("{}: hypervisor entitlement missing", file.path),
                    None => format!("{}: signature unreadable", file.path),
                },
                None => format!("{}: not found", file.path),
            };
            parts.push(state);
        }
        if parts.is_empty() {
            "no binaries to sign".to_string()
        } else {
            parts.join(", ")
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (row, dirs);
        "signature covered by the archive manifest".to_string()
    }
}

/// One `backend components (<name>)` line per installed backend: files
/// present, signature state, minimum-OS fit. Informational — a missing
/// entitlement or an out-of-window host is visible here without failing
/// doctor, matching the optional nature of every component set.
pub(super) fn backend_component_checks() -> Vec<Check> {
    let Some(host) = live_host() else {
        return Vec::new();
    };
    let dirs = component_dirs();
    let mut checks = Vec::new();
    for row in component_table() {
        if !component_files_present(row, &dirs) {
            continue;
        }
        let fit = match not_available_reason(row, &host) {
            None => "host in support window".to_string(),
            Some(reason) => reason,
        };
        checks.push(Check {
            name: check_name(row.backend),
            category: "platform",
            ok: true,
            info: format!("present; {}; {}", signature_state(row, &dirs), fit),
        });
    }
    checks
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_binaries::backend_components::row_for;

    /// The check renders one line per file-bearing backend whose files sit
    /// beside the exe; both current file-bearing rows must be named.
    #[test]
    fn file_bearing_rows_have_distinct_check_names() {
        let libkrun = row_for(BackendKind::Libkrun);
        let hvf = row_for(BackendKind::Hvf);
        assert!(!libkrun.files.is_empty());
        assert!(!hvf.files.is_empty());
        assert_ne!(check_name(libkrun.backend), check_name(hvf.backend));
    }
}
