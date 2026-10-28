//! Per-tenant host-agent daemon state.

use super::Check;

/// `kill(pid, 0)` liveness: the process exists and is signalable.
fn pid_is_alive(pid: libc::pid_t) -> bool {
    // SAFETY: signal 0 delivers nothing; it only validates the pid.
    unsafe { libc::kill(pid, 0) == 0 }
}

/// Summarize the per-tenant host-agent daemons under `root`.
/// Reports warm daemons, stale daemon artifacts, or "absent" when none exist.
fn host_agent_daemon_summary(root: &std::path::Path) -> String {
    let Ok(entries) = std::fs::read_dir(root) else {
        return "absent (no per-tenant daemon yet; an admitted workload starts one)".to_string();
    };
    let mut warm = Vec::new();
    let mut stale = Vec::new();
    for entry in entries.flatten() {
        let dir = entry.path();
        if !dir.is_dir() {
            continue;
        }
        let tenant = entry.file_name().to_string_lossy().into_owned();
        let pid_file = dir.join("daemon.pid");
        let pid_file_exists = pid_file.exists();
        let pid = std::fs::read_to_string(&pid_file)
            .ok()
            .and_then(|s| s.trim().parse::<libc::pid_t>().ok());
        let sock = mvm_core::config::host_agent_control_socket_in(&dir).exists();
        if let Some(p) = pid.filter(|p| pid_is_alive(*p))
            && sock
        {
            warm.push(format!("{tenant}: running (pid {p})"));
        } else if sock || pid_file_exists {
            // A pid or socket left behind by a dead daemon.
            stale.push(tenant);
        }
        // Empty dirs, for example one containing only the spawn lock, are skipped.
    }
    warm.sort();
    stale.sort();
    if warm.is_empty() && stale.is_empty() {
        return "absent (no per-tenant daemon running)".to_string();
    }
    let mut parts = Vec::new();
    if !warm.is_empty() {
        parts.push(format!("{} warm - {}", warm.len(), warm.join(", ")));
    }
    if !stale.is_empty() {
        parts.push(format!("stale: {}", stale.join(", ")));
    }
    parts.join("; ")
}

/// Per-tenant host-agent daemon state. Informational.
pub(super) fn host_agent_daemon_check() -> Check {
    Check {
        name: "host-agent daemon",
        category: "platform",
        ok: true,
        info: host_agent_daemon_summary(&mvm_core::config::host_agent_root()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_agent_daemon_summary_reports_absent_warm_and_stale() {
        let root = tempfile::Builder::new()
            .prefix(&"doctor-host-agent-".repeat(6))
            .tempdir()
            .unwrap();
        assert!(host_agent_daemon_summary(&root.path().join("missing")).starts_with("absent"));

        // No dirs yet means absent.
        assert!(host_agent_daemon_summary(root.path()).starts_with("absent"));

        // A "running" tenant: live pid (this process) + control.sock.
        let live = root.path().join("local");
        std::fs::create_dir_all(&live).unwrap();
        std::fs::write(live.join("daemon.pid"), std::process::id().to_string()).unwrap();
        let live_socket = mvm_core::config::host_agent_control_socket_in(&live);
        mvm_core::config::create_private_dir(live_socket.parent().unwrap()).unwrap();
        std::fs::write(&live_socket, "").unwrap();
        let s = host_agent_daemon_summary(root.path());
        assert!(s.contains("1 warm"), "got {s:?}");
        assert!(s.contains("local: running"), "got {s:?}");

        // A "stale" tenant: a dead pid + a leftover socket.
        let dead = root.path().join("acme");
        std::fs::create_dir_all(&dead).unwrap();
        std::fs::write(dead.join("daemon.pid"), "2147483647").unwrap();
        let dead_socket = mvm_core::config::host_agent_control_socket_in(&dead);
        mvm_core::config::create_private_dir(dead_socket.parent().unwrap()).unwrap();
        std::fs::write(&dead_socket, "").unwrap();
        let s = host_agent_daemon_summary(root.path());
        assert!(s.contains("stale: acme"), "got {s:?}");

        for (tenant, socket) in [(&live, &live_socket), (&dead, &dead_socket)] {
            if socket.parent().unwrap() != tenant {
                std::fs::remove_dir_all(socket.parent().unwrap()).unwrap();
            }
        }
    }

    #[test]
    fn host_agent_daemon_summary_finds_a_relocated_control_socket() {
        let directory = tempfile::tempdir_in("/tmp").unwrap();
        let home = directory.path().join("long-home-".repeat(12));
        let state = mvm_core::config::host_agent_dir_at(&home, "local");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::write(state.join("daemon.pid"), std::process::id().to_string()).unwrap();
        let socket = mvm_core::config::host_agent_control_socket_in(&state);
        assert_ne!(socket, state.join("control.sock"));
        let socket_dir = socket.parent().unwrap();
        mvm_core::private_fs::create_owned_private_dir(socket_dir).unwrap();
        std::fs::write(&socket, "").unwrap();

        let summary = host_agent_daemon_summary(&mvm_core::config::host_agent_root_at(&home));
        std::fs::remove_file(&socket).unwrap();
        std::fs::remove_dir(socket_dir).unwrap();
        assert!(summary.contains("local: running"), "got {summary:?}");
        assert!(!summary.contains("stale:"), "got {summary:?}");
    }
}
