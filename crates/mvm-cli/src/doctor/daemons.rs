//! Per-tenant host-agent daemon and workload packet-tunnel worker state.

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
        let sock = dir.join("control.sock").exists();
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

/// Summarize workload packet-tunnel worker state under `vms_root`. Reports each
/// worker as active (live pid) or stale (dead/malformed pid with leftover
/// artifacts), and `absent` when nothing is staged. Informational: no tunnel
/// worker is the normal state for a workload with no admitted forwarding tunnel.
fn network_tunnel_worker_summary(vms_root: &std::path::Path) -> String {
    let Ok(entries) = std::fs::read_dir(vms_root) else {
        return "absent (no workload tunnel worker running)".to_string();
    };
    let mut running = Vec::new();
    let mut stale = Vec::new();
    for entry in entries.flatten() {
        let dir = entry.path();
        if !dir.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        let pid_file = dir.join(mvm_runtime::NETWORK_TUNNEL_WORKER_PID_FILE);
        let audit_file = dir.join(mvm_runtime::NETWORK_TUNNEL_AUDIT_JSONL);
        let pid_file_exists = pid_file.exists();
        let pid = std::fs::read_to_string(&pid_file)
            .ok()
            .and_then(|s| s.trim().parse::<libc::pid_t>().ok());
        let has_artifacts = pid_file_exists || audit_file.exists();
        if let Some(pid) = pid.filter(|pid| pid_is_alive(*pid)) {
            running.push(format!("{name} (pid {pid})"));
        } else if has_artifacts {
            stale.push(name);
        }
    }
    running.sort();
    stale.sort();
    if running.is_empty() && stale.is_empty() {
        return "absent (no workload tunnel worker running)".to_string();
    }
    let mut parts = Vec::new();
    if !running.is_empty() {
        parts.push(format!("{} active - {}", running.len(), running.join(", ")));
    }
    if !stale.is_empty() {
        parts.push(format!("stale: {}", stale.join(", ")));
    }
    parts.join("; ")
}

/// Workload packet-tunnel worker state. Informational.
pub(super) fn network_tunnel_worker_check() -> Check {
    Check {
        name: "network tunnel worker",
        category: "platform",
        ok: true,
        info: network_tunnel_worker_summary(&mvm_core::config::vms_dir()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_agent_daemon_summary_reports_absent_warm_and_stale() {
        let root = tempfile::tempdir().unwrap();
        assert!(host_agent_daemon_summary(&root.path().join("missing")).starts_with("absent"));

        // No dirs yet means absent.
        assert!(host_agent_daemon_summary(root.path()).starts_with("absent"));

        // A "running" tenant: live pid (this process) + control.sock.
        let live = root.path().join("local");
        std::fs::create_dir_all(&live).unwrap();
        std::fs::write(live.join("daemon.pid"), std::process::id().to_string()).unwrap();
        std::fs::write(live.join("control.sock"), "").unwrap();
        let s = host_agent_daemon_summary(root.path());
        assert!(s.contains("1 warm"), "got {s:?}");
        assert!(s.contains("local: running"), "got {s:?}");

        // A "stale" tenant: a dead pid + a leftover socket.
        let dead = root.path().join("acme");
        std::fs::create_dir_all(&dead).unwrap();
        std::fs::write(dead.join("daemon.pid"), "2147483647").unwrap();
        std::fs::write(dead.join("control.sock"), "").unwrap();
        let s = host_agent_daemon_summary(root.path());
        assert!(s.contains("stale: acme"), "got {s:?}");
    }

    #[test]
    fn network_tunnel_worker_check_is_informational_platform_check() {
        let c = network_tunnel_worker_check();
        assert_eq!(c.name, "network tunnel worker");
        assert_eq!(c.category, "platform");
        assert!(c.ok, "tunnel worker state is informational, never blocking");
    }

    #[test]
    fn network_tunnel_worker_summary_absent_when_root_missing_or_empty() {
        let root = tempfile::tempdir().unwrap();
        assert!(network_tunnel_worker_summary(&root.path().join("missing")).starts_with("absent"));
        assert!(network_tunnel_worker_summary(root.path()).starts_with("absent"));
        std::fs::create_dir_all(root.path().join("vm-no-tunnel")).unwrap();
        assert!(network_tunnel_worker_summary(root.path()).starts_with("absent"));
    }

    #[test]
    fn network_tunnel_worker_summary_reports_live_workers() {
        let root = tempfile::tempdir().unwrap();
        for name in ["vm-a", "vm-b"] {
            let dir = root.path().join(name);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(
                dir.join(mvm_runtime::NETWORK_TUNNEL_WORKER_PID_FILE),
                format!("{}\n", std::process::id()),
            )
            .unwrap();
        }

        let s = network_tunnel_worker_summary(root.path());
        assert!(s.contains("2 active"), "got {s:?}");
        assert!(s.contains("vm-a (pid"), "got {s:?}");
        assert!(s.contains("vm-b (pid"), "got {s:?}");
    }

    #[test]
    fn network_tunnel_worker_summary_reports_stale_artifacts() {
        let root = tempfile::tempdir().unwrap();
        let stale = root.path().join("vm-stale");
        std::fs::create_dir_all(&stale).unwrap();
        std::fs::write(
            stale.join(mvm_runtime::NETWORK_TUNNEL_WORKER_PID_FILE),
            "2147483646\n",
        )
        .unwrap();
        std::fs::write(stale.join(mvm_runtime::NETWORK_TUNNEL_AUDIT_JSONL), "").unwrap();

        let s = network_tunnel_worker_summary(root.path());
        assert!(s.contains("stale: vm-stale"), "got {s:?}");
    }
}
