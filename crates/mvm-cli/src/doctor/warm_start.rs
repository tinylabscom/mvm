//! Per-backend warm-start / capability matrix — snapshot tier, standby
//! pool, and the Linux fast-resume substrate probe.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::ui;

/// Per-backend warm-start capability + Linux fast-resume substrate, surfaced
/// under `warm_start` in `mvmctl doctor --json`.
#[derive(Debug, Serialize)]
pub(super) struct WarmStartReport {
    /// Backend name → warm-start tier label (`SnapshotCapability::label`).
    /// `BTreeMap` for deterministic JSON ordering, like `balloon_support`.
    backends: BTreeMap<String, &'static str>,
    /// The Linux-only fast-resume substrate (NBD module, HugeTLB reservation).
    /// `null` off Linux — the substrate backs Firecracker's live-memory path,
    /// which only runs on KVM; macOS reports per-backend tiers but N/A here.
    substrate: Option<WarmStartSubstrate>,
    /// Backend name → `supports_standby_pool()`. The standby pool
    /// (pre-pay spawn/codesign latency) is a *different* axis from the snapshot tier above;
    /// only libkrun implements it today.
    standby_pool: BTreeMap<String, bool>,
    /// Live count of idle standbys recorded under `~/.mvm/pool/` (best-effort; `None` if
    /// the pool dir can't be read).
    standby_pool_idle: Option<usize>,
}

/// Linux fast-resume substrate probe: the kernel pieces the
/// Firecracker UFFD/NBD/hugepages resume recipe needs.
#[derive(Debug, Serialize)]
struct WarmStartSubstrate {
    /// `/sys/module/nbd` present — the NBD module is loaded (Firecracker
    /// serves the resumed rootfs over NBD).
    nbd_module_loaded: bool,
    /// `/proc/sys/vm/nr_hugepages` > 0 — 2 MB hugepages reserved for the UFFD
    /// memfile backing a live-memory resume.
    hugetlb_reserved: bool,
}

// ── Warm-start capability ──────────────────────

/// One row of the per-backend capability matrix — the security/perf
/// tradeoffs a user weighs when picking `--hypervisor`. Every field is
/// read straight off `VmBackend`, so the table can never drift from
/// runtime behavior.
#[derive(Debug, Clone, Serialize)]
pub(super) struct BackendCapabilityRow {
    /// Backend name, matching `VmBackend::name`.
    backend: String,
    /// `SnapshotCapability::label` — warm-start fidelity (RAM resume vs disk reboot).
    snapshot_tier: &'static str,
    /// Host TAP device (vs a userspace gateway / slirp).
    tap_networking: bool,
    /// vsock guest control channel.
    vsock: bool,
    /// virtio-balloon runtime memory reclaim.
    balloon: bool,
    /// Copy-on-write fs checkpoint (APFS `clonefile`), independent of memory snapshots.
    fs_quick_checkpoint: bool,
    /// Pre-warmed standby pool that pre-pays spawn/codesign latency — the boot-latency axis.
    standby_pool: bool,
}

/// Build the per-backend capability matrix from the catalog's real backends
/// (the Tier 3 `mock` double is excluded via the warm-start descriptor set).
/// Each row reads off `VmBackend` so doctor's table is the runtime truth, not
/// a hand-maintained copy. Sorted by name for deterministic output.
pub(super) fn collect_capability_table() -> Vec<BackendCapabilityRow> {
    let mut rows: Vec<BackendCapabilityRow> =
        mvm_runtime::catalog::warm_start_support_descriptors()
            .map(|descriptor| {
                let b = descriptor.instantiate_dyn();
                let caps = b.capabilities();
                BackendCapabilityRow {
                    backend: b.name().to_string(),
                    snapshot_tier: b.snapshot_capability().label(),
                    tap_networking: caps.tap_networking,
                    vsock: caps.vsock,
                    balloon: caps.balloon,
                    fs_quick_checkpoint: caps.fs_quick_checkpoint,
                    standby_pool: b.supports_standby_pool(),
                }
            })
            .collect();
    rows.sort_by(|a, b| a.backend.cmp(&b.backend));
    rows
}

/// Render the per-backend capability matrix in text mode — the at-a-glance
/// tradeoff table behind `--hypervisor`. One line per backend.
pub(super) fn render_capability_table(rows: &[BackendCapabilityRow]) {
    let title = "Backend capability matrix (per backend)";
    println!("\n{}", title);
    println!("{}", "-".repeat(title.len()));
    let yn = |b: bool| if b { "yes" } else { "—" };
    for r in rows {
        ui::status_line(
            &format!("  {}:", r.backend),
            &format!(
                "snapshot {} · tap-net {} · vsock {} · balloon {} · fs-checkpoint {} · standby-pool {}",
                r.snapshot_tier,
                yn(r.tap_networking),
                yn(r.vsock),
                yn(r.balloon),
                yn(r.fs_quick_checkpoint),
                yn(r.standby_pool),
            ),
        );
    }
}

/// Enumerate every backend's `snapshot_capability()` tier and, on Linux,
/// probe the fast-resume substrate. Surfaced so a user knows which backend
/// resumes from RAM (Firecracker live-memory, HVF save/restore) vs. reboots
/// from a disk snapshot (libkrun) before relying on a warm start.
pub(super) fn collect_warm_start_support() -> WarmStartReport {
    let mut backends = BTreeMap::new();
    let mut standby_pool = BTreeMap::new();
    for descriptor in mvm_runtime::catalog::warm_start_support_descriptors() {
        let b = descriptor.instantiate_dyn();
        backends.insert(b.name().to_string(), b.snapshot_capability().label());
        standby_pool.insert(b.name().to_string(), b.supports_standby_pool());
    }
    // Best-effort live idle count. A missing pool dir reads as 0.
    let standby_pool_idle = mvm_runtime::standby_pool::SupervisorStandbyPool::open()
        .and_then(|p| p.list())
        .ok()
        .map(|v| {
            v.iter()
                .filter(|h| h.state == mvm_core::vm_backend::StandbyState::Idle)
                .count()
        });
    WarmStartReport {
        backends,
        substrate: collect_warm_start_substrate(),
        standby_pool,
        standby_pool_idle,
    }
}

/// `<sys_module>/nbd` exists ⇒ the NBD kernel module is loaded. Pure so it's
/// testable without `/sys`. Only `collect_warm_start_substrate` (Linux) and
/// the unit tests call it; off Linux the non-test build has no caller.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn nbd_module_loaded_at(sys_module: &std::path::Path) -> bool {
    sys_module.join("nbd").exists()
}

/// Parse `/proc/sys/vm/nr_hugepages`; > 0 ⇒ hugepages reserved. Pure so it's
/// testable cross-platform; a non-numeric/empty read is "none reserved".
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn hugetlb_reserved_from(nr_hugepages: &str) -> bool {
    nr_hugepages
        .trim()
        .parse::<u64>()
        .map(|n| n > 0)
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn collect_warm_start_substrate() -> Option<WarmStartSubstrate> {
    let nr = std::fs::read_to_string("/proc/sys/vm/nr_hugepages").unwrap_or_default();
    Some(WarmStartSubstrate {
        nbd_module_loaded: nbd_module_loaded_at(std::path::Path::new("/sys/module")),
        hugetlb_reserved: hugetlb_reserved_from(&nr),
    })
}

#[cfg(not(target_os = "linux"))]
fn collect_warm_start_substrate() -> Option<WarmStartSubstrate> {
    None
}

/// Print the warm-start matrix in `mvmctl doctor` text mode. One line per
/// backend, then the Linux substrate (or N/A off Linux).
pub(super) fn render_warm_start_support(r: &WarmStartReport) {
    let title = "Warm-start capability (per backend)";
    println!("\n{}", title);
    println!("{}", "-".repeat(title.len()));
    for (backend, tier) in &r.backends {
        ui::status_line(&format!("  {backend}:"), tier);
    }
    match &r.substrate {
        Some(s) => {
            ui::status_line(
                "  substrate · NBD module",
                if s.nbd_module_loaded {
                    "loaded"
                } else {
                    "not loaded"
                },
            );
            ui::status_line(
                "  substrate · HugeTLB",
                if s.hugetlb_reserved {
                    "reserved"
                } else {
                    "none reserved"
                },
            );
        }
        None => ui::status_line("  substrate (Linux fast-resume)", "N/A (Linux-only)"),
    }

    // The standby pool (pre-pay spawn latency), a separate axis from
    // the snapshot tiers above. Only libkrun implements it today.
    let pool_title = "Standby pool (per backend)";
    println!("\n{}", pool_title);
    println!("{}", "-".repeat(pool_title.len()));
    for (backend, supported) in &r.standby_pool {
        ui::status_line(
            &format!("  {backend}:"),
            if *supported { "supported" } else { "—" },
        );
    }
    ui::status_line(
        "  idle standbys",
        &match r.standby_pool_idle {
            Some(n) => n.to_string(),
            None => "unknown".to_string(),
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collect_warm_start_support_reports_per_backend_tier() {
        let r = collect_warm_start_support();
        // The honest per-backend warm-start matrix.
        assert_eq!(r.backends.get("firecracker"), Some(&"live-memory"));
        assert_eq!(r.backends.get("libkrun"), Some(&"disk-only"));
        assert_eq!(r.backends.get("qemu"), Some(&"disk-only"));
    }

    #[test]
    fn collect_warm_start_support_keeps_catalog_backends_in_stable_order() {
        let r = collect_warm_start_support();
        let ordered_backends: Vec<_> = r.backends.into_iter().collect();
        let ordered_standby_pool: Vec<_> = r.standby_pool.into_iter().collect();

        assert_eq!(
            ordered_backends,
            vec![
                ("firecracker".to_string(), "live-memory"),
                ("libkrun".to_string(), "disk-only"),
                ("qemu".to_string(), "disk-only"),
            ]
        );
        assert_eq!(
            ordered_standby_pool,
            vec![
                ("firecracker".to_string(), true),
                ("libkrun".to_string(), true),
                ("qemu".to_string(), false),
            ]
        );
    }

    #[test]
    fn collect_warm_start_support_reports_standby_pool_per_backend() {
        let r = collect_warm_start_support();
        // Firecracker and libkrun implement the standby pool; QEMU does not.
        // Report honest values for every backend; none may be silently dropped.
        assert_eq!(r.standby_pool.get("firecracker"), Some(&true));
        assert_eq!(r.standby_pool.get("libkrun"), Some(&true));
        assert_eq!(r.standby_pool.get("qemu"), Some(&false));
    }

    #[test]
    fn collect_capability_table_reports_per_backend_dispositions() {
        let rows = collect_capability_table();
        let by = |name: &str| rows.iter().find(|r| r.backend == name).cloned();

        // The Tier 3 `mock` test double is excluded; the three real
        // backends are present, in stable name order.
        let names: Vec<_> = rows.iter().map(|r| r.backend.as_str()).collect();
        assert_eq!(names, vec!["firecracker", "libkrun", "qemu"]);

        let fc = by("firecracker").unwrap();
        assert_eq!(fc.snapshot_tier, "live-memory");
        assert!(fc.tap_networking, "firecracker uses a host TAP device");
        assert!(fc.vsock);
        assert!(fc.balloon);
        assert!(
            fc.standby_pool,
            "Firecracker implements live standby warm-spawn"
        );

        let krun = by("libkrun").unwrap();
        assert_eq!(krun.snapshot_tier, "disk-only");
        assert!(
            !krun.tap_networking,
            "libkrun uses a userspace gateway, not a host TAP"
        );
        assert!(krun.vsock);
        assert!(
            krun.standby_pool,
            "libkrun still pre-pays spawn latency through the supervisor pool"
        );

        let qemu = by("qemu").unwrap();
        assert_eq!(qemu.snapshot_tier, "disk-only");
        assert!(
            !qemu.tap_networking,
            "qemu uses user-mode slirp, not a host TAP"
        );
        assert!(qemu.vsock);
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn warm_start_substrate_is_none_off_linux() {
        // The NBD/HugeTLB fast-resume substrate is Linux-only; macOS reports
        // the per-backend tier but N/A for the substrate.
        assert!(collect_warm_start_support().substrate.is_none());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn warm_start_substrate_is_probed_on_linux() {
        // On Linux the substrate is probed (values depend on the host; we only
        // assert it's present, not loaded).
        assert!(collect_warm_start_support().substrate.is_some());
    }

    #[test]
    fn hugetlb_reserved_from_parses_count() {
        assert!(!hugetlb_reserved_from("0\n"));
        assert!(hugetlb_reserved_from("128\n"));
        assert!(!hugetlb_reserved_from("garbage"));
        assert!(!hugetlb_reserved_from(""));
    }

    #[test]
    fn nbd_module_loaded_at_detects_presence() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(!nbd_module_loaded_at(tmp.path()));
        std::fs::create_dir(tmp.path().join("nbd")).unwrap();
        assert!(nbd_module_loaded_at(tmp.path()));
    }
}
