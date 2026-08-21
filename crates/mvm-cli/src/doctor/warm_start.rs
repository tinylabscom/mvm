//! Per-backend recovery capability matrix — snapshot tier, standby pool,
//! and the Linux fast-resume substrate probe.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::ui;

/// Per-backend warm-start capability + Linux fast-resume substrate, surfaced
/// under `warm_start` in `mvmctl doctor --json`.
#[derive(Debug, Serialize)]
pub(super) struct WarmStartReport {
    /// Backend name → recovery tier label (`SnapshotCapability::label`).
    /// `BTreeMap` for deterministic JSON ordering, like `balloon_support`.
    backends: BTreeMap<String, &'static str>,
    /// The Linux-only fast-resume substrate (NBD module, HugeTLB reservation).
    /// `null` off Linux — the substrate backs the KVM Firecracker fast-resume
    /// path; macOS reports per-backend tiers but N/A here.
    substrate: Option<WarmStartSubstrate>,
    /// Backend name → standby-pool capability from `VmCapabilities`.
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

/// Build the per-backend capability matrix from every selectable catalog
/// backend. Each row reads the authoritative `VmCapabilities` value, so the
/// doctor's table cannot drift from runtime behavior. Sorted by name for
/// deterministic output.
pub(super) fn collect_capability_table() -> Vec<BackendCapabilityRow> {
    let mut rows: Vec<BackendCapabilityRow> = mvm_runtime::catalog::descriptors()
        .iter()
        .filter(|descriptor| {
            descriptor.kind != mvm_core::vm_backend::BackendKind::Mock
                || cfg!(feature = "test-support")
        })
        .map(|descriptor| {
            let b = descriptor.instantiate_dyn();
            let caps = b.capabilities();
            BackendCapabilityRow {
                backend: b.name().to_string(),
                snapshot_tier: caps.snapshot_capability.label(),
                tap_networking: caps.tap_networking,
                vsock: caps.vsock,
                balloon: caps.balloon,
                fs_quick_checkpoint: caps.fs_quick_checkpoint,
                standby_pool: caps.standby_pool,
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

/// Enumerate every backend's authoritative recovery tier and standby
/// capability and, on Linux, probe the fast-resume substrate. Unsupported
/// backends remain in the report so an operator sees an explicit refusal
/// instead of mistaking an omitted row for an undocumented fallback.
pub(super) fn collect_warm_start_support() -> WarmStartReport {
    let mut backends = BTreeMap::new();
    let mut standby_pool = BTreeMap::new();
    for descriptor in mvm_runtime::catalog::descriptors()
        .iter()
        .filter(|descriptor| {
            descriptor.kind != mvm_core::vm_backend::BackendKind::Mock
                || cfg!(feature = "test-support")
        })
    {
        let b = descriptor.instantiate_dyn();
        let caps = b.capabilities();
        backends.insert(b.name().to_string(), caps.snapshot_capability.label());
        standby_pool.insert(b.name().to_string(), caps.standby_pool);
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
    // the snapshot tiers above.
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
        assert_eq!(r.backends.get("firecracker"), Some(&"unsupported"));
        assert_eq!(r.backends.get("libkrun"), Some(&"unsupported"));
        assert_eq!(r.backends.get("qemu"), Some(&"unsupported"));
        // HVF saves and reloads machine state; apple-container boots through
        // the same supervisor and inherits the tier.
        assert_eq!(r.backends.get("hvf"), Some(&"save-restore"));
        assert_eq!(r.backends.get("wasm"), Some(&"unsupported"));
        assert_eq!(r.backends.get("apple-container"), Some(&"save-restore"));
    }

    #[test]
    fn collect_warm_start_support_keeps_catalog_backends_in_stable_order() {
        let r = collect_warm_start_support();
        let ordered_backends: Vec<_> = r.backends.into_iter().collect();
        let ordered_standby_pool: Vec<_> = r.standby_pool.into_iter().collect();

        let mut expected_backends = vec![
            ("apple-container".to_string(), "save-restore"),
            ("firecracker".to_string(), "unsupported"),
            ("hvf".to_string(), "save-restore"),
            ("libkrun".to_string(), "unsupported"),
            ("qemu".to_string(), "unsupported"),
            ("wasm".to_string(), "unsupported"),
            ("web-linux".to_string(), "unsupported"),
        ];
        let mut expected_standby_pool = vec![
            ("apple-container".to_string(), false),
            ("firecracker".to_string(), true),
            ("hvf".to_string(), true),
            ("libkrun".to_string(), false),
            ("qemu".to_string(), false),
            ("wasm".to_string(), false),
            ("web-linux".to_string(), false),
        ];
        if cfg!(feature = "test-support") {
            expected_backends.insert(4, ("mock".to_string(), "live-memory"));
            expected_standby_pool.insert(4, ("mock".to_string(), false));
        }
        assert_eq!(ordered_backends, expected_backends);
        assert_eq!(ordered_standby_pool, expected_standby_pool);
    }

    #[test]
    fn collect_warm_start_support_reports_standby_pool_per_backend() {
        let r = collect_warm_start_support();
        assert_eq!(r.standby_pool.get("firecracker"), Some(&true));
        assert_eq!(r.standby_pool.get("libkrun"), Some(&false));
        assert_eq!(r.standby_pool.get("qemu"), Some(&false));
    }

    #[test]
    fn collect_capability_table_reports_per_backend_dispositions() {
        let rows = collect_capability_table();
        let by = |name: &str| rows.iter().find(|r| r.backend == name).cloned();

        // Every selectable backend remains in the matrix, including explicit
        // unsupported recovery tiers.
        let names: Vec<_> = rows.iter().map(|r| r.backend.as_str()).collect();
        let mut expected = vec![
            "apple-container",
            "firecracker",
            "hvf",
            "libkrun",
            "qemu",
            "wasm",
            "web-linux",
        ];
        if cfg!(feature = "test-support") {
            expected.push("mock");
            expected.sort_unstable();
        }
        assert_eq!(names, expected);

        let qemu = by("qemu").unwrap();
        assert_eq!(qemu.snapshot_tier, "unsupported");
        assert!(
            !qemu.tap_networking,
            "qemu uses user-mode slirp, not a host TAP"
        );
        assert!(qemu.vsock);

        let libkrun = by("libkrun").unwrap();
        assert_eq!(libkrun.snapshot_tier, "unsupported");
        assert!(!libkrun.standby_pool);

        // The doctor table reports what a host can actually service. The
        // runner-backed Firecracker path now advertises the saved-state pool
        // because refill preloads a paused child and claim resumes it only
        // after fresh channels and identity gates are armed.
        let firecracker = by("firecracker").unwrap();
        assert!(firecracker.standby_pool);
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
