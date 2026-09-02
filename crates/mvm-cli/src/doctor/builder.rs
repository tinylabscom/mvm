//! Everything builder-VM: dev-VM reachability, egress/transport posture,
//! Stage 0 status, and the builder backend/residency selection reports.

use super::Check;
use mvm_core::platform::Platform;

/// Path of the host-side vsock proxy socket for the dev VM.
///
/// The Apple Container backend names the dev VM `mvm-dev` and writes its
/// proxy socket under `mvm_share_dir()` — its presence is doctor's signal
/// that the builder VM is reachable. The legacy `mvm-builder` constant
/// (`VM_NAME`) is the routing key for `shell::run_on_vm`, not a filesystem
/// path.
pub(super) fn dev_vm_socket_path() -> String {
    mvm_core::config::vm_vsock_proxy_socket("mvm-dev")
        .display()
        .to_string()
}

pub(super) fn dev_vm_running() -> bool {
    std::path::Path::new(&dev_vm_socket_path()).exists()
}

/// Informational `Check` returned when a builder-tool probe can't run
/// because the dev VM is down. Doctor exits 0 in this case — builder
/// tooling lives in the dev VM, never on the host, so its absence is
/// not a host-side defect.
pub(super) fn builder_tool_skipped(name: &'static str, category: &'static str) -> Check {
    Check {
        name,
        category,
        ok: true,
        info: "skipped — dev VM not running; run `mvmctl bootstrap` to verify".into(),
    }
}

pub(super) fn stage0_status_check() -> Check {
    use mvm_core::policy::audit::LocalAuditKind;
    let info = match mvm_core::policy::audit::read_last_stage0_event() {
        None => "no Stage 0 recorded yet (run `mvmctl bootstrap`)".to_string(),
        Some(ev) => {
            let outcome = match ev.kind {
                LocalAuditKind::Stage0Boot => "boot (in progress or interrupted)",
                LocalAuditKind::Stage0CachePromoted => "cache promoted (clean)",
                LocalAuditKind::Stage0Failed => "failed",
                _ => "unknown",
            };
            match ev.detail {
                Some(d) => format!("last Stage 0: {outcome} at {} ({d})", ev.timestamp),
                None => format!("last Stage 0: {outcome} at {}", ev.timestamp),
            }
        }
    };
    Check {
        name: "stage 0",
        category: "tools",
        ok: true,
        info,
    }
}

/// Surface the builder VM store's on-disk presence + size. Host-side we
/// can't verify nix-store integrity (that needs booting the VM), so this is
/// informational: present/absent + size, with the `cache repair` recovery path
/// noted. `ok` is always true — an absent store just means a cold first build,
/// and a present-but-degraded store isn't host-detectable without a build.
pub(super) fn builder_store_check() -> Check {
    // The repair dry-run is a pure read: it returns (existed, bytes, path)
    // without removing anything.
    let info = match mvm_build::builder_vm::clear_builder_store(true) {
        Ok(s) if s.existed => format!(
            "present ({:.1} GiB) at {} — if `mvmctl bootstrap` fails with a dangling-store \
             error, run `mvmctl cache repair`",
            s.bytes_freed as f64 / (1024.0 * 1024.0 * 1024.0),
            s.path,
        ),
        Ok(s) => format!("absent ({} — first `mvmctl bootstrap` builds it)", s.path),
        Err(e) => format!("could not stat builder store: {e}"),
    };
    Check {
        name: "builder store",
        category: "tools",
        ok: true,
        info,
    }
}

/// The builder VM's fixed egress posture, appended to every
/// builder-egress line as an affirmation. The builder VM locks egress on
/// the deps-install arm (proxy-uid-only, fail-closed) and opens it for
/// flake-build fetches — a fixed design, not a runtime decision.
#[cfg(feature = "builder-vm")]
const BUILDER_EGRESS_POSTURE: &str = "egress is locked on the deps-install arm (proxy-uid-only, fail-closed) \
     and open for flake-build fetches";

/// Map a parsed network-bootstrap outcome to its `Check` body.
/// Pure so the classification → report mapping is unit-testable without
/// touching the filesystem.
#[cfg(feature = "builder-vm")]
fn builder_egress_check_from_outcome(outcome: mvm_build::guest_net::BuilderNetBootstrap) -> Check {
    use mvm_build::guest_net::BuilderNetBootstrap;
    // The check name is already "builder egress", and the renderer prints
    // it as `builder egress: <status> (<info>)` — so the info body omits
    // the redundant prefix and leads with the outcome.
    let (ok, info) = match outcome {
        BuilderNetBootstrap::Lease { ip } => (
            true,
            format!("DHCP lease {ip} on the builder egress path; {BUILDER_EGRESS_POSTURE}"),
        ),
        BuilderNetBootstrap::StaticFallback { ip } => (
            true,
            format!(
                "static fallback {ip} (no DHCP lease — degraded but \
                 reachable); {BUILDER_EGRESS_POSTURE}"
            ),
        ),
        BuilderNetBootstrap::Failed => (
            false,
            format!(
                "net bootstrap FAILED (no DHCP lease, no static fallback \
                 — builds can't fetch); {BUILDER_EGRESS_POSTURE}"
            ),
        ),
        BuilderNetBootstrap::Unknown => (
            true,
            format!("outcome not yet recorded in console.log; {BUILDER_EGRESS_POSTURE}"),
        ),
    };
    Check {
        name: "builder egress",
        category: "platform",
        ok,
        info,
    }
}

/// Surface the persistent builder VM's last network-bootstrap outcome
/// (DHCP lease / static fallback / failure) so the failure class is
/// diagnosable without reading the guest console by hand.
///
/// Reads the libkrun dev VM's host-side `console.log` at the fixed
/// `mvm-dev` state dir. When the VM hasn't booted yet the file is absent and
/// the check reports that cleanly.
#[cfg(feature = "builder-vm")]
pub(super) fn builder_egress_check() -> Check {
    let log_path = mvm_core::config::vm_state_dir("mvm-dev").join("console.log");
    let Ok(contents) = std::fs::read_to_string(&log_path) else {
        return Check {
            name: "builder egress",
            category: "platform",
            ok: true,
            info: "no builder VM yet (run `mvmctl bootstrap`)".to_string(),
        };
    };
    let outcome = mvm_build::guest_net::classify_builder_net_bootstrap(&contents);
    builder_egress_check_from_outcome(outcome)
}

/// Stub when the `builder-vm` feature is off — a CLI built without builder
/// support never boots a builder VM.
#[cfg(not(feature = "builder-vm"))]
pub(super) fn builder_egress_check() -> Check {
    Check {
        name: "builder egress",
        category: "platform",
        ok: true,
        info: "n/a (mvm-cli built without `builder-vm` feature)".to_string(),
    }
}

/// Probe timeout for the resident builder-daemon readiness check. Short
/// so `doctor` stays responsive even when a stale socket is present.
const BUILDERD_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(300);

/// Summarize resident builder-daemon (`mvm-builderd`) readiness across the
/// persistent builder VMs under `vms_root`. Each builder VM exposes its
/// typed control socket at `<vm_state_dir>/vsock-<BUILDERD_CONTROL_PORT>.sock`;
/// every present socket is probed with a bounded handshake. Informational:
/// absence just means no builder VM is running, so `ok` stays true.
fn builderd_daemon_summary(vms_root: &std::path::Path) -> String {
    let Ok(entries) = std::fs::read_dir(vms_root) else {
        return "absent (no builder VM yet; run `mvmctl bootstrap`)".to_string();
    };
    let mut lines = Vec::new();
    for entry in entries.flatten() {
        let dir = entry.path();
        if !dir.is_dir() {
            continue;
        }
        // A builder VM may be libkrun (`<dir>/vsock-<port>.sock`) or HVF
        // (`<dir>/vsock/vsock-<port>.sock`); probe whichever socket the
        // backend actually created.
        let Some(sock) = mvm_build::builderd::builderd_control_socket_candidates(&dir)
            .into_iter()
            .find(|p| p.exists())
        else {
            continue;
        };
        let name = entry.file_name().to_string_lossy().into_owned();
        let readiness =
            mvm_build::builderd::probe_builderd_readiness(&sock, BUILDERD_PROBE_TIMEOUT);
        lines.push(format!(
            "{name}: {}",
            mvm_build::builderd::readiness_summary(&readiness)
        ));
    }
    lines.sort();
    if lines.is_empty() {
        return "absent (no builder daemon; run `mvmctl bootstrap`)".to_string();
    }
    lines.join("; ")
}

/// Resident builder-daemon readiness. Informational.
pub(super) fn builderd_daemon_check() -> Check {
    let vms_root = mvm_build::builder_vm::builder_vm_cache_dir().join("vms");
    Check {
        name: "builder daemon",
        category: "platform",
        ok: true,
        info: builderd_daemon_summary(&vms_root),
    }
}

/// The builder transport shape currently in effect on this host.
///
/// This makes the no-guest-NIC cutover status explicit instead of forcing an
/// operator to infer it from the backend line plus the separate egress check.
/// It also marks the remaining guest-NIC-based paths as legacy/unsupported for
/// the production vsock-only architecture.
#[cfg(feature = "builder-vm")]
pub(super) fn builder_transport_check(plat: Platform) -> Check {
    use mvm_build::builder_backend_select::BuilderBackendChoice;
    let choice = mvm_build::builder_backend_select::resolve_choice();
    let info = match choice {
        BuilderBackendChoice::Hvf => {
            "vsock-only host/guest transport; no builder guest NIC, no DHCP or gateway bootstrap"
                .to_string()
        }
        BuilderBackendChoice::Libkrun => {
            if plat == Platform::Wsl2 {
                "legacy guest-network bootstrap path on libkrun (DHCP/static fallback); no-guest-NIC builder cutover not landed on WSL2"
                    .to_string()
            } else {
                "legacy guest-network bootstrap path on libkrun (DHCP/static fallback); still a builder networking exception, not the final vsock-only transport"
                    .to_string()
            }
        }
        BuilderBackendChoice::Qemu => {
            "unsupported legacy builder path: qemu dev/test fallback with guest-network bootstrap; not part of the production vsock-only architecture"
                .to_string()
        }
        BuilderBackendChoice::WebLinux => {
            "browser-only WebLinux builder; no native transport or builder guest".to_string()
        }
    };
    Check {
        name: "builder transport",
        category: "platform",
        ok: true,
        info,
    }
}

#[cfg(not(feature = "builder-vm"))]
pub(super) fn builder_transport_check(_plat: Platform) -> Check {
    Check {
        name: "builder transport",
        category: "platform",
        ok: true,
        info: "n/a (mvm-cli built without `builder-vm` feature)".to_string(),
    }
}

/// Surface which builder-VM backend the selection layer resolves to
/// on this host, plus the override source if any.
///
/// `mvm_build::builder_backend_select` enforces priority
/// `--builder` flag > `MVM_BUILDER_BACKEND` env > platform default
/// (macOS 26+ Apple Silicon → hvf; Linux native → qemu; everywhere else →
/// libkrun). The
/// flag is folded into the env at startup (`commands::run`), so by
/// the time doctor runs every override is observable via env.
///
/// The check is informational — it never fails. A missing libkrun
/// prereq is reported by the platform-level `libkrun_check` already in
/// the report; this check is about the *selection*, not the availability.
#[cfg(feature = "builder-vm")]
pub(super) fn builder_backend_check(plat: Platform) -> Check {
    use mvm_build::builder_backend_select::{
        BuilderBackendChoice, MVM_BUILDER_BACKEND_ENV, MVM_LINUX_BUILDER_VM_ENV,
        auto_detect_default_for, linux_builder_vm_requested, resolve_env_override,
    };

    let env_override = resolve_env_override();
    // Derive the whole line from the `plat` we were handed, not from a second,
    // independent probe of the live host. `auto_detect_default()` re-probes;
    // using it here made the backend half of this line describe the real host
    // while the availability half described `plat`, so the two could disagree
    // and the report would be internally inconsistent. It also made the
    // function untestable for any platform other than the one running it.
    let auto = auto_detect_default_for(
        plat,
        plat.is_hvf_default_tier() && cfg!(target_arch = "aarch64"),
    );
    let resolved = env_override.unwrap_or(auto);

    // Best-effort: detect whether the override came from the
    // `--builder` flag or the env var. The flag is folded into the
    // env at startup, so we can't distinguish them after the fact;
    // surface both possibilities so an operator reading the report
    // knows where to look.
    let mut source = match env_override {
        Some(_) => format!("override via --builder / ${MVM_BUILDER_BACKEND_ENV}"),
        None => format!("auto-detected (default: {})", auto.name()),
    };
    // Surface the Linux-only rollout signal alongside the backend
    // selection. The env does not participate in choosing the builder backend;
    // it changes how the workload path will dispatch once nested Firecracker
    // lands. Operators who set it should see it acknowledged in `doctor`
    // output.
    if linux_builder_vm_requested() {
        source = format!("{source}; ${MVM_LINUX_BUILDER_VM_ENV}=1 (Plan 100 W6 opt-in)");
    }

    let availability = match resolved {
        BuilderBackendChoice::Libkrun => {
            if plat.has_libkrun() {
                "libkrun available".to_string()
            } else {
                format!("libkrun NOT available ({})", libkrun_sys::install_hint())
            }
        }
        BuilderBackendChoice::Qemu => {
            // Linux dev/builder backend. KVM-accelerated
            // where /dev/kvm is present, TCG fallback otherwise.
            if which::which("qemu-system-x86_64").is_ok()
                || which::which("qemu-system-aarch64").is_ok()
            {
                let accel = if std::path::Path::new("/dev/kvm").exists() {
                    "KVM"
                } else {
                    "TCG (unaccelerated)"
                };
                format!("QEMU available ({accel})")
            } else {
                "QEMU NOT available (apt install qemu-system-x86 qemu-utils)".to_string()
            }
        }
        BuilderBackendChoice::Hvf => {
            "HVF builder (constructor registered at CLI startup)".to_string()
        }
        BuilderBackendChoice::WebLinux => {
            "WebLinux builder is browser-only; not available on native hosts".to_string()
        }
    };

    Check {
        name: "builder backend",
        category: "platform",
        ok: true,
        info: format!("{} — {} — {}", resolved.name(), source, availability),
    }
}

/// Which arm will produce the default boot image, and why.
///
/// A source checkout builds its own images and an installed binary fetches one.
/// That is usually invisible, which is fine until the two disagree with what an
/// operator expected — at which point "which arm ran" is the first question and
/// there has been nowhere to read the answer. Reported in the same
/// `<choice> — <source> — <availability>` shape as the builder backend line, so
/// the override path is observable rather than folklore.
pub(super) fn boot_image_acquisition_check() -> Check {
    use mvm_build::boot_image_select::{BootImageAcquisition, resolve};

    let is_checkout = crate::commands::env::builder_vm::find_builder_vm_flake_is_source_checkout();
    let resolved = resolve(None, is_checkout);

    // The arm can be chosen and still be unsatisfiable: `build` on an installed
    // binary has no flake to build from. Say so here rather than letting the
    // first image acquisition be where the operator finds out.
    let availability = match resolved.choice {
        BootImageAcquisition::Build if is_checkout => "in-repo image flake present".to_string(),
        BootImageAcquisition::Build => {
            "NO in-repo image flake — a forced local build will refuse".to_string()
        }
        BootImageAcquisition::Fetch if is_checkout => {
            "fetching a prebuilt from a source checkout; the image will record itself as fetched"
                .to_string()
        }
        BootImageAcquisition::Fetch => "published image".to_string(),
    };

    Check {
        name: "boot image",
        category: "platform",
        // Informational: every combination is a legitimate operator choice.
        // The forced-build-without-a-flake case is named in the text and
        // refuses at acquisition time, which is where it can say what to do.
        ok: true,
        info: format!(
            "{} — {} — {availability}",
            resolved.choice.name(),
            resolved.source.describe()
        ),
    }
}

/// Stub when `builder-vm` feature is off (CLI built without the
/// builder support — e.g. dependency-light packaging).
#[cfg(not(feature = "builder-vm"))]
pub(super) fn builder_backend_check(_plat: Platform) -> Check {
    Check {
        name: "builder backend",
        category: "platform",
        ok: true,
        info: "n/a (mvm-cli built without `builder-vm` feature)".to_string(),
    }
}

/// Informational check: the residency policy's effect on builder routing
/// and whether a persistent builder session is currently live.
///
/// The check never fails — the routing choice is always observable via
/// `MVM_RESIDENCY` and the session state is a best-effort filesystem probe.
/// The two axes together let an operator understand what `mvmctl build image`
/// will do before invoking it.
#[cfg(feature = "builder-vm")]
pub(super) fn builder_residency_check() -> Check {
    let (policy, _source) = mvm_core::residency::resolve_residency();
    let routing = if policy.allows_persistent_builder() {
        "uses persistent when active"
    } else {
        "ephemeral per build (cold)"
    };
    let vms_root = mvm_build::builder_vm::builder_vm_cache_dir().join("vms");
    let session = builder_residency_session_summary(
        policy.kind(),
        mvm_build::persistent_builder::read_active_session().is_some(),
        builder_parked_snapshot_present(&vms_root),
    );
    Check {
        name: "builder residency",
        category: "platform",
        ok: true,
        info: format!("{} — builds {} — {}", policy.label(), routing, session),
    }
}

/// The persistent-builder snapshot/park mechanism belonged to a removed
/// builder; the libkrun builder has no memory snapshot, so no builder VM
/// carries a resumable snapshot today. Always `false` until some builder
/// grows one.
#[cfg(feature = "builder-vm")]
fn builder_parked_snapshot_present(_vms_root: &std::path::Path) -> bool {
    false
}

#[cfg(feature = "builder-vm")]
fn builder_residency_session_summary(
    kind: mvm_core::residency::ResidencyKind,
    persistent_active: bool,
    parked_snapshot_present: bool,
) -> &'static str {
    match kind {
        mvm_core::residency::ResidencyKind::Parked if parked_snapshot_present => {
            "parked (snapshot present)"
        }
        mvm_core::residency::ResidencyKind::Parked => "parked (no snapshot)",
        _ if persistent_active => "persistent builder active",
        _ if parked_snapshot_present => "parked snapshot present",
        _ => "no persistent builder",
    }
}

/// Stub when the `builder-vm` feature is off.
#[cfg(not(feature = "builder-vm"))]
pub(super) fn builder_residency_check() -> Check {
    Check {
        name: "builder residency",
        category: "platform",
        ok: true,
        info: "n/a (mvm-cli built without `builder-vm` feature)".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::util::test_env::TestEnv;

    struct EnvGuard {
        _env: TestEnv,
        _tmp_root: Option<tempfile::TempDir>,
    }

    impl EnvGuard {
        fn new(root: Option<tempfile::TempDir>) -> Self {
            let mut env = TestEnv::new();
            if let Some(r) = root.as_ref() {
                env.set("MVM_HOME", r.path());
            }
            EnvGuard {
                _env: env,
                _tmp_root: root,
            }
        }
    }

    #[test]
    fn dev_vm_socket_path_lives_in_the_dev_vm_state_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let expected = format!("{}/vms/mvm-dev/vsock.sock", tmp.path().display());
        let _g = EnvGuard::new(Some(tmp));
        assert_eq!(dev_vm_socket_path(), expected);
    }

    #[test]
    fn dev_vm_running_is_false_when_no_socket() {
        let _g = EnvGuard::new(Some(tempfile::tempdir().unwrap()));
        assert!(
            !dev_vm_running(),
            "fresh tempdir has no vsock socket; dev_vm_running must be false"
        );
    }

    #[test]
    fn builder_tool_skipped_reports_ok_with_skip_marker() {
        let c = builder_tool_skipped("nix", "tools");
        assert!(c.ok, "skip is informational, not a failure");
        assert_eq!(c.name, "nix");
        assert_eq!(c.category, "tools");
        assert!(
            c.info.contains("dev VM not running"),
            "expected skip marker, got: {}",
            c.info
        );
    }

    #[cfg(feature = "builder-vm")]
    #[test]
    fn builder_egress_lease_is_ok_and_names_ip() {
        use mvm_build::guest_net::BuilderNetBootstrap;
        let c = builder_egress_check_from_outcome(BuilderNetBootstrap::Lease {
            ip: "192.168.127.3".to_string(),
        });
        assert_eq!(c.name, "builder egress");
        assert_eq!(c.category, "platform");
        assert!(c.ok);
        assert!(c.info.contains("DHCP lease 192.168.127.3"));
        assert!(c.info.contains("builder egress path"));
        assert!(c.info.contains("fail-closed"), "posture appended");
    }

    #[cfg(feature = "builder-vm")]
    #[test]
    fn builder_egress_static_fallback_is_ok_but_degraded() {
        use mvm_build::guest_net::BuilderNetBootstrap;
        let c = builder_egress_check_from_outcome(BuilderNetBootstrap::StaticFallback {
            ip: "192.168.127.3".to_string(),
        });
        assert!(c.ok);
        assert!(c.info.contains("static fallback 192.168.127.3"));
        assert!(c.info.contains("degraded but reachable"));
    }

    #[cfg(feature = "builder-vm")]
    #[test]
    fn builder_egress_failed_is_not_ok() {
        use mvm_build::guest_net::BuilderNetBootstrap;
        let c = builder_egress_check_from_outcome(BuilderNetBootstrap::Failed);
        assert!(!c.ok);
        assert!(c.info.contains("FAILED"));
        assert!(c.info.contains("can't fetch"));
    }

    #[cfg(feature = "builder-vm")]
    #[test]
    fn builder_egress_unknown_is_ok() {
        use mvm_build::guest_net::BuilderNetBootstrap;
        let c = builder_egress_check_from_outcome(BuilderNetBootstrap::Unknown);
        assert!(c.ok);
        assert!(c.info.contains("not yet recorded"));
    }

    #[cfg(feature = "builder-vm")]
    #[test]
    fn builder_egress_check_reports_no_vm_when_console_log_absent() {
        // With MVM_HOME pointed at an empty dir there is no
        // persistent builder console.log, so the check reports the
        // no-VM-yet info and exits ok.
        let scratch = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", scratch.path());
        let c = builder_egress_check();
        assert!(c.ok);
        assert!(c.info.contains("no builder VM yet"));
    }

    #[cfg(feature = "builder-vm")]
    #[test]
    fn builder_egress_check_classifies_a_fixture_console_log() {
        let scratch = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", scratch.path());
        // Materialize a fixture console.log at the exact path the helper
        // resolves, then assert the lease is read end-to-end.
        let log = mvm_core::config::vm_state_dir("mvm-dev").join("console.log");
        std::fs::create_dir_all(log.parent().unwrap()).unwrap();
        std::fs::write(
            &log,
            "udhcpc: lease of 192.168.127.3 obtained from 192.168.127.1, lease time 3600\n",
        )
        .unwrap();
        let c = builder_egress_check();
        assert!(c.ok);
        assert!(c.info.contains("DHCP lease 192.168.127.3"));
    }

    #[test]
    fn builderd_daemon_check_is_informational_platform_check() {
        let c = builderd_daemon_check();
        assert_eq!(c.name, "builder daemon");
        assert_eq!(c.category, "platform");
        assert!(
            c.ok,
            "builder-daemon readiness is informational, never blocking"
        );
    }

    #[test]
    fn builderd_daemon_summary_absent_when_root_missing_or_empty() {
        let root = tempfile::tempdir().unwrap();
        assert!(builderd_daemon_summary(&root.path().join("missing")).starts_with("absent"));
        // An empty vms root, and a builder-VM dir with no control socket,
        // both read as absent (nothing to probe).
        assert!(builderd_daemon_summary(root.path()).starts_with("absent"));
        std::fs::create_dir_all(root.path().join("mvm-persistent-builder-vm-x")).unwrap();
        assert!(builderd_daemon_summary(root.path()).starts_with("absent"));
    }

    #[test]
    fn builderd_daemon_summary_reports_ready_for_a_live_daemon() {
        use std::os::unix::net::UnixListener;
        // A builder-VM state dir whose control socket is served by the
        // real `serve_connection` loop reports "ready". Bind under a short
        // /tmp root with a short dir name — the full socket path must fit
        // under the AF_UNIX SUN_LEN limit (~104 bytes on macOS).
        let root = tempfile::Builder::new()
            .prefix("mvmbd")
            .tempdir_in("/tmp")
            .unwrap();
        let vm_dir = root.path().join("bv");
        std::fs::create_dir_all(&vm_dir).unwrap();
        let sock = mvm_build::builderd::builderd_control_socket_path(&vm_dir);
        let listener = match UnixListener::bind(&sock) {
            Ok(listener) => listener,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("skipping builderd daemon summary unix listener test: {err}");
                return;
            }
            Err(err) => panic!("bind: {err}"),
        };
        let handle = std::thread::spawn(move || {
            let (mut conn, _addr) = listener.accept().expect("accept");
            mvm_build::builderd::serve_connection(&mut conn).expect("serve");
        });

        let s = builderd_daemon_summary(root.path());
        assert!(s.contains("bv: ready"), "got {s:?}");
        handle.join().expect("server thread");
    }

    #[test]
    fn builderd_daemon_summary_finds_an_hvf_shaped_socket() {
        use std::os::unix::net::UnixListener;
        // Regression for the live HVF boot: the HVF supervisor nests the
        // control socket under `<vm_state_dir>/vsock/`. The scan must find
        // it there, not only at the libkrun `<vm_state_dir>/vsock-*.sock`.
        let root = tempfile::Builder::new()
            .prefix("mvmbd")
            .tempdir_in("/tmp")
            .unwrap();
        let vm_dir = root.path().join("bhvf");
        let sock = mvm_build::builderd::builderd_hvf_control_socket_path(&vm_dir);
        std::fs::create_dir_all(sock.parent().unwrap()).unwrap();
        let listener = match UnixListener::bind(&sock) {
            Ok(listener) => listener,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("skipping builderd daemon summary unix listener test: {err}");
                return;
            }
            Err(err) => panic!("bind: {err}"),
        };
        let handle = std::thread::spawn(move || {
            let (mut conn, _addr) = listener.accept().expect("accept");
            mvm_build::builderd::serve_connection(&mut conn).expect("serve");
        });

        let s = builderd_daemon_summary(root.path());
        assert!(s.contains("bhvf: ready"), "got {s:?}");
        handle.join().expect("server thread");
    }

    #[cfg(feature = "builder-vm")]
    #[test]
    fn builder_transport_check_reports_hvf_as_vsock_only() {
        let mut env = TestEnv::new();
        env.set("MVM_BUILDER_BACKEND", "hvf");
        let c = builder_transport_check(Platform::MacOS);
        assert_eq!(c.name, "builder transport");
        assert_eq!(c.category, "platform");
        assert!(c.ok);
        assert!(c.info.contains("vsock-only"), "got {:?}", c.info);
        assert!(c.info.contains("no builder guest NIC"), "got {:?}", c.info);
    }

    #[cfg(feature = "builder-vm")]
    #[test]
    fn builder_transport_check_reports_libkrun_as_legacy_guest_network() {
        let mut env = TestEnv::new();
        env.set("MVM_BUILDER_BACKEND", "libkrun");
        let c = builder_transport_check(Platform::MacOS);
        assert_eq!(c.name, "builder transport");
        assert!(
            c.info.contains("legacy guest-network bootstrap"),
            "got {:?}",
            c.info
        );
        assert!(c.info.contains("libkrun"), "got {:?}", c.info);
    }

    #[cfg(feature = "builder-vm")]
    #[test]
    fn builder_transport_check_marks_qemu_as_unsupported_legacy() {
        let mut env = TestEnv::new();
        env.set("MVM_BUILDER_BACKEND", "qemu");
        let c = builder_transport_check(Platform::LinuxNoKvm);
        assert_eq!(c.name, "builder transport");
        assert!(c.info.contains("unsupported legacy"), "got {:?}", c.info);
        assert!(c.info.contains("qemu"), "got {:?}", c.info);
    }

    /// The report line must derive entirely from the platform it is handed.
    ///
    /// This pins the fix for a real inconsistency: the check used to resolve
    /// the backend from a second, independent probe of the live host
    /// (`auto_detect_default()`) while deriving the availability half from the
    /// `plat` argument, so on a host whose real platform differed from `plat`
    /// the two halves of one line described different machines.
    ///
    /// It is also the assertion that fails on *any* host if that regresses:
    /// a Linux box with `/dev/kvm` re-probes to qemu, one without re-probes to
    /// libkrun, so whichever machine runs this, one of the two cases below
    /// contradicts the live probe.
    #[cfg(all(target_os = "linux", feature = "builder-vm"))]
    #[test]
    fn builder_backend_check_derives_the_backend_from_the_platform_it_is_given() {
        let mut env = TestEnv::new();
        env.remove("MVM_BUILDER_BACKEND");

        let native = builder_backend_check(Platform::LinuxNative);
        assert!(
            native.info.starts_with("qemu — "),
            "LinuxNative must resolve qemu regardless of the running host; got: {}",
            native.info
        );

        let no_kvm = builder_backend_check(Platform::LinuxNoKvm);
        assert!(
            no_kvm.info.starts_with("libkrun — "),
            "LinuxNoKvm must resolve libkrun regardless of the running host; got: {}",
            no_kvm.info
        );
    }

    #[cfg(all(target_os = "linux", feature = "builder-vm"))]
    #[test]
    fn builder_backend_check_linux_reports_qemu_auto_detected() {
        let mut env = TestEnv::new();
        env.remove("MVM_BUILDER_BACKEND");

        let c = builder_backend_check(Platform::LinuxNative);

        assert!(c.ok, "builder backend check must not fail informational");
        assert_eq!(c.name, "builder backend");
        assert_eq!(c.category, "platform");
        // Format: `<backend> — <source> — <availability>`
        assert!(
            c.info.starts_with("qemu — "),
            "expected qemu-resolved line; got: {}",
            c.info
        );
        assert!(
            c.info.contains("auto-detected"),
            "expected `auto-detected` source label when env unset; got: {}",
            c.info
        );
        assert!(
            c.info.contains("QEMU available") || c.info.contains("QEMU NOT available"),
            "expected per-VMM availability segment; got: {}",
            c.info
        );
    }

    /// The knob is only useful if its answer is readable. A resolution that
    /// never reaches `doctor` leaves "which arm ran" as folklore, which is the
    /// complaint this check exists to answer.
    #[test]
    fn the_boot_image_check_reports_the_resolved_arm_and_its_source() {
        let mut env = TestEnv::new();
        env.set(mvm_build::boot_image_select::MVM_BOOT_IMAGE_ENV, "fetch");

        let c = boot_image_acquisition_check();

        assert!(c.ok);
        assert_eq!(c.name, "boot image");
        assert!(
            c.info.starts_with("fetch — "),
            "the resolved arm must lead the line; got: {}",
            c.info
        );
        assert!(
            c.info.contains("override via $MVM_BOOT_IMAGE"),
            "the line must name where the answer came from; got: {}",
            c.info
        );
        // Same three-segment shape as the builder backend line.
        assert_eq!(
            c.info.matches(" — ").count(),
            2,
            "expected `<choice> — <source> — <availability>`; got: {}",
            c.info
        );
    }

    /// Unset must read as auto-detected, not as an override nobody set.
    #[test]
    fn the_boot_image_check_reports_auto_detection_when_the_knob_is_unset() {
        let mut env = TestEnv::new();
        env.remove(mvm_build::boot_image_select::MVM_BOOT_IMAGE_ENV);

        let c = boot_image_acquisition_check();

        assert!(
            c.info.contains("auto-detected"),
            "an unset knob must not read as an override; got: {}",
            c.info
        );
        assert!(
            !c.info.contains("override via"),
            "an unset knob must not claim an override; got: {}",
            c.info
        );
    }

    #[cfg(all(target_os = "linux", feature = "builder-vm"))]
    #[test]
    fn builder_backend_check_linux_honors_env_override() {
        let mut env = TestEnv::new();
        env.set("MVM_BUILDER_BACKEND", "qemu");

        let c = builder_backend_check(Platform::LinuxNative);

        assert!(c.ok);
        // Env override flips the resolved backend even when
        // `auto_detect_default()` would have picked qemu.
        assert!(
            c.info.starts_with("qemu — "),
            "expected qemu-resolved line under env override; got: {}",
            c.info
        );
        assert!(
            c.info.contains("override via"),
            "expected `override via` source label; got: {}",
            c.info
        );
        assert!(
            c.info.contains("QEMU available") || c.info.contains("QEMU NOT available"),
            "expected per-VMM availability segment; got: {}",
            c.info
        );
    }

    #[cfg(all(target_os = "linux", feature = "builder-vm"))]
    #[test]
    fn builder_backend_check_linux_libkrun_override_no_longer_reports_a_rootfs_gap() {
        let mut env = TestEnv::new();
        env.set("MVM_BUILDER_BACKEND", "libkrun");

        let c = builder_backend_check(Platform::LinuxNative);

        assert!(
            c.info.starts_with("libkrun — "),
            "expected libkrun-resolved line under env override; got: {}",
            c.info
        );
        assert!(
            c.info.contains("override via"),
            "expected `override via` source label; got: {}",
            c.info
        );
        // The Linux/KVM steady-state guard is lifted, so doctor reports libkrun
        // availability from host capability alone and no longer surfaces a
        // rootfs-builder-unsupported gap for an explicit libkrun override.
        assert!(
            !c.info.contains("not supported on Linux/KVM"),
            "guard is lifted; expected no unsupported-rootfs gap; got: {}",
            c.info
        );
    }

    #[cfg(all(target_os = "linux", feature = "builder-vm"))]
    #[test]
    fn builder_backend_check_linux_surfaces_linux_builder_vm_env() {
        // When MVM_LINUX_BUILDER_VM=1 is set, the builder-backend line
        // adds the rollout-opt-in annotation alongside the resolved
        // backend + availability.
        let mut env = TestEnv::new();
        env.remove("MVM_BUILDER_BACKEND");
        env.set("MVM_LINUX_BUILDER_VM", "1");

        let c = builder_backend_check(Platform::LinuxNative);

        assert!(c.ok);
        assert!(
            c.info.contains("MVM_LINUX_BUILDER_VM"),
            "expected Plan 100 W6 opt-in annotation; got: {}",
            c.info
        );
        assert!(
            c.info.contains("Plan 100 W6 opt-in"),
            "expected `Plan 100 W6 opt-in` annotation; got: {}",
            c.info
        );
    }

    #[cfg(not(feature = "builder-vm"))]
    #[test]
    fn builder_backend_check_stub_when_feature_off() {
        let c = builder_backend_check(Platform::LinuxNative);
        assert!(c.ok);
        assert_eq!(c.name, "builder backend");
        assert!(
            c.info.contains("n/a"),
            "stub should mention n/a; got: {}",
            c.info
        );
    }

    #[cfg(feature = "builder-vm")]
    #[test]
    fn builder_residency_check_reports_policy_and_session_state() {
        let c = builder_residency_check();
        assert_eq!(c.category, "platform");
        assert!(c.ok);
        assert!(
            c.info.contains("persistent builder")
                || c.info.contains("parked")
                || c.info.contains("no persistent builder"),
            "info was {:?}",
            c.info
        );
        // names the builder routing effect
        assert!(
            c.info.contains("uses persistent") || c.info.contains("ephemeral"),
            "info was {:?}",
            c.info
        );
    }

    #[cfg(feature = "builder-vm")]
    #[test]
    fn builder_residency_session_summary_names_parked_snapshot_state() {
        use mvm_core::residency::ResidencyKind;

        assert_eq!(
            builder_residency_session_summary(ResidencyKind::Parked, false, true),
            "parked (snapshot present)"
        );
        assert_eq!(
            builder_residency_session_summary(ResidencyKind::Parked, false, false),
            "parked (no snapshot)"
        );
        assert_eq!(
            builder_residency_session_summary(ResidencyKind::Warm, true, false),
            "persistent builder active"
        );
        assert_eq!(
            builder_residency_session_summary(ResidencyKind::Warm, false, true),
            "parked snapshot present"
        );
    }
}
