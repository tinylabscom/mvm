//! Host platform detection: KVM/nested-KVM, libkrun, network backend,
//! residency policy, the TypeScript runner probe, and disk space.

use super::Check;
use mvm_core::platform::Platform;
use mvm_runtime::shell;

pub(super) fn platform_description(plat: Platform) -> String {
    match plat {
        Platform::MacOS => "macOS".to_string(),
        Platform::LinuxNative => "Linux with KVM".to_string(),
        Platform::LinuxNoKvm => "Linux without KVM".to_string(),
        Platform::Wsl2 => {
            if plat.has_kvm() {
                "WSL2 (nested KVM present; experimental/unsupported)".to_string()
            } else {
                "WSL2 (no nested KVM; unsupported)".to_string()
            }
        }
        Platform::Windows => "Windows".to_string(),
    }
}

/// Surface nested-KVM availability on Linux. Required for the
/// dispatch flip from a libkrun builder VM to a nested Firecracker
/// workload. Linux-only: macOS and Windows hosts get a clean "n/a"
/// line so the doctor output isn't noisy on the platforms the
/// question doesn't apply to.
///
/// Two states matter to operators:
///   1. `MVM_LINUX_BUILDER_VM` is unset → informational only (this
///      is the default today; nested-KVM either ready or a future
///      enablement step).
///   2. `MVM_LINUX_BUILDER_VM=1` is set → the operator has opted in;
///      nested-KVM missing is now a hard "fix this before the nested
///      dispatch ships" error.
pub(super) fn nested_kvm_check(plat: Platform) -> Check {
    if !matches!(plat, Platform::LinuxNative) {
        return Check {
            name: "nested-kvm",
            category: "platform",
            ok: true,
            info: "n/a (Linux-only — macOS hosts use libkrun/HVF; Plan 100 W6 affects Linux only)"
                .to_string(),
        };
    }
    let has_nested = plat.has_nested_kvm();
    let env_requested = linux_builder_vm_requested_for_doctor();
    match (has_nested, env_requested) {
        (true, true) => Check {
            name: "nested-kvm",
            category: "platform",
            ok: true,
            info: "available — MVM_LINUX_BUILDER_VM=1 is set; Plan 100 W6 nesting ready".to_string(),
        },
        (true, false) => Check {
            name: "nested-kvm",
            category: "platform",
            ok: true,
            info: "available (informational — set MVM_LINUX_BUILDER_VM=1 to opt into Plan 100 W6 nesting once it lands)"
                .to_string(),
        },
        (false, true) => Check {
            name: "nested-kvm",
            category: "platform",
            ok: false,
            info: "MVM_LINUX_BUILDER_VM=1 but nested KVM not enabled. \
                   Enable on Intel: `modprobe -r kvm_intel && modprobe kvm_intel nested=Y` \
                   (or `options kvm_intel nested=Y` in /etc/modprobe.d/). \
                   AMD: `modprobe -r kvm_amd && modprobe kvm_amd nested=1`. \
                   Confirm via /sys/module/kvm_intel/parameters/nested or \
                   /sys/module/kvm_amd/parameters/nested."
                .to_string(),
        },
        (false, false) => Check {
            name: "nested-kvm",
            category: "platform",
            ok: true, // Not a failure unless the operator opts in.
            info: "not enabled (informational — enable kvm_intel/kvm_amd nested=1 before \
                   setting MVM_LINUX_BUILDER_VM=1 ahead of Plan 100 W6)"
                .to_string(),
        },
    }
}

#[cfg(feature = "builder-vm")]
fn linux_builder_vm_requested_for_doctor() -> bool {
    mvm_build::builder_backend_select::linux_builder_vm_requested()
}

#[cfg(not(feature = "builder-vm"))]
fn linux_builder_vm_requested_for_doctor() -> bool {
    false
}

pub(super) fn kvm_check(plat: Platform, in_vm: bool) -> Check {
    // Inside the Linux execution environment (builder VM) or native Linux:
    // check /dev/kvm locally
    if in_vm
        || plat == Platform::LinuxNative
        || plat == Platform::LinuxNoKvm
        || plat == Platform::Wsl2
    {
        // Use test -c (character device exists) rather than test -r (readable),
        // because KVM access may be via group membership which doesn't imply -r.
        return match shell::run_host("bash", &["-c", "test -c /dev/kvm && echo ok"]) {
            Ok(out) if out.status.success() => {
                let context = if in_vm {
                    "available (inside the Linux execution environment)"
                } else {
                    "available"
                };
                Check {
                    name: "kvm",
                    category: "platform",
                    ok: true,
                    info: context.to_string(),
                }
            }
            _ => Check {
                name: "kvm",
                category: "platform",
                ok: false,
                info: if in_vm {
                    "/dev/kvm not accessible inside the Linux execution environment".to_string()
                } else {
                    "not available. Enable virtualization in BIOS or check permissions on /dev/kvm."
                        .to_string()
                },
            },
        };
    }

    // macOS host: /dev/kvm doesn't exist anywhere in the stack — the
    // backend is libkrun or HVF driven by Hypervisor.framework. Lima is
    // gone; reporting KVM as missing on macOS would be a stale artifact
    // from that era.
    Check {
        name: "kvm",
        category: "platform",
        ok: true,
        info: "n/a on macOS (Hypervisor.framework via libkrun / HVF)".to_string(),
    }
}

/// Surface the active transport contract for the non-KVM backends.
///
/// The current workload and builder directions are direct-vsock only:
/// no guest-NIC helper binary is required on the host for the active
/// libkrun/HVF lanes, and stale gateway expectations should not fail
/// `mvmctl doctor`.
#[cfg(target_family = "unix")]
pub(super) fn network_backend_check(plat: Platform) -> Check {
    if plat.is_windows() {
        return Check {
            name: "network-backend",
            category: "platform",
            ok: true,
            info: "n/a (no native Windows port)".to_string(),
        };
    }
    Check {
        name: "network-backend",
        category: "platform",
        ok: true,
        info: "direct vsock only; no host gateway binary is part of the active runtime contract"
            .to_string(),
    }
}

/// The upstream proxy the per-VM egress endpoint will inherit for its forward
/// leg, so the override path is observable before a workload is launched.
///
/// Never fails. A host with no proxy configured is the normal case, and a
/// malformed value is reported as not-ok here rather than surfacing later as an
/// unexplained total egress failure — which is exactly what it would look like
/// on a host whose only route out is the proxy.
pub(super) fn egress_proxy_check() -> Check {
    match mvm_http::ProxyConfig::from_env() {
        Ok(None) => Check {
            name: "egress proxy",
            category: "platform",
            ok: true,
            info: "none configured — the forward leg dials destinations directly".to_string(),
        },
        Ok(Some(cfg)) => Check {
            name: "egress proxy",
            category: "platform",
            ok: true,
            info: format!("{} (from environment)", cfg.summary()),
        },
        Err(e) => Check {
            name: "egress proxy",
            category: "platform",
            ok: false,
            info: format!("proxy environment is unusable: {e}"),
        },
    }
}

/// Windows stub — keeps the call site cfg-free.
#[cfg(not(target_family = "unix"))]
pub(super) fn network_backend_check(_plat: Platform) -> Check {
    Check {
        name: "network-backend",
        category: "platform",
        ok: true,
        info: "n/a (no Unix libkrun port on this OS)".to_string(),
    }
}

/// libkrun availability. Probes the host for the
/// libkrun shared library at the standard install paths. `ok: true`
/// regardless of presence (libkrun is optional); the `info` field
/// surfaces the install hint when missing so users see exactly what
/// to run.
pub(super) fn libkrun_check(plat: Platform) -> Check {
    if plat.is_windows() {
        return Check {
            name: "libkrun",
            category: "platform",
            ok: true,
            info: "n/a (no native Windows port; WSL2 is future/experimental)".to_string(),
        };
    }
    if plat.has_libkrun() {
        Check {
            name: "libkrun",
            category: "platform",
            ok: true,
            info: "available".to_string(),
        }
    } else {
        Check {
            name: "libkrun",
            category: "platform",
            ok: true, // Optional; not a failure.
            info: format!("not available ({})", libkrun_sys::install_hint()),
        }
    }
}

/// Report the resolved residency policy, its source, the warm target, and the
/// idle timeout. The check is informational and never fails — every override is
/// observable via the `MVM_RESIDENCY` env var at the time doctor runs.
pub(super) fn residency_check() -> Check {
    use mvm_core::residency::{MVM_RESIDENCY_ENV, ResidencySource, resolve_residency};

    let (policy, source) = resolve_residency();
    let source_str = match source {
        ResidencySource::EnvOverride => format!("override via ${MVM_RESIDENCY_ENV}"),
        ResidencySource::AutoDetect => "auto-detected".to_string(),
    };
    let idle = match policy.idle_timeout() {
        Some(d) => format!(", idle={}m", d.as_secs() / 60),
        None => String::new(),
    };
    Check {
        name: "residency",
        category: "platform",
        ok: true,
        info: format!(
            "{} — {} — warm_target={}{}",
            policy.label(),
            source_str,
            policy.warm_target(),
            idle
        ),
    }
}

/// TypeScript runner probe — `mvmctl build compile <script.ts>` auto-runs
/// the script on the host with `MVM_SDK_MODE=record` and lowers the
/// emitted recording into a Workload. That path needs a TS-aware
/// runner (`tsx`, `bun`, or `deno`); plain `node` can't execute `.ts`
/// in mvm's supported Node range.
///
/// **WARN (not FAIL) when missing.** A TS runner is only required if
/// the user actually runs `mvmctl build compile` on a `.ts` script — most
/// mvm workflows (Python, IR-JSON, decorator-only TS) don't need one.
/// Doctor surfaces the install hint so the gap is discoverable, but
/// `mvmctl doctor` still exits 0 to avoid breaking CI on hosts that
/// genuinely don't want a Node toolchain.
///
/// Probe is cheap: at most three `which::which` lookups plus one
/// cwd-relative `is_file` per runner — no subprocesses.
pub(super) fn ts_runner_check() -> Check {
    // Project-local resolution wins over PATH — see
    // `crate::ts_runner` module docs for the full order.
    if let Some(p) = crate::ts_runner::project_local() {
        return Check {
            name: "TypeScript runner",
            category: "tools",
            ok: true,
            info: format!(
                "project-local at {} (used by `mvmctl build compile <script.ts>`)",
                p.display()
            ),
        };
    }
    if let Some(p) = crate::ts_runner::on_path() {
        return Check {
            name: "TypeScript runner",
            category: "tools",
            ok: true,
            info: format!(
                "{} on PATH ({})",
                p.file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("<unknown>"),
                p.display()
            ),
        };
    }
    Check {
        name: "TypeScript runner",
        category: "tools",
        // `ok: true` is the WARN posture — doctor reports the gap in
        // the `info` field but does not exit nonzero. The install
        // hint is verbose on purpose; this is the one place users
        // discover the project-local + global recipes.
        ok: true,
        info: format!(
            "not found — {} (only required if you run `mvmctl build compile <script.ts>`)",
            crate::ts_runner::install_hint()
        ),
    }
}

pub(super) fn disk_space_check(in_vm: bool) -> Check {
    let result = if in_vm {
        parse_disk_space("df -BG ~/.mvm 2>/dev/null || df -BG / 2>/dev/null")
    } else if cfg!(target_os = "macos") {
        parse_disk_space("df -g ~ 2>/dev/null")
    } else {
        parse_disk_space("df -BG ~/.mvm 2>/dev/null || df -BG / 2>/dev/null")
    };

    match result {
        Some(gib) if gib >= 10 => Check {
            name: "disk space",
            category: "platform",
            ok: true,
            info: format!("{} GiB free", gib),
        },
        Some(gib) => Check {
            name: "disk space",
            category: "platform",
            ok: false,
            info: format!("only {} GiB free (10 GiB recommended)", gib),
        },
        None => Check {
            name: "disk space",
            category: "platform",
            ok: true,
            info: "unable to determine (skipped)".to_string(),
        },
    }
}

/// Parse free disk space in GiB from `df` output.
/// Expects the 4th column of the 2nd line to be the available space with a G suffix.
fn parse_disk_space(cmd: &str) -> Option<u64> {
    let output = shell::run_host("bash", &["-c", cmd]).ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout.lines().nth(1)?;
    let avail = line.split_whitespace().nth(3)?;
    let num_str = avail.trim_end_matches('G').trim_end_matches('i');
    num_str.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::util::test_env::TestEnv;

    #[test]
    fn platform_description_covers_all_variants() {
        assert!(platform_description(Platform::MacOS).contains("macOS"));
        assert!(platform_description(Platform::LinuxNative).contains("KVM"));
        assert!(platform_description(Platform::LinuxNoKvm).contains("without KVM"));
    }

    #[test]
    fn kvm_check_on_macos_is_informational() {
        let c = kvm_check(Platform::MacOS, false);
        assert!(c.ok, "macOS kvm check must not fail: {}", c.info);
        assert!(
            c.info.contains("Hypervisor.framework"),
            "expected Hypervisor.framework rationale, got: {}",
            c.info
        );
    }

    // ── nested-kvm check + MVM_LINUX_BUILDER_VM line ──

    #[test]
    fn nested_kvm_check_macos_reports_na() {
        let c = nested_kvm_check(Platform::MacOS);
        assert!(c.ok, "macOS host must not fail on Linux-only probe");
        assert_eq!(c.name, "nested-kvm");
        assert_eq!(c.category, "platform");
        assert!(c.info.contains("n/a"), "got: {}", c.info);
        assert!(c.info.contains("Linux-only"), "got: {}", c.info);
    }

    #[test]
    fn nested_kvm_check_windows_reports_na() {
        let c = nested_kvm_check(Platform::Windows);
        assert!(c.ok);
        assert!(c.info.contains("n/a"));
    }

    #[test]
    fn nested_kvm_check_wsl2_reports_na() {
        let c = nested_kvm_check(Platform::Wsl2);
        assert!(c.ok);
        assert!(c.info.contains("n/a"));
    }

    #[cfg(all(target_os = "linux", feature = "builder-vm"))]
    #[test]
    fn nested_kvm_check_linux_native_reports_actionable_text() {
        // Without spoofing the sysfs probe we can't pin the (ok/!ok)
        // outcome — different CI runners report different nested-KVM
        // states. What we CAN pin: the line is "nested-kvm", category
        // "platform", and the info text covers one of the four
        // documented branches (env-set + ready, env-set + missing,
        // env-unset + ready, env-unset + missing).
        let mut env = TestEnv::new();
        env.remove("MVM_LINUX_BUILDER_VM");
        let c = nested_kvm_check(Platform::LinuxNative);
        assert_eq!(c.name, "nested-kvm");
        assert_eq!(c.category, "platform");
        let info = &c.info;
        // Env-unset branch — one of two truthy paths.
        assert!(
            info.contains("informational")
                || info.contains("not enabled (informational")
                || info.contains("available (informational"),
            "expected informational env-unset text; got: {info}"
        );
    }

    #[test]
    fn residency_check_reports_policy_and_source() {
        let c = residency_check();
        assert_eq!(c.category, "platform");
        assert!(c.ok);
        // label — source — warm_target=N
        assert!(c.info.contains("warm_target="), "info was {:?}", c.info);
        assert!(
            c.info.contains("auto-detected") || c.info.contains("override"),
            "info was {:?}",
            c.info
        );
    }

    #[test]
    fn ts_runner_check_reports_warn_posture_with_install_hint_when_missing() {
        // Force a clean lookup: no MVM_TSX pin, no project-local
        // ./node_modules/.bin, and (most critically) an empty PATH
        // so the host's own `tsx`/`bun`/`deno` can't make this test
        // flaky. The probe must still return `ok: true` (WARN, not
        // FAIL) so `mvmctl doctor` exits 0 on a host without a TS
        // runner.
        let mut env = TestEnv::new();
        let prev_cwd = std::env::current_dir().expect("cwd");
        let tmp = tempfile::tempdir().unwrap();
        env.set("PATH", "");
        env.remove("MVM_TSX");
        std::env::set_current_dir(tmp.path()).expect("chdir");

        let c = ts_runner_check();

        // Restore cwd before any assert can fail (TestEnv restores PATH /
        // MVM_TSX on drop; cwd is restored manually).
        let _ = std::env::set_current_dir(&prev_cwd);
        drop(env);

        assert_eq!(c.name, "TypeScript runner");
        assert_eq!(c.category, "tools");
        assert!(
            c.ok,
            "TS-runner probe is WARN-only (informational), not FAIL: info={}",
            c.info
        );
        assert!(
            c.info.contains("not found"),
            "expected 'not found' marker, got: {}",
            c.info
        );
        // Install hint must be inlined so `mvmctl doctor` users
        // don't need to re-discover the per-OS recipe elsewhere.
        for s in ["tsx", "bun", "deno", "MVM_TSX"] {
            assert!(c.info.contains(s), "info missing {s:?}: {}", c.info);
        }
    }

    #[cfg(unix)]
    #[test]
    fn ts_runner_check_reports_pass_when_project_local_present() {
        use std::os::unix::fs::PermissionsExt;
        let mut env = TestEnv::new();
        let prev_cwd = std::env::current_dir().expect("cwd");
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("node_modules").join(".bin");
        std::fs::create_dir_all(&bin).unwrap();
        let tsx = bin.join("tsx");
        std::fs::write(&tsx, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&tsx, std::fs::Permissions::from_mode(0o755)).unwrap();
        env.remove("MVM_TSX");
        std::env::set_current_dir(tmp.path()).expect("chdir");

        let c = ts_runner_check();

        let _ = std::env::set_current_dir(&prev_cwd);
        drop(env);

        assert!(c.ok);
        assert!(
            c.info.contains("project-local"),
            "expected 'project-local' marker, got: {}",
            c.info
        );
    }

    #[test]
    fn parse_disk_space_typical_output() {
        let result = parse_disk_space(
            "printf 'Filesystem     1G-blocks  Used Available Use%% Mounted on\n/dev/sda1           100G   55G       45G  55%% /\n'",
        );
        assert_eq!(result, Some(45));
    }
}
