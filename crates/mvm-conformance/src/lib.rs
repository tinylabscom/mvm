//! Library surface for the dev-only cucumber-rs BDD conformance harness.
//!
//! `cucumber` is a dev-dependency of this crate, and Cargo never exposes a
//! package's dev-dependencies to its own `[lib]` target — only to the test
//! binary that links it — so the `World` type and the cucumber-attributed step
//! definitions live under `tests/` (see `tests/conformance.rs`). Step logic
//! that doesn't need cucumber's macros belongs here instead, so it can be
//! unit-tested independent of the cucumber runner. Not a dependency of any
//! shipped crate.

pub mod claims;
pub mod doc_examples;
pub mod source_commands;

/// Cucumber tag for a scenario whose steps aren't implemented yet; always skipped.
pub const PENDING_TAG: &str = "wip";

/// Cucumber tag for a scenario that boots a real microVM and reaches the
/// network; opt in with `MVM_BDD_LIVE=1` (skipped in the default hermetic lane).
pub const LIVE_TAG: &str = "live";

/// Cucumber tag for the narrow real-microVM lifecycle selected by the merge
/// queue. Selection stays inside [`scenario_gate_for_ci`] so it cannot replace
/// or bypass the live and Firecracker capability checks.
pub const CI_LIVE_TAG: &str = "ci_live";

/// Cucumber tag for a scenario that boots a real Firecracker microVM. Being a
/// real boot it also honors the `@live` opt-in (`MVM_BDD_LIVE`), and it runs
/// only where a usable `/dev/kvm` and a `firecracker` binary are both present —
/// skipped cleanly, never failed, elsewhere, so the suite stays green on hosts
/// without KVM (GitHub-hosted ARM runners, or any dev box lacking one).
pub const FIRECRACKER_TAG: &str = "firecracker";

/// Cucumber tag for a scenario that shells out to Node — the TypeScript
/// example checkers. A host without Node is a real configuration (the KVM
/// witness box is one), and failing there would report a missing toolchain as
/// a documentation defect. Gated rather than skipped inside the step, so the
/// run's own skip tally counts it instead of the scenario passing on no work.
pub const NODE_TAG: &str = "node";

/// Cucumber tag for a scenario that installs a pre-built signed bundle.
/// Sealing a bundle means a full image build, far too slow to run inline, so
/// the operator supplies one with `MVM_BDD_BUNDLE=<path to .mvmpkg>` plus the
/// publisher key it was sealed under in `MVM_BDD_BUNDLE_PUBKEY`; the scenario
/// is skipped cleanly when either is absent. `scripts/make-bundle-fixture.sh`
/// produces both.
pub const BUNDLE_TAG: &str = "bundle";

/// Cucumber tag for a scenario that boots a guest from a prebuilt *workload*
/// kernel rather than building one. The kernel is taken from
/// `MVM_BDD_WORKLOAD_KERNEL`, or from the host's own builder-VM cache when that
/// is unset; the scenario is skipped cleanly when neither yields a file.
///
/// Before this tag existed the step read the variable with `.expect(...)`, so on
/// a host with KVM the scenario *failed* — "MVM_BDD_WORKLOAD_KERNEL must name
/// the live workload kernel" — instead of skipping. The variable is named in no
/// Justfile recipe, no CI lane and no document, so that failure was the only
/// outcome it ever had, and it read as a broken volume path.
pub const WORKLOAD_KERNEL_TAG: &str = "workload_kernel";
/// A scenario that captures a full-VM memory snapshot. Not every backend can:
/// Firecracker reports snapshot tier `unsupported` on hosts without the
/// required support, and the verb then refuses rather than misbehaving.
pub const SNAPSHOT_TAG: &str = "snapshot";
/// A scenario that seeds the guest-runtime cache from a prebuilt directory of
/// `mvm-`prefixed guest binaries, named by `MVM_BDD_GUEST_BIN_DIR`.
pub const GUEST_BINS_TAG: &str = "guest_bins";
/// A scenario whose workload binds an SDK host service, which admission refuses
/// unless the SDK sidecar image is mounted read-only in the guest.
pub const SDK_SIDECAR_TAG: &str = "sdk_sidecar";
/// A scenario asserting a latency *budget*, not just recording a measurement.
/// A budget is a claim about hardware as much as about code: the same build
/// meets it on NVMe and misses it on spinning disk.
pub const PERF_BUDGET_TAG: &str = "perf_budget";
/// A scenario whose guest must tunnel TLS through the egress proxy. The proxy
/// offers CONNECT and SOCKS5; a client that can do neither (BusyBox `wget`
/// ignores `ALL_PROXY` and sends the absolute-URI form the proxy refuses rather
/// than forward in cleartext) cannot satisfy it.
pub const TLS_TUNNEL_CLIENT_TAG: &str = "tls_tunnel_client";
/// A scenario that shares a live host directory into the guest over virtio-fs.
/// libkrun and the in-house HVF VMM both serve one; Firecracker has no virtio-fs
/// device at all and refuses a `DirShare` volume before boot. Declared rather
/// than probed, for the same reason as
/// [`SNAPSHOT_TAG`] — deciding it here would mean re-deriving backend
/// auto-selection, a copy that drifts silently.
///
/// A refusal-shaped scenario needs this tag as much as a success-shaped one:
/// the share is refused with the same exit code the scenario is asserting, so
/// without the gate it passes while witnessing nothing.
pub const DIR_SHARE_TAG: &str = "dir_share";

/// Host capabilities a scenario may require, probed once by the harness.
///
/// Plain data so [`scenario_should_run`] is a pure decision the harness can
/// unit-test without touching the environment.
#[derive(Debug, Clone, Copy)]
pub struct RuntimeCaps {
    /// `MVM_BDD_LIVE` is set — the operator opted into real-microVM scenarios.
    pub live_opted_in: bool,
    /// A usable `/dev/kvm` and a `firecracker` binary on `PATH` are both present,
    /// so a real Firecracker boot can run here.
    pub firecracker_bootable: bool,
    /// `MVM_BDD_BUNDLE` names a readable `.mvmpkg` *and* `MVM_BDD_BUNDLE_PUBKEY`
    /// names the publisher key it was sealed under, so a bundle scenario has
    /// something to install and a trust anchor that admits it.
    pub bundle_fixture: bool,
    /// A `node` binary is resolvable, so the TypeScript example checkers can
    /// run at all.
    pub node_available: bool,
    /// A prebuilt workload kernel is resolvable, so a scenario that boots one
    /// has something to boot.
    pub workload_kernel: bool,
    /// `MVM_BDD_GUEST_BIN_DIR` names a directory of prebuilt guest binaries, so
    /// a scenario that seeds the guest-runtime cache has something to seed from.
    pub guest_bin_dir: bool,
    /// The SDK sidecar image is present in the version-keyed cache, so a
    /// workload binding an SDK host service can be admitted.
    pub sdk_sidecar: bool,
    /// The host is declared fast enough to hold the launch budget, so a
    /// threshold assertion measures the code rather than the disk.
    pub perf_budget_host: bool,
    /// The guest image ships a client that can tunnel TLS through the proxy.
    pub tls_tunnel_client: bool,
    /// The active backend can capture a full-VM memory snapshot, so
    /// `machine checkpoint create --class vm-full` and the pause/resume
    /// round-trip can succeed rather than refusing by capability.
    pub memory_snapshot: bool,
    /// The active backend serves a live host-directory share (virtio-fs), so a
    /// scenario passing `--mount` reaches a guest instead of being refused
    /// before boot.
    pub dir_share: bool,
}

/// Decide whether a scenario with `tags` should run given the host `caps`.
///
/// A required capability that is absent yields a clean skip, never a failure.
/// Pure so it is unit-testable: the harness supplies real probed capabilities,
/// tests supply synthetic ones.
pub fn scenario_should_run(tags: &[String], caps: RuntimeCaps) -> bool {
    matches!(scenario_gate(tags, caps), ScenarioGate::Run)
}

/// Why a scenario runs or does not.
///
/// `scenario_should_run` collapses this to a bool, which is all the cucumber
/// filter needs — but a bool cannot be counted by reason, and a suite that
/// reports nothing about what it declined to attempt reads as full coverage
/// when it is not. The harness tallies these and says so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScenarioGate {
    /// The scenario runs.
    Run,
    /// Tagged `@wip`: unfinished by declaration, not by capability.
    Pending,
    /// Tagged `@live` on a host that did not opt in (`MVM_BDD_LIVE` unset).
    /// This is the one that matters: these are the scenarios that boot a real
    /// microVM, and skipping them is why a change can break every guest boot
    /// with a green suite.
    NeedsLiveOptIn,
    /// Opted into live, but this host cannot boot Firecracker — no `/dev/kvm`
    /// this process can open, or no `firecracker` on `PATH`.
    NeedsFirecracker,
    /// No `.mvmpkg` for a bundle-boot scenario to install.
    NeedsBundleFixture,
    /// No prebuilt workload kernel could be resolved.
    NeedsWorkloadKernel,
    /// The backend cannot capture a full-VM memory snapshot on this host.
    NeedsMemorySnapshot,
    /// The active backend serves no virtio-fs directory share.
    NeedsDirShare,
    /// No prebuilt guest-binary directory was named.
    NeedsGuestBinDir,
    /// The SDK sidecar image is not in the cache.
    NeedsSdkSidecar,
    /// The host is not declared fast enough to assert a latency budget.
    NeedsPerfBudgetHost,
    /// The guest image has no client that can tunnel TLS through the proxy.
    NeedsTlsTunnelClient,
    /// No `node` on `PATH`, so the TypeScript example checkers cannot run.
    NeedsNode,
    /// The merge-queue lane selected only `@ci_live` scenarios, and this
    /// scenario is outside that deliberately narrow subset.
    OutsideCiLiveSubset,
}

impl ScenarioGate {
    /// A stable kebab-case name, so a lane can name the skips it tolerates in
    /// its own configuration and a reviewer can read the policy without
    /// consulting this enum's variant spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Run => "run",
            Self::Pending => "pending",
            Self::NeedsLiveOptIn => "needs-live-opt-in",
            Self::NeedsFirecracker => "needs-firecracker",
            Self::NeedsBundleFixture => "needs-bundle-fixture",
            Self::NeedsWorkloadKernel => "needs-workload-kernel",
            Self::NeedsMemorySnapshot => "needs-memory-snapshot",
            Self::NeedsGuestBinDir => "needs-guest-bin-dir",
            Self::NeedsSdkSidecar => "needs-sdk-sidecar",
            Self::NeedsPerfBudgetHost => "needs-perf-budget-host",
            Self::NeedsTlsTunnelClient => "needs-tls-tunnel-client",
            Self::NeedsNode => "needs-node",
            Self::OutsideCiLiveSubset => "outside-ci-live-subset",
        }
    }
}

/// The reason behind [`scenario_should_run`]. Same order of checks, so the two
/// cannot disagree about whether a scenario runs.
pub fn scenario_gate(tags: &[String], caps: RuntimeCaps) -> ScenarioGate {
    let tagged = |name: &str| tags.iter().any(|t| t == name);
    if tagged(PENDING_TAG) {
        return ScenarioGate::Pending;
    }
    if tagged(LIVE_TAG) && !caps.live_opted_in {
        return ScenarioGate::NeedsLiveOptIn;
    }
    // A firecracker scenario is a real boot, so it also requires the `@live`
    // opt-in and is additionally skipped where KVM or the binary is absent.
    if tagged(FIRECRACKER_TAG) && !caps.live_opted_in {
        return ScenarioGate::NeedsLiveOptIn;
    }
    if tagged(FIRECRACKER_TAG) && !caps.firecracker_bootable {
        return ScenarioGate::NeedsFirecracker;
    }
    if tagged(BUNDLE_TAG) && !caps.bundle_fixture {
        return ScenarioGate::NeedsBundleFixture;
    }
    if tagged(NODE_TAG) && !caps.node_available {
        return ScenarioGate::NeedsNode;
    }
    if tagged(WORKLOAD_KERNEL_TAG) && !caps.workload_kernel {
        return ScenarioGate::NeedsWorkloadKernel;
    }
    if tagged(SNAPSHOT_TAG) && !caps.memory_snapshot {
        return ScenarioGate::NeedsMemorySnapshot;
    }
    if tagged(DIR_SHARE_TAG) && !caps.dir_share {
        return ScenarioGate::NeedsDirShare;
    }
    if tagged(GUEST_BINS_TAG) && !caps.guest_bin_dir {
        return ScenarioGate::NeedsGuestBinDir;
    }
    if tagged(SDK_SIDECAR_TAG) && !caps.sdk_sidecar {
        return ScenarioGate::NeedsSdkSidecar;
    }
    if tagged(PERF_BUDGET_TAG) && !caps.perf_budget_host {
        return ScenarioGate::NeedsPerfBudgetHost;
    }
    if tagged(TLS_TUNNEL_CLIENT_TAG) && !caps.tls_tunnel_client {
        return ScenarioGate::NeedsTlsTunnelClient;
    }
    ScenarioGate::Run
}

/// Apply the merge-queue subset selection without replacing the capability
/// checks. Cucumber's command-line tag filter replaces the programmatic
/// filter; keeping the selection here makes a missing live opt-in or KVM
/// capability continue to fail closed.
pub fn scenario_gate_for_ci(
    tags: &[String],
    caps: RuntimeCaps,
    ci_live_only: bool,
) -> ScenarioGate {
    if ci_live_only && !tags.iter().any(|tag| tag == CI_LIVE_TAG) {
        return ScenarioGate::OutsideCiLiveSubset;
    }
    scenario_gate(tags, caps)
}

impl ScenarioGate {
    /// What to tell the operator, in the summary line.
    pub fn reason(self) -> Option<&'static str> {
        match self {
            Self::Run => None,
            Self::Pending => Some("@wip"),
            Self::NeedsLiveOptIn => Some("need MVM_BDD_LIVE (these boot a real microVM)"),
            Self::NeedsFirecracker => Some("need /dev/kvm + firecracker on PATH"),
            Self::NeedsBundleFixture => Some(
                "need MVM_BDD_BUNDLE to name a readable .mvmpkg and \
                 MVM_BDD_BUNDLE_PUBKEY its publisher key",
            ),
            Self::NeedsNode => Some("need node on PATH (TypeScript example checkers)"),
            Self::NeedsWorkloadKernel => Some(
                "need a prebuilt workload kernel (MVM_BDD_WORKLOAD_KERNEL, or one \
                 in the host builder-VM cache)",
            ),
            Self::NeedsDirShare => Some(
                "need MVM_BDD_DIR_SHARE=1 on a host whose active backend serves \
                 virtio-fs directory shares (libkrun and HVF do; Firecracker has \
                 no virtio-fs device and refuses --mount before boot)",
            ),
            Self::NeedsMemorySnapshot => Some(
                "need MVM_BDD_SNAPSHOT=1 on a host whose active backend reports \
                 snapshot tier `save-restore` (see `mvmctl doctor`)",
            ),
            Self::NeedsGuestBinDir => Some(
                "need MVM_BDD_GUEST_BIN_DIR to name a directory of prebuilt \
                 guest binaries (mvm-guest-agent, mvm-guest-netinit, \
                 mvm-egress-client, mvm-oci-entrypoint)",
            ),
            Self::NeedsSdkSidecar => Some(
                "need the SDK sidecar image in the mvm cache (build it with \
                 `nix build ./nix/images/runtime-overlay#sdk-sidecar-image`)",
            ),
            Self::NeedsPerfBudgetHost => Some(
                "need MVM_BDD_PERF_BUDGET=1 on a host that can hold the launch \
                 budget (a latency threshold on rotational storage measures the \
                 disk, not the code)",
            ),
            Self::NeedsTlsTunnelClient => Some(
                "need MVM_BDD_TLS_CLIENT=1: the guest image must ship a client \
                 that tunnels TLS via CONNECT or SOCKS5 (BusyBox wget ignores \
                 ALL_PROXY and sends the absolute-URI form the proxy refuses)",
            ),
            Self::OutsideCiLiveSubset => Some("outside the merge-queue @ci_live subset"),
        }
    }
}

/// Whether a version-keyed SDK sidecar cache under `sidecar_root` holds a
/// built image.
///
/// Walks version and arch directories rather than hardcoding either, so a
/// version bump cannot quietly turn this into "never available".
///
/// The root is an argument rather than resolved here, because the directory
/// that decides the gate is the one the *scenarios* run against. A probe that
/// resolves its own `MVM_HOME` reports on a home the subject never reads, and
/// where that home happens to hold an image, the gate admits a scenario that
/// then fails in the isolated home where it is absent.
///
/// Note what counts as present: the image file, not the version directory.
/// Those two answers diverge exactly when a cache was created and never
/// populated, which is the state that makes the distinction matter.
pub fn sidecar_image_cached_in(sidecar_root: &std::path::Path, image_file: &str) -> bool {
    let Ok(versions) = std::fs::read_dir(sidecar_root) else {
        return false;
    };
    versions.filter_map(Result::ok).any(|version| {
        std::fs::read_dir(version.path()).is_ok_and(|arches| {
            arches
                .filter_map(Result::ok)
                .any(|arch| arch.path().join(image_file).is_file())
        })
    })
}

#[cfg(test)]
mod sidecar_cache {
    use super::sidecar_image_cached_in;

    const IMAGE: &str = "sdk.ext4";

    #[test]
    fn a_missing_cache_root_is_not_cached() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(!sidecar_image_cached_in(&dir.path().join("absent"), IMAGE));
    }

    #[test]
    fn a_version_directory_without_the_image_is_not_cached() {
        // The shape that made the gate lie: the cache exists and is keyed
        // correctly, but nothing ever wrote the image into it.
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(dir.path().join("0.18.0").join("x86_64")).expect("create arch dir");
        assert!(!sidecar_image_cached_in(dir.path(), IMAGE));
    }

    #[test]
    fn an_image_under_any_version_and_arch_is_cached() {
        let dir = tempfile::tempdir().expect("tempdir");
        let arch = dir.path().join("9.9.9").join("aarch64");
        std::fs::create_dir_all(&arch).expect("create arch dir");
        std::fs::write(arch.join(IMAGE), b"image").expect("write image");
        assert!(sidecar_image_cached_in(dir.path(), IMAGE));
    }
}

/// Which mvm home a live step runs against.
///
/// A home the scenario declared for itself wins over the artifact-warm
/// `MVM_E2E_HOME`. The two phrasings must agree: a scenario that creates a
/// machine through one step and starts it through another is talking about one
/// directory, and while they disagreed it failed with `machine "..." does not
/// exist` — an error naming the machine and never the home it was looked for
/// in, which is why it read as a product defect.
///
/// The warm home still applies to every scenario that declared none, which is
/// what keeps a live run from re-cross-compiling the guest binaries once per
/// scenario.
pub fn live_home_precedence<'a>(
    scenario_home: Option<&'a std::path::Path>,
    warm_home: Option<&'a std::path::Path>,
) -> Option<&'a std::path::Path> {
    scenario_home.or(warm_home)
}

#[cfg(test)]
mod live_home {
    use super::live_home_precedence;
    use std::path::Path;

    #[test]
    fn a_scenario_declared_home_wins_over_the_warm_one() {
        // The case that broke: create ran against the scenario home, start
        // against the warm one, and the machine was "missing".
        assert_eq!(
            live_home_precedence(Some(Path::new("/scenario")), Some(Path::new("/warm"))),
            Some(Path::new("/scenario"))
        );
    }

    #[test]
    fn the_warm_home_is_used_when_the_scenario_declared_none() {
        assert_eq!(
            live_home_precedence(None, Some(Path::new("/warm"))),
            Some(Path::new("/warm"))
        );
    }

    #[test]
    fn neither_home_yields_none_so_the_caller_must_create_one() {
        assert_eq!(live_home_precedence(None, None), None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tags(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| (*s).to_string()).collect()
    }

    const NONE: RuntimeCaps = RuntimeCaps {
        live_opted_in: false,
        firecracker_bootable: false,
        bundle_fixture: false,
        node_available: false,
        guest_bin_dir: false,
        sdk_sidecar: false,
        perf_budget_host: false,
        tls_tunnel_client: false,
        memory_snapshot: false,
        dir_share: false,
        workload_kernel: false,
    };
    const ALL: RuntimeCaps = RuntimeCaps {
        live_opted_in: true,
        firecracker_bootable: true,
        bundle_fixture: true,
        node_available: false,
        guest_bin_dir: true,
        sdk_sidecar: true,
        perf_budget_host: true,
        tls_tunnel_client: true,
        memory_snapshot: true,
        dir_share: true,
        workload_kernel: true,
    };

    #[test]
    fn dir_share_scenario_skips_where_the_backend_serves_no_share() {
        let gate = scenario_gate(
            &tags(&["live", "dir_share"]),
            RuntimeCaps {
                dir_share: false,
                ..ALL
            },
        );
        assert_eq!(gate, ScenarioGate::NeedsDirShare);
        assert!(gate.reason().is_some(), "a skip must name what is missing");
        assert!(scenario_should_run(&tags(&["live", "dir_share"]), ALL));
    }

    #[test]
    fn bundle_scenario_skips_without_a_fixture() {
        // Everything else in place, but no `.mvmpkg` to install.
        assert!(!scenario_should_run(
            &tags(&["live", "firecracker", "bundle"]),
            RuntimeCaps {
                bundle_fixture: false,
                ..ALL
            },
        ));
        assert!(scenario_should_run(
            &tags(&["live", "firecracker", "bundle"]),
            ALL
        ));
    }

    /// The gate this exists for: without a resolvable kernel the scenario must
    /// skip, not fail. It failed before — the step read the env var with
    /// `.expect(...)`, so on a KVM host the only outcome it ever had was a
    /// panic that read as a broken volume path.
    #[test]
    fn workload_kernel_scenario_skips_without_a_kernel() {
        assert!(!scenario_should_run(
            &tags(&["live", "firecracker", "workload_kernel"]),
            RuntimeCaps {
                guest_bin_dir: false,
                sdk_sidecar: false,
                perf_budget_host: false,
                tls_tunnel_client: false,
                memory_snapshot: false,
                dir_share: false,
                workload_kernel: false,
                ..ALL
            },
        ));
        assert!(scenario_should_run(
            &tags(&["live", "firecracker", "workload_kernel"]),
            ALL
        ));
    }

    #[test]
    fn snapshot_scenario_skips_where_the_backend_cannot_snapshot() {
        // Firecracker reports snapshot tier `unsupported`, so the pause/resume
        // and checkpoint verbs refuse by capability rather than misbehaving.
        // Skipping names that; failing would read as a broken verb.
        assert!(!scenario_should_run(
            &tags(&["live", "snapshot"]),
            RuntimeCaps {
                guest_bin_dir: false,
                sdk_sidecar: false,
                perf_budget_host: false,
                tls_tunnel_client: false,
                memory_snapshot: false,
                dir_share: false,
                ..ALL
            },
        ));
        assert!(scenario_should_run(&tags(&["live", "snapshot"]), ALL));
    }

    #[test]
    fn snapshot_gate_reports_its_own_reason() {
        let gate = scenario_gate(
            &tags(&["live", "snapshot"]),
            RuntimeCaps {
                guest_bin_dir: false,
                sdk_sidecar: false,
                perf_budget_host: false,
                tls_tunnel_client: false,
                memory_snapshot: false,
                dir_share: false,
                ..ALL
            },
        );
        assert_eq!(gate, ScenarioGate::NeedsMemorySnapshot);
        assert!(
            gate.reason()
                .is_some_and(|r| r.contains("MVM_BDD_SNAPSHOT")),
            "the skip reason must name the variable that turns it on"
        );
    }

    #[test]
    fn guest_bins_scenario_skips_without_a_prebuilt_directory() {
        // The variable is named in no recipe, lane or document, so these
        // scenarios panicked on it the moment the live opt-in turned them on.
        // A skip names what is missing; a panic reads as a broken verb.
        assert!(!scenario_should_run(
            &tags(&["live", "firecracker", "guest_bins"]),
            RuntimeCaps {
                guest_bin_dir: false,
                ..ALL
            },
        ));
        assert!(scenario_should_run(
            &tags(&["live", "firecracker", "guest_bins"]),
            ALL
        ));
    }

    #[test]
    fn sdk_sidecar_scenario_skips_without_the_cached_image() {
        // Admission refuses a workload binding an SDK host service when the
        // sidecar is absent, so the scenario cannot pass on a host where the
        // image was never built.
        assert!(!scenario_should_run(
            &tags(&["live", "sdk_sidecar"]),
            RuntimeCaps {
                sdk_sidecar: false,
                ..ALL
            },
        ));
        assert!(scenario_should_run(&tags(&["live", "sdk_sidecar"]), ALL));
    }

    #[test]
    fn perf_budget_scenario_skips_on_an_undeclared_host() {
        // A latency threshold on slow storage measures the disk. The
        // measurement scenarios stay ungated; only the budget claim is.
        assert!(!scenario_should_run(
            &tags(&["live", "perf_budget"]),
            RuntimeCaps {
                perf_budget_host: false,
                ..ALL
            },
        ));
        assert!(scenario_should_run(&tags(&["live", "perf_budget"]), ALL));
    }

    #[test]
    fn tls_tunnel_scenario_skips_without_a_capable_guest_client() {
        // The proxy offers CONNECT and SOCKS5 and refuses the absolute-URI
        // form rather than forward it in cleartext. A guest client that can do
        // neither cannot satisfy the scenario, and that is the image's limit,
        // not the proxy's.
        assert!(!scenario_should_run(
            &tags(&["live", "tls_tunnel_client"]),
            RuntimeCaps {
                tls_tunnel_client: false,
                ..ALL
            },
        ));
        assert!(scenario_should_run(
            &tags(&["live", "tls_tunnel_client"]),
            ALL
        ));
    }

    #[test]
    fn untagged_scenario_always_runs() {
        assert!(scenario_should_run(&tags(&[]), NONE));
    }

    #[test]
    fn pending_scenario_never_runs_even_with_all_caps() {
        assert!(!scenario_should_run(&tags(&["wip"]), ALL));
    }

    #[test]
    fn live_scenario_skips_without_opt_in_but_runs_with_it() {
        assert!(!scenario_should_run(&tags(&["live"]), NONE));
        assert!(scenario_should_run(
            &tags(&["live"]),
            RuntimeCaps {
                live_opted_in: true,
                firecracker_bootable: false,
                bundle_fixture: false,
                node_available: false,
                guest_bin_dir: false,
                sdk_sidecar: false,
                perf_budget_host: false,
                tls_tunnel_client: false,
                memory_snapshot: false,
                dir_share: false,
                workload_kernel: false,
            },
        ));
    }

    #[test]
    fn firecracker_scenario_skips_cleanly_without_kvm_and_binary() {
        assert!(!scenario_should_run(
            &tags(&["live", "firecracker"]),
            RuntimeCaps {
                live_opted_in: true,
                firecracker_bootable: false,
                bundle_fixture: false,
                node_available: false,
                guest_bin_dir: false,
                sdk_sidecar: false,
                perf_budget_host: false,
                tls_tunnel_client: false,
                memory_snapshot: false,
                dir_share: false,
                workload_kernel: false,
            },
        ));
        assert!(scenario_should_run(&tags(&["live", "firecracker"]), ALL));
    }

    #[test]
    fn firecracker_scenario_also_requires_live_opt_in() {
        // KVM + firecracker present but no live opt-in → still skipped.
        assert!(!scenario_should_run(
            &tags(&["firecracker"]),
            RuntimeCaps {
                live_opted_in: false,
                firecracker_bootable: true,
                bundle_fixture: false,
                node_available: false,
                guest_bin_dir: false,
                sdk_sidecar: false,
                perf_budget_host: false,
                tls_tunnel_client: false,
                memory_snapshot: false,
                dir_share: false,
                workload_kernel: false,
            },
        ));
        // Live opt-in but missing capability → skipped.
        assert!(!scenario_should_run(
            &tags(&["firecracker"]),
            RuntimeCaps {
                live_opted_in: true,
                firecracker_bootable: false,
                bundle_fixture: false,
                node_available: false,
                guest_bin_dir: false,
                sdk_sidecar: false,
                perf_budget_host: false,
                tls_tunnel_client: false,
                memory_snapshot: false,
                dir_share: false,
                workload_kernel: false,
            },
        ));
        // Both present → runs.
        assert!(scenario_should_run(&tags(&["firecracker"]), ALL));
    }

    /// The gate and the bool must never disagree about whether a scenario runs
    /// — they are read by the same filter, and a divergence would make the
    /// summary describe a different run than the one that happened.
    #[test]
    fn the_gate_and_the_bool_agree_on_every_shape() {
        let caps = [
            RuntimeCaps {
                live_opted_in: false,
                firecracker_bootable: false,
                bundle_fixture: false,
                node_available: false,
                guest_bin_dir: false,
                sdk_sidecar: false,
                perf_budget_host: false,
                tls_tunnel_client: false,
                memory_snapshot: false,
                dir_share: false,
                workload_kernel: false,
            },
            RuntimeCaps {
                live_opted_in: true,
                firecracker_bootable: false,
                bundle_fixture: false,
                node_available: false,
                guest_bin_dir: false,
                sdk_sidecar: false,
                perf_budget_host: false,
                tls_tunnel_client: false,
                memory_snapshot: false,
                dir_share: false,
                workload_kernel: false,
            },
            RuntimeCaps {
                live_opted_in: true,
                firecracker_bootable: true,
                bundle_fixture: false,
                node_available: false,
                guest_bin_dir: false,
                sdk_sidecar: false,
                perf_budget_host: false,
                tls_tunnel_client: false,
                memory_snapshot: false,
                dir_share: false,
                workload_kernel: false,
            },
            RuntimeCaps {
                live_opted_in: true,
                firecracker_bootable: true,
                bundle_fixture: true,
                node_available: false,
                guest_bin_dir: false,
                sdk_sidecar: false,
                perf_budget_host: false,
                tls_tunnel_client: false,
                memory_snapshot: false,
                dir_share: false,
                workload_kernel: true,
            },
            RuntimeCaps {
                live_opted_in: false,
                firecracker_bootable: true,
                bundle_fixture: true,
                node_available: false,
                guest_bin_dir: false,
                sdk_sidecar: false,
                perf_budget_host: false,
                tls_tunnel_client: false,
                memory_snapshot: false,
                dir_share: false,
                workload_kernel: true,
            },
        ];
        let shapes = [
            tags(&[]),
            tags(&[PENDING_TAG]),
            tags(&[LIVE_TAG]),
            tags(&[FIRECRACKER_TAG]),
            tags(&[LIVE_TAG, FIRECRACKER_TAG]),
            tags(&[BUNDLE_TAG]),
            tags(&[LIVE_TAG, FIRECRACKER_TAG, BUNDLE_TAG]),
        ];
        for c in caps {
            for t in &shapes {
                assert_eq!(
                    scenario_should_run(t, c),
                    scenario_gate(t, c) == ScenarioGate::Run,
                    "tags {t:?} caps {c:?}"
                );
            }
        }
    }

    /// Each skip reason is distinguishable, because the whole point is to
    /// count them separately. `@live` without the opt-in is the one that
    /// matters most — those are the scenarios that boot a real microVM.
    #[test]
    fn each_skip_reason_is_reported_distinctly() {
        let none = RuntimeCaps {
            live_opted_in: false,
            firecracker_bootable: false,
            bundle_fixture: false,
            node_available: false,
            guest_bin_dir: false,
            sdk_sidecar: false,
            perf_budget_host: false,
            tls_tunnel_client: false,
            memory_snapshot: false,
            dir_share: false,
            workload_kernel: false,
        };
        let live_only = RuntimeCaps {
            live_opted_in: true,
            firecracker_bootable: false,
            bundle_fixture: false,
            node_available: false,
            guest_bin_dir: false,
            sdk_sidecar: false,
            perf_budget_host: false,
            tls_tunnel_client: false,
            memory_snapshot: false,
            dir_share: false,
            workload_kernel: false,
        };
        let bootable = RuntimeCaps {
            live_opted_in: true,
            firecracker_bootable: true,
            bundle_fixture: false,
            node_available: false,
            guest_bin_dir: false,
            sdk_sidecar: false,
            perf_budget_host: false,
            tls_tunnel_client: false,
            memory_snapshot: false,
            dir_share: false,
            workload_kernel: false,
        };

        assert_eq!(
            scenario_gate(&tags(&[PENDING_TAG]), bootable),
            ScenarioGate::Pending
        );
        assert_eq!(
            scenario_gate(&tags(&[LIVE_TAG]), none),
            ScenarioGate::NeedsLiveOptIn
        );
        // Opted in, but this host cannot boot: a different problem with a
        // different fix, and it must not be reported as "you forgot the flag".
        assert_eq!(
            scenario_gate(&tags(&[FIRECRACKER_TAG]), live_only),
            ScenarioGate::NeedsFirecracker
        );
        assert_eq!(
            scenario_gate(&tags(&[BUNDLE_TAG]), bootable),
            ScenarioGate::NeedsBundleFixture
        );
        assert_eq!(scenario_gate(&tags(&[]), none), ScenarioGate::Run);

        // Every non-Run gate explains itself; Run has nothing to explain.
        assert!(ScenarioGate::Run.reason().is_none());
        for g in [
            ScenarioGate::Pending,
            ScenarioGate::NeedsLiveOptIn,
            ScenarioGate::NeedsFirecracker,
            ScenarioGate::NeedsBundleFixture,
            ScenarioGate::OutsideCiLiveSubset,
        ] {
            assert!(g.reason().is_some(), "{g:?} must say why");
        }
    }

    #[test]
    fn ci_subset_selection_preserves_live_and_firecracker_gates() {
        let selected = tags(&[LIVE_TAG, FIRECRACKER_TAG, CI_LIVE_TAG]);
        assert_eq!(
            scenario_gate_for_ci(&selected, NONE, true),
            ScenarioGate::NeedsLiveOptIn
        );
        assert_eq!(
            scenario_gate_for_ci(
                &selected,
                RuntimeCaps {
                    live_opted_in: true,
                    firecracker_bootable: false,
                    bundle_fixture: false,
                    node_available: false,
                    guest_bin_dir: false,
                    sdk_sidecar: false,
                    perf_budget_host: false,
                    tls_tunnel_client: false,
                    memory_snapshot: false,
                    dir_share: false,
                    workload_kernel: false,
                },
                true,
            ),
            ScenarioGate::NeedsFirecracker
        );
        assert_eq!(
            scenario_gate_for_ci(&selected, ALL, true),
            ScenarioGate::Run
        );
        assert_eq!(
            scenario_gate_for_ci(&tags(&[LIVE_TAG]), ALL, true),
            ScenarioGate::OutsideCiLiveSubset
        );
        assert_eq!(
            scenario_gate_for_ci(&tags(&[]), NONE, false),
            ScenarioGate::Run
        );
    }
}

/// Point a command at an isolated `HOME` without orphaning the Rust toolchain.
///
/// Scenarios replace `HOME` so a run cannot touch the developer's real
/// `~/.mvm`. But `rustup` locates its toolchains through `$HOME/.rustup` unless
/// `RUSTUP_HOME` says otherwise, so replacing `HOME` alone also hides every
/// installed toolchain and target from any command that compiles something.
///
/// On a source checkout that is not a subtle degradation. `mvmctl` cross-compiles
/// the embedded host-vm binaries to musl, and under a bare isolated `HOME` that
/// build either fails with
///
/// ```text
/// error[E0463]: can't find crate for `core`
///   = note: the `x86_64-unknown-linux-musl` target may not be installed
/// ```
///
/// — which reads as a missing target on a host where the target *is* installed —
/// or silently downloads a fresh toolchain into the throwaway directory, once per
/// scenario, for as long as the suite runs.
///
/// So the state isolation is kept and the toolchain locators are passed through.
/// `MVM_HOME` still points at the temporary directory; only rustup's and cargo's
/// own roots survive, and neither is state the suite is trying to isolate.
pub trait IsolatedHome {
    /// Point this command at `home` for state, keeping the toolchain visible.
    fn isolated_home(&mut self, home: impl AsRef<std::path::Path>) -> &mut Self;
}

impl IsolatedHome for std::process::Command {
    fn isolated_home(&mut self, home: impl AsRef<std::path::Path>) -> &mut Self {
        let home = home.as_ref();
        self.env("HOME", home).env("MVM_HOME", home);
        for (var, dir) in [("RUSTUP_HOME", ".rustup"), ("CARGO_HOME", ".cargo")] {
            if let Some(value) = toolchain_root(var, dir) {
                self.env(var, value);
            }
        }
        self
    }
}

/// Resolve a toolchain root: an explicit override wins, otherwise the directory
/// under the *real* home, and only when it actually exists — passing a path that
/// is not there would replace one confusing failure with another.
fn toolchain_root(var: &str, dir: &str) -> Option<std::path::PathBuf> {
    if let Some(explicit) = std::env::var_os(var) {
        let path = std::path::PathBuf::from(explicit);
        return path.is_dir().then_some(path);
    }
    let real_home = std::env::var_os("HOME")?;
    let path = std::path::PathBuf::from(real_home).join(dir);
    path.is_dir().then_some(path)
}

#[cfg(test)]
mod isolate_home_tests {
    use super::*;

    /// The isolation itself must survive the fix: both state vars still point at
    /// the scenario's directory, or the suite starts writing to the real `~/.mvm`.
    #[test]
    fn isolates_both_state_variables() {
        let dir = std::env::temp_dir().join("mvm-isolate-home-test");
        let mut command = std::process::Command::new("true");
        command.isolated_home(&dir);

        let vars: std::collections::BTreeMap<_, _> = command
            .get_envs()
            .filter_map(|(k, v)| Some((k.to_str()?.to_string(), v?.to_str()?.to_string())))
            .collect();

        assert_eq!(vars.get("HOME").map(String::as_str), dir.to_str());
        assert_eq!(vars.get("MVM_HOME").map(String::as_str), dir.to_str());
    }

    /// The point of the change: a toolchain root that exists is handed through,
    /// so a compiling command can still find the installed targets.
    #[test]
    fn passes_an_existing_toolchain_root_through() {
        let real = std::env::temp_dir().join("mvm-isolate-home-rustup");
        std::fs::create_dir_all(&real).expect("create fake RUSTUP_HOME");
        // Safety: single-threaded test process; the var is restored below.
        let previous = std::env::var_os("RUSTUP_HOME");
        unsafe { std::env::set_var("RUSTUP_HOME", &real) };

        let mut command = std::process::Command::new("true");
        command.isolated_home(std::env::temp_dir());
        let passed = command
            .get_envs()
            .any(|(k, v)| k == "RUSTUP_HOME" && v.map(|v| v == real.as_os_str()) == Some(true));

        match previous {
            Some(value) => unsafe { std::env::set_var("RUSTUP_HOME", value) },
            None => unsafe { std::env::remove_var("RUSTUP_HOME") },
        }
        assert!(passed, "an existing RUSTUP_HOME must reach the child");
    }

    /// A root that does not exist is not forwarded: pointing rustup at a missing
    /// directory trades one misleading failure for another.
    #[test]
    fn does_not_forward_a_missing_root() {
        let previous = std::env::var_os("RUSTUP_HOME");
        unsafe { std::env::set_var("RUSTUP_HOME", "/definitely/not/a/real/rustup/root") };

        let mut command = std::process::Command::new("true");
        command.isolated_home(std::env::temp_dir());
        let forwarded = command.get_envs().any(|(k, _)| k == "RUSTUP_HOME");

        match previous {
            Some(value) => unsafe { std::env::set_var("RUSTUP_HOME", value) },
            None => unsafe { std::env::remove_var("RUSTUP_HOME") },
        }
        assert!(!forwarded, "a missing root must not be forwarded");
    }

    /// No step may replace `HOME` by hand.
    ///
    /// `IsolatedHome::isolated_home` exists because replacing `HOME` alone hides
    /// the Rust toolchain from any command that compiles something — on a source
    /// checkout the embedded host-vm binaries then fail to cross-compile with
    /// "the `x86_64-unknown-linux-musl` target may not be installed", on a host
    /// where it is installed. That failure reads as a broken product, and it cost
    /// a ninety-minute live run to find. A raw `.env("HOME", …)` reintroduces it
    /// silently, so the rule is mechanical rather than remembered.
    #[test]
    fn no_step_sets_home_without_the_isolation_helper() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
        let mut offenders = Vec::new();
        let mut scanned = 0usize;

        let mut stack = vec![dir.clone()];
        while let Some(current) = stack.pop() {
            for entry in std::fs::read_dir(&current).into_iter().flatten().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if path.extension().is_some_and(|e| e == "rs") {
                    scanned += 1;
                    let text = std::fs::read_to_string(&path).unwrap_or_default();
                    for (number, line) in text.lines().enumerate() {
                        if line.contains(r#".env("HOME""#) {
                            offenders.push(format!(
                                "  {}:{}",
                                path.file_name().unwrap_or_default().to_string_lossy(),
                                number + 1
                            ));
                        }
                    }
                }
            }
        }

        assert!(
            scanned > 5,
            "scanned only {scanned} step file(s) — the walk went blind, so this \
             test would pass without checking anything"
        );
        assert!(
            offenders.is_empty(),
            "{} site(s) set HOME directly; use `command.isolated_home(path)` so the \
             Rust toolchain stays visible to the child:\n{}",
            offenders.len(),
            offenders.join("\n")
        );
    }
}
