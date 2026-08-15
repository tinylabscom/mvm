//! `xtask check-uniform-vsock-egress`
//!
//! Uniform vsock egress: the Firecracker, libkrun, and HVF CLI workload backends
//! are converged onto **one** launch seam — `WorkloadRunner<Driver,
//! RealNetworkEndpointSpawner, RealBrokerRegistrar>`. The per-VM substitution endpoint
//! (the sole claim-10 egress gate) is spawned in exactly one place,
//! `RealNetworkEndpointSpawner::spawn` (`workload_runner/runner.rs`), over vsock/uds; a
//! `VmmDriver` only wires the guest port through and spawns nothing itself. This
//! gate is that claim in executable form: it fails closed if a future edit
//! reverts a converged variant to a raw backend, swaps the endpoint spawner off
//! the seam, or wires an egress endpoint inside a driver.
//!
//! Three assertions:
//!
//! - **A — the converged CLI workload variants ARE runners.** `backend.rs` keeps
//!   the `FcRunner`/`LibkrunRunner`/`HvfRunner` aliases at the full
//!   `WorkloadRunner<Driver, RealNetworkEndpointSpawner, RealBrokerRegistrar>` shape
//!   (matching the `RealNetworkEndpointSpawner, RealBrokerRegistrar` tail, so a spawner
//!   swap trips the gate), and `pub enum AnyBackend` binds the runner arms
//!   `Firecracker(FcRunner)` + `Libkrun(LibkrunRunner)` + `Hvf(HvfRunner)` —
//!   never a raw `Firecracker(FirecrackerBackend)` / `Libkrun(LibkrunBackend)` /
//!   `Hvf(HvfBackend)`.
//! - **B — no egress-endpoint wiring on the guarded surface.** The
//!   `driver/*.rs` files and `apple_container_backend.rs` carry none of the raw
//!   egress-spawn tokens; the one legal spawn site
//!   (`workload_runner/runner.rs`) is out of the guarded set.
//! - **C — `AppleContainerBackend` still delegates to an `HvfRunner`.** It holds
//!   a `runner: HvfRunner` field, and each of its launch paths — `start`,
//!   `start_with_mode`, `warm_start` — calls the matching `self.runner.*`,
//!   so its egress reaches the endpoint spawner through the runner Assertion A
//!   already locks. Those three are the methods that bring a guest up; the rest
//!   of the surface acts on an already-launched VM or reports metadata, so it
//!   opens no egress seam.
//!
//! Scope — the covered set is what `AnyBackend::as_workload_backend` admits:
//!
//! - Firecracker, libkrun and HVF are covered **directly** (A + B).
//! - `AppleContainer` is covered **transitively**, and C is why that is a
//!   checked fact rather than an implicit one: the backend is the HVF workload
//!   runner with only the kernel image substituted, so it spawns no endpoint of
//!   its own and inherits the runner's single egress seam. Without C, replacing
//!   the runner field or bypassing it in `start` would grow a second seam on a
//!   workload-bearing tier while this gate stayed green.
//! - `Mock` is admitted only when the test-support feature is on; it is an
//!   in-memory double, not a host VMM.
//!
//! `Wasm`, `Qemu` and `Docker` are **barred** from the admitted funnel —
//! `as_workload_backend` returns `None` for each — so no admitted workload
//! dispatches through them and there is no egress seam here to lock. That is a
//! different thing from being an unconverged workload backend: they are not on
//! the funnel at all.

use anyhow::{Result, bail};
use regex::Regex;
use std::path::{Path, PathBuf};

/// The converged dispatch surface — the aliases and enum arms Assertion A reads.
const BACKEND_RS: &str = "crates/mvm-runtime/src/backend.rs";

/// The Apple Container backend — the transitively covered workload tier
/// Assertion C reads, and part of Assertion B's guarded set.
const APPLE_CONTAINER_RS: &str = "crates/mvm-runtime/src/apple_container_backend.rs";

/// A converged runner alias and the driver it must wrap. The alias must stay at
/// the `WorkloadRunner<Driver, RealNetworkEndpointSpawner, RealBrokerRegistrar>` shape;
/// swapping the spawner or broker registrar off the tail trips Assertion A.
struct RunnerAlias {
    alias: &'static str,
    driver: &'static str,
}

const REQUIRED_ALIASES: &[RunnerAlias] = &[
    RunnerAlias {
        alias: "FcRunner",
        driver: "FcDriver",
    },
    RunnerAlias {
        alias: "LibkrunRunner",
        driver: "LibkrunDriver",
    },
    RunnerAlias {
        alias: "HvfRunner",
        driver: "HvfDriver",
    },
];

/// Enum arms `pub enum AnyBackend` MUST bind — the converged runner variants.
const REQUIRED_ENUM_ARMS: &[&str] = &[
    "Firecracker(FcRunner)",
    "Libkrun(LibkrunRunner)",
    "Hvf(HvfRunner)",
];

/// Enum arms a regression would introduce — a converged variant reverted to its
/// raw backend. Their presence as a variant construction fails the gate.
const FORBIDDEN_ENUM_ARMS: &[&str] = &[
    "Firecracker(FirecrackerBackend)",
    "Libkrun(LibkrunBackend)",
    "Hvf(HvfBackend)",
];

/// The surface Assertion B guards: a `VmmDriver` only wires the guest port
/// through, so no per-VM egress endpoint may be spawned here — and neither may
/// `apple_container_backend.rs`, which is covered transitively precisely
/// because it spawns nothing of its own.
///
/// Deliberately NOT guarded (they legitimately construct or hold endpoints and
/// sit outside the converged CLI scope): `workload_runner/runner.rs` (the one
/// `RealNetworkEndpointSpawner`), the builder role, the raw `libkrun.rs` +
/// `microvm/egress_bridge.rs` + `egress_redirect.rs` (held live by the hostd
/// supervisor + Firecracker standby fleet path), the endpoint definition
/// (`network_endpoint_spawn.rs`) + the `mvm-hostd` supervisor + the substitution
/// endpoint binary, and `bench/probe.rs`.
const GUARDED_PATHS: &[&str] = &["crates/mvm-runtime/src/driver", APPLE_CONTAINER_RS];

/// Raw egress-spawn tokens. Any of these on the guarded driver surface means a
/// per-VM endpoint is being spawned outside `RealNetworkEndpointSpawner`.
const FORBIDDEN: &[&str] = &[
    "spawn_network_endpoint",
    "EndpointTransport::Uds",
    "EndpointTransport::Vsock",
    "spawn_libkrun_egress_endpoint_if_needed",
    "spawn_egress_endpoint",
    "install_egress_redirect",
];

pub fn run(workspace: &Path) -> Result<()> {
    check_converged_runner_shape(workspace)?;
    check_apple_container_delegates_to_runner(workspace)?;
    let scanned = check_no_driver_egress_spawn(workspace)?;
    eprintln!(
        "check-uniform-vsock-egress: clean (Firecracker + libkrun + HVF bind WorkloadRunner \
         runners; apple-container delegates to an HvfRunner; {scanned} guarded file(s) spawn \
         no egress endpoint — Wasm, Qemu and Docker are barred from the admitted funnel)"
    );
    Ok(())
}

/// Assertion A — the converged CLI workload variants are runners, not raw backends.
fn check_converged_runner_shape(workspace: &Path) -> Result<()> {
    let path = workspace.join(BACKEND_RS);
    let Ok(text) = std::fs::read_to_string(&path) else {
        bail!(
            "check-uniform-vsock-egress: cannot read {BACKEND_RS} — the converged \
             backend dispatch must exist"
        );
    };

    for alias in REQUIRED_ALIASES {
        if !alias_regex(alias).is_match(&text) {
            bail!(
                "check-uniform-vsock-egress: {alias} lost its converged runner shape. \
                 Expected `type {alias} = WorkloadRunner<{driver}, RealNetworkEndpointSpawner, \
                 RealBrokerRegistrar>`. Swapping the endpoint spawner or broker registrar \
                 off this seam breaks the uniform vsock-egress convergence — including \
                 for apple-container, which reaches the endpoint through `HvfRunner`.",
                alias = alias.alias,
                driver = alias.driver
            );
        }
    }

    // Forbidden arms first: a straight revert both drops the runner arm and
    // introduces the raw one, and this branch gives the more specific diagnosis.
    let code = code_lines(&text);
    for (n, line) in &code {
        for arm in FORBIDDEN_ENUM_ARMS {
            if line.contains(arm) {
                bail!(
                    "check-uniform-vsock-egress: {BACKEND_RS}:{n}: `{arm}` reverts a \
                     converged CLI workload variant to a raw backend. Firecracker + \
                     libkrun + HVF must stay `WorkloadRunner` arms.\n    {}",
                    line.trim()
                );
            }
        }
    }
    for arm in REQUIRED_ENUM_ARMS {
        if !code.iter().any(|(_, line)| line.contains(arm)) {
            bail!(
                "check-uniform-vsock-egress: `pub enum AnyBackend` no longer binds the \
                 `{arm}` runner arm. Firecracker + libkrun + HVF must dispatch through \
                 `WorkloadRunner`, not a raw backend."
            );
        }
    }
    Ok(())
}

/// A launch path on the Apple Container backend: a method that brings a guest
/// up, and so must reach the runner that owns the egress seam. `signature` is
/// matched against the method's signature line; `delegation` must appear in the
/// body that follows.
struct LaunchPath {
    signature: &'static str,
    delegation: &'static str,
}

/// Every `AppleContainerBackend` method that starts or restores a guest. These
/// are the ones whose delegation carries egress; the rest of the `VmBackend`
/// surface (`wait`/`pause`/`resume`/`stop`/`stop_all`/`status`/`list`/`logs`/
/// `install`/`name`/`kind`/`capabilities`/`security_profile`) acts on an
/// already-launched VM or reports metadata, so it opens no egress seam and is
/// deliberately not pinned here.
const APPLE_CONTAINER_LAUNCH_PATHS: &[LaunchPath] = &[
    LaunchPath {
        signature: "fn start(&self, config: &VmStartConfig)",
        delegation: "self.runner.start(",
    },
    LaunchPath {
        signature: "fn start_with_mode(",
        delegation: "self.runner.start_with_mode(",
    },
    // A warm start restores a guest that then runs a workload, so it reaches
    // the same endpoint the cold path does.
    LaunchPath {
        signature: "fn warm_start(",
        delegation: "self.runner.warm_start(",
    },
];

/// Assertion C — `AppleContainerBackend` still reaches egress through an
/// `HvfRunner`. Its coverage is transitive, so both halves must hold: it holds
/// the runner, and every launch path goes through it rather than around it.
fn check_apple_container_delegates_to_runner(workspace: &Path) -> Result<()> {
    let path = workspace.join(APPLE_CONTAINER_RS);
    let Ok(text) = std::fs::read_to_string(&path) else {
        bail!(
            "check-uniform-vsock-egress: cannot read {APPLE_CONTAINER_RS} — the \
             apple-container workload backend must exist"
        );
    };
    let code = code_lines(&text);

    let field = Regex::new(r"\brunner\s*:\s*HvfRunner\b").expect("static field regex");
    if !code.iter().any(|(_, line)| field.is_match(line)) {
        bail!(
            "check-uniform-vsock-egress: {APPLE_CONTAINER_RS}: `AppleContainerBackend` no \
             longer holds a `runner: HvfRunner`. Its claim-10 coverage is transitive — it \
             reaches the one `RealNetworkEndpointSpawner` through the HVF runner. Holding anything \
             else means this workload tier needs its own egress seam, which is the \
             convergence this gate exists to prevent."
        );
    }

    for path in APPLE_CONTAINER_LAUNCH_PATHS {
        let Some(body) = fn_body(&code, path.signature) else {
            bail!(
                "check-uniform-vsock-egress: {APPLE_CONTAINER_RS}: cannot find `{sig}` — \
                 this launch path must exist for its delegation to be checkable. Removing a \
                 launch path instead of pinning it is not a way past this gate.",
                sig = path.signature
            );
        };
        if !squeeze(&body.concat()).contains(&squeeze(path.delegation)) {
            bail!(
                "check-uniform-vsock-egress: {APPLE_CONTAINER_RS}: the launch path `{sig}` no \
                 longer delegates to `{delegation}...)`. A launch that bypasses the HVF runner \
                 bypasses the per-VM substitution endpoint that owns claim-10 for this tier.",
                sig = path.signature,
                delegation = path.delegation
            );
        }
    }
    Ok(())
}

/// Drop all whitespace, so a delegation rustfmt wrapped across lines
/// (`self.runner\n    .start_with_mode(...)`) still matches the token being
/// looked for. Without this the gate reads as green on a wrapped call it never
/// actually found.
fn squeeze(text: &str) -> String {
    text.chars().filter(|c| !c.is_whitespace()).collect()
}

/// The code lines of the function whose signature line contains `signature`, up
/// to the next `fn ` at the same-or-shallower nesting. Returns `None` when the
/// signature is absent.
fn fn_body<'a>(code: &[(usize, &'a str)], signature: &str) -> Option<Vec<&'a str>> {
    let start = code.iter().position(|(_, line)| line.contains(signature))?;
    let mut body = Vec::new();
    for (_, line) in &code[start + 1..] {
        if line.contains("fn ") {
            break;
        }
        body.push(*line);
    }
    Some(body)
}

/// Assertion B — the guarded surface spawns no egress endpoint. Returns
/// the number of guarded files scanned.
fn check_no_driver_egress_spawn(workspace: &Path) -> Result<usize> {
    let re = forbidden_regex();
    let rs_files = guarded_rs_files(workspace)?;
    let hits = scan_files_forbidden(workspace, &rs_files, &re);
    if !hits.is_empty() {
        bail!(
            "check-uniform-vsock-egress: a per-VM egress endpoint is spawned on the \
             guarded surface. The only legal spawn site is \
             `RealNetworkEndpointSpawner::spawn` in workload_runner/runner.rs; a driver wires \
             the guest port through and spawns nothing, and the apple-container backend \
             delegates rather than spawning:\n{}",
            hits.join("\n")
        );
    }
    Ok(rs_files.len())
}

fn alias_regex(alias: &RunnerAlias) -> Regex {
    let pattern = format!(
        r"type\s+{}\s*=\s*WorkloadRunner\s*<\s*{}\s*,\s*RealNetworkEndpointSpawner\s*,\s*RealBrokerRegistrar\s*>",
        alias.alias, alias.driver
    );
    Regex::new(&pattern).expect("static alias regex")
}

fn forbidden_regex() -> Regex {
    Regex::new(&FORBIDDEN.join("|")).expect("static regex")
}

/// Non-comment code lines as (1-based line number, line). Prose in `//`/`*`
/// comment lines may name a raw backend to explain the invariant, so it is
/// skipped — the assertion is about code.
fn code_lines(text: &str) -> Vec<(usize, &str)> {
    text.lines()
        .enumerate()
        .filter(|(_, line)| {
            let trimmed = line.trim_start();
            !(trimmed.starts_with("//") || trimmed.starts_with('*'))
        })
        .map(|(i, line)| (i + 1, line))
        .collect()
}

fn guarded_rs_files(workspace: &Path) -> Result<Vec<PathBuf>> {
    let mut rs_files = Vec::new();
    for guarded in GUARDED_PATHS {
        collect_rs_files(&workspace.join(guarded), &mut rs_files)?;
    }
    Ok(rs_files)
}

fn collect_rs_files(path: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    if path.is_file() {
        if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path.to_path_buf());
        }
        return Ok(());
    }
    if !path.is_dir() {
        return Ok(());
    }
    for entry in std::fs::read_dir(path)?.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, out)?;
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    Ok(())
}

fn scan_files_forbidden(workspace: &Path, files: &[PathBuf], re: &Regex) -> Vec<String> {
    let mut hits = Vec::new();
    for file in files {
        let text = std::fs::read_to_string(file).unwrap_or_default();
        for (n, line) in text.lines().enumerate() {
            // Skip comments — a driver may name a raw egress helper in prose to
            // explain why it does not call it.
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with('*') {
                continue;
            }
            if re.is_match(line) {
                hits.push(format!(
                    "{}:{}: {}",
                    file.strip_prefix(workspace).unwrap_or(file).display(),
                    n + 1,
                    line.trim()
                ));
            }
        }
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workspace_root() -> PathBuf {
        // xtask/src/check_uniform_vsock_egress.rs → workspace root is two up.
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask has a parent")
            .to_path_buf()
    }

    #[test]
    fn current_tree_passes() {
        run(&workspace_root()).expect("uniform vsock-egress gate must pass on the current tree");
    }

    #[test]
    fn forbidden_token_in_guarded_driver_is_detected() {
        let root = tempfile::tempdir().expect("tempdir");
        let driver = root.path().join("crates/mvm-runtime/src/driver");
        std::fs::create_dir_all(&driver).expect("create driver dir");
        std::fs::write(
            driver.join("rogue.rs"),
            "fn wire() {\n    spawn_network_endpoint(params);\n}\n",
        )
        .expect("write rogue driver");

        let err = check_no_driver_egress_spawn(root.path())
            .expect_err("a driver spawning an endpoint must fail the gate");
        assert!(
            err.to_string().contains("spawn_network_endpoint"),
            "got {err}"
        );
    }

    #[test]
    fn comment_mentioning_a_forbidden_token_is_ignored() {
        let root = tempfile::tempdir().expect("tempdir");
        let driver = root.path().join("crates/mvm-runtime/src/driver");
        std::fs::create_dir_all(&driver).expect("create driver dir");
        std::fs::write(
            driver.join("clean.rs"),
            "// this driver deliberately never calls spawn_egress_endpoint\nfn wire() {}\n",
        )
        .expect("write clean driver");

        let scanned = check_no_driver_egress_spawn(root.path())
            .expect("a comment-only mention must not trip the gate");
        assert_eq!(scanned, 1);
    }

    #[test]
    fn alias_regex_requires_the_real_endpoint_spawner_tail() {
        let re = alias_regex(&REQUIRED_ALIASES[0]);
        assert!(re.is_match(
            "type FcRunner = WorkloadRunner<FcDriver, RealNetworkEndpointSpawner, RealBrokerRegistrar>;"
        ));
        // A spawner swap must not match — that is the regression the tail guards.
        assert!(!re.is_match(
            "type FcRunner = WorkloadRunner<FcDriver, RawEndpointSpawner, RealBrokerRegistrar>;"
        ));
    }

    #[test]
    fn reverting_an_enum_arm_to_a_raw_backend_fails() {
        let root = tempfile::tempdir().expect("tempdir");
        let backend = root.path().join(BACKEND_RS);
        std::fs::create_dir_all(backend.parent().expect("parent")).expect("create dirs");
        std::fs::write(
            &backend,
            "type FcRunner = WorkloadRunner<FcDriver, RealNetworkEndpointSpawner, RealBrokerRegistrar>;\n\
             type LibkrunRunner = WorkloadRunner<LibkrunDriver, RealNetworkEndpointSpawner, RealBrokerRegistrar>;\n\
             type HvfRunner = WorkloadRunner<HvfDriver, RealNetworkEndpointSpawner, RealBrokerRegistrar>;\n\
             pub enum AnyBackend {\n    Firecracker(FirecrackerBackend),\n    Libkrun(LibkrunRunner),\n}\n",
        )
        .expect("write backend fixture");

        let err = check_converged_runner_shape(root.path())
            .expect_err("a raw Firecracker arm must fail the gate");
        assert!(
            err.to_string().contains("Firecracker(FirecrackerBackend)"),
            "got {err}"
        );
    }

    /// One launch path in a fixture: the signature line, and the single body
    /// line under it.
    struct FixtureMethod {
        signature: &'static str,
        body: String,
    }

    /// A faithful fixture's launch paths — each delegating to the runner, as the
    /// real backend does. Tests mutate or drop one entry to model a regression.
    fn faithful_launch_paths() -> Vec<FixtureMethod> {
        [
            (
                "fn start(&self, config: &VmStartConfig) -> Result<VmId> {",
                "self.runner.start(&self.config_with_kernel(config)?)",
            ),
            // Wrapped across lines exactly as rustfmt writes it in the real
            // file — a per-line match would miss this and read as green.
            (
                "fn start_with_mode(&self, config: &VmStartConfig, mode: StartMode) -> Result<VmId> {",
                "self.runner\n            .start_with_mode(&self.config_with_kernel(config)?, mode)",
            ),
            (
                "fn warm_start(&self, config: &VmStartConfig, req: SnapshotCapability) -> Outcome {",
                "self.runner.warm_start(config, req)",
            ),
        ]
        .into_iter()
        .map(|(signature, body)| FixtureMethod {
            signature,
            body: body.to_string(),
        })
        .collect()
    }

    /// The faithful launch paths with the one whose signature contains
    /// `signature` rewritten to `body`.
    fn with_launch_body(signature: &str, body: &str) -> Vec<FixtureMethod> {
        let mut paths = faithful_launch_paths();
        let entry = paths
            .iter_mut()
            .find(|m| m.signature.contains(signature))
            .expect("fixture must carry the launch path under test");
        entry.body = body.to_string();
        paths
    }

    /// The faithful launch paths with the one whose signature contains
    /// `signature` deleted entirely.
    fn without_launch_path(signature: &str) -> Vec<FixtureMethod> {
        faithful_launch_paths()
            .into_iter()
            .filter(|m| !m.signature.contains(signature))
            .collect()
    }

    /// Write an apple-container fixture with the given struct field and launch
    /// paths, and run Assertion C over it.
    fn apple_container_fixture(
        field: &str,
        paths: &[FixtureMethod],
    ) -> (tempfile::TempDir, Result<()>) {
        let root = tempfile::tempdir().expect("tempdir");
        let path = root.path().join(APPLE_CONTAINER_RS);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("create dirs");
        let mut source = format!("pub struct AppleContainerBackend {{\n    {field}\n}}\n");
        source.push_str("impl VmBackend for AppleContainerBackend {\n");
        for method in paths {
            source.push_str(&format!(
                "    {}\n        {}\n    }}\n\n",
                method.signature, method.body
            ));
        }
        // A lifecycle method that is deliberately NOT a launch path, so the
        // fixture proves the gate pins the launch set rather than everything.
        source.push_str("    fn stop(&self, id: &VmId) -> Result<()> {\n        self.runner.stop(id)\n    }\n}\n");
        std::fs::write(&path, source).expect("write apple-container fixture");
        let outcome = check_apple_container_delegates_to_runner(root.path());
        (root, outcome)
    }

    /// The launch paths under test, with the bypass that models rerouting each
    /// one past the runner and the delegation the gate must name.
    const LAUNCH_PATH_CASES: &[(&str, &str, &str)] = &[
        (
            "fn start(",
            "hvf_runner().start(&self.config_with_kernel(config)?)",
            "self.runner.start(",
        ),
        (
            "fn start_with_mode(",
            "hvf_runner().start_with_mode(&self.config_with_kernel(config)?, mode)",
            "self.runner.start_with_mode(",
        ),
        (
            "fn warm_start(",
            "hvf_runner().warm_start(config, req)",
            "self.runner.warm_start(",
        ),
    ];

    #[test]
    fn apple_container_holding_the_hvf_runner_and_delegating_passes() {
        let (_root, outcome) =
            apple_container_fixture("runner: HvfRunner,", &faithful_launch_paths());
        outcome.expect("the real shape must pass Assertion C");
    }

    #[test]
    fn swapping_the_apple_container_runner_for_a_raw_backend_fails() {
        // The transitive coverage rests on the runner: a raw backend field
        // would need its own egress seam.
        let (_root, outcome) =
            apple_container_fixture("runner: HvfBackend,", &faithful_launch_paths());
        let err = outcome.expect_err("a raw runner field must fail the gate");
        assert!(err.to_string().contains("runner: HvfRunner"), "got {err}");
    }

    #[test]
    fn an_apple_container_launch_path_that_bypasses_the_runner_fails() {
        // Each launch path is pinned independently: rerouting any one of them
        // past the runner opens a second egress seam on this tier. The bypass
        // still reaches an `HvfRunner`, so a check that merely looked for that
        // token would pass — the delegation through the held field is the point.
        for (signature, bypass, named) in LAUNCH_PATH_CASES {
            let (_root, outcome) =
                apple_container_fixture("runner: HvfRunner,", &with_launch_body(signature, bypass));
            let err = outcome
                .expect_err("a launch path bypassing the runner must fail the gate")
                .to_string();
            assert!(err.contains(named), "for {signature}: got {err}");
        }
    }

    #[test]
    fn a_deleted_apple_container_launch_path_fails() {
        // Deleting a launch path must not be a way past the gate: the check
        // fails rather than passing vacuously on a method it cannot find.
        for (signature, _, _) in LAUNCH_PATH_CASES {
            let (_root, outcome) =
                apple_container_fixture("runner: HvfRunner,", &without_launch_path(signature));
            let err = outcome
                .expect_err("an absent launch path must fail rather than pass vacuously")
                .to_string();
            assert!(err.contains("cannot find"), "for {signature}: got {err}");
        }
    }

    #[test]
    fn forbidden_token_in_the_apple_container_backend_is_detected() {
        // Assertion B's guarded set covers this file: an egress-spawn token
        // here is a second seam on a workload-bearing tier.
        let root = tempfile::tempdir().expect("tempdir");
        let path = root.path().join(APPLE_CONTAINER_RS);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("create dirs");
        std::fs::write(
            &path,
            "fn start(&self) {\n    spawn_network_endpoint(params);\n}\n",
        )
        .expect("write rogue apple-container backend");

        let err = check_no_driver_egress_spawn(root.path())
            .expect_err("an egress spawn in the apple-container backend must fail the gate");
        let err = err.to_string();
        assert!(err.contains("spawn_network_endpoint"), "got {err}");
        assert!(err.contains("apple_container_backend.rs"), "got {err}");
    }

    #[test]
    fn reverting_hvf_to_a_raw_backend_fails() {
        // HVF is now a converged runner arm, so a revert to the raw `HvfBackend`
        // must fail the gate exactly like the Firecracker/libkrun reverts. The
        // fixture keeps the aliases and the other two runner arms intact so the
        // failure is unambiguously the HVF revert.
        let root = tempfile::tempdir().expect("tempdir");
        let backend = root.path().join(BACKEND_RS);
        std::fs::create_dir_all(backend.parent().expect("parent")).expect("create dirs");
        std::fs::write(
            &backend,
            "type FcRunner = WorkloadRunner<FcDriver, RealNetworkEndpointSpawner, RealBrokerRegistrar>;\n\
             type LibkrunRunner = WorkloadRunner<LibkrunDriver, RealNetworkEndpointSpawner, RealBrokerRegistrar>;\n\
             type HvfRunner = WorkloadRunner<HvfDriver, RealNetworkEndpointSpawner, RealBrokerRegistrar>;\n\
             pub enum AnyBackend {\n    Firecracker(FcRunner),\n    Libkrun(LibkrunRunner),\n    Hvf(HvfBackend),\n}\n",
        )
        .expect("write backend fixture");

        let err = check_converged_runner_shape(root.path())
            .expect_err("a raw Hvf arm must fail the gate");
        assert!(err.to_string().contains("Hvf(HvfBackend)"), "got {err}");
    }
}
