//! `xtask check-uniform-vsock-egress`
//!
//! Uniform vsock egress: the Firecracker and libkrun CLI workload backends are
//! converged onto **one** launch seam — `WorkloadRunner<Driver,
//! RealEndpointSpawner, RealBrokerRegistrar>`. The per-VM substitution endpoint
//! (the sole claim-10 egress gate) is spawned in exactly one place,
//! `RealEndpointSpawner::spawn` (`workload_runner/runner.rs`), over vsock/uds; a
//! `VmmDriver` only wires the guest port through and spawns nothing itself. This
//! gate is that claim in executable form: it fails closed if a future edit
//! reverts a converged variant to a raw backend, swaps the endpoint spawner off
//! the seam, or wires an egress endpoint inside a driver.
//!
//! Two assertions:
//!
//! - **A — the converged CLI workload variants ARE runners.** `backend.rs` keeps
//!   the `FcRunner`/`LibkrunRunner`/`HvfRunner` aliases at the full
//!   `WorkloadRunner<Driver, RealEndpointSpawner, RealBrokerRegistrar>` shape
//!   (matching the `RealEndpointSpawner, RealBrokerRegistrar` tail, so a spawner
//!   swap trips the gate), and `pub enum AnyBackend` binds the runner arms
//!   `Firecracker(FcRunner)` + `Libkrun(LibkrunRunner)` — never a raw
//!   `Firecracker(FirecrackerBackend)` / `Libkrun(LibkrunBackend)`.
//! - **B — no egress-endpoint wiring on the converged driver surface.** The
//!   `driver/*.rs` files carry none of the raw egress-spawn tokens; the one legal
//!   spawn site (`workload_runner/runner.rs`) is out of the guarded set.
//!
//! Scope — this gate is **incremental by design**. It cannot assert "every
//! workload backend is a runner": raw `AnyBackend::Hvf` is still the macOS-26
//! auto-select default (`HvfRunner` is opt-in), and `Wasm` is a workload but
//! raw. Those two are **explicitly exempt** — the exemption list is the
//! remaining-convergence ledger, and it shrinks to nothing once the HVF backend
//! also converges onto the runner seam. Until then this gate locks Firecracker +
//! libkrun and leaves raw Hvf + Wasm alone.

use anyhow::{Result, bail};
use regex::Regex;
use std::path::{Path, PathBuf};

/// The converged dispatch surface — the aliases and enum arms Assertion A reads.
const BACKEND_RS: &str = "crates/mvm-runtime/src/backend.rs";

/// A converged runner alias and the driver it must wrap. The alias must stay at
/// the `WorkloadRunner<Driver, RealEndpointSpawner, RealBrokerRegistrar>` shape;
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
const REQUIRED_ENUM_ARMS: &[&str] = &["Firecracker(FcRunner)", "Libkrun(LibkrunRunner)"];

/// Enum arms a regression would introduce — a converged variant reverted to its
/// raw backend. Their presence as a variant construction fails the gate.
const FORBIDDEN_ENUM_ARMS: &[&str] =
    &["Firecracker(FirecrackerBackend)", "Libkrun(LibkrunBackend)"];

/// The converged driver surface Assertion B guards: a `VmmDriver` only wires the
/// guest port through, so no per-VM egress endpoint may be spawned here.
///
/// Deliberately NOT guarded (they legitimately construct or hold endpoints and
/// sit outside the converged CLI scope): `workload_runner/runner.rs` (the one
/// `RealEndpointSpawner`), the builder role, the raw `libkrun.rs` +
/// `microvm/egress_bridge.rs` + `egress_redirect.rs` (held live by the hostd
/// supervisor + Firecracker standby fleet path), the endpoint definition
/// (`substitution_spawn.rs`) + the `mvm-hostd` supervisor + the substitution
/// endpoint binary, and `bench_probe`.
const GUARDED_PATHS: &[&str] = &["crates/mvm-runtime/src/driver"];

/// Raw egress-spawn tokens. Any of these on the guarded driver surface means a
/// per-VM endpoint is being spawned outside `RealEndpointSpawner`.
const FORBIDDEN: &[&str] = &[
    "spawn_substitution_endpoint",
    "EndpointTransport::Uds",
    "EndpointTransport::Vsock",
    "spawn_libkrun_egress_endpoint_if_needed",
    "spawn_egress_endpoint",
    "install_egress_redirect",
];

pub fn run(workspace: &Path) -> Result<()> {
    check_converged_runner_shape(workspace)?;
    let scanned = check_no_driver_egress_spawn(workspace)?;
    eprintln!(
        "check-uniform-vsock-egress: clean (Firecracker + libkrun bind WorkloadRunner \
         runners; {scanned} driver file(s) spawn no egress endpoint — raw Hvf + Wasm \
         exempt until HVF converges)"
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
                 Expected `type {alias} = WorkloadRunner<{driver}, RealEndpointSpawner, \
                 RealBrokerRegistrar>`. Swapping the endpoint spawner or broker registrar \
                 off this seam breaks the uniform vsock-egress convergence. (Raw Hvf + \
                 Wasm remain exempt until HVF converges — see the module doc.)",
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
                     libkrun must stay `WorkloadRunner` arms.\n    {}",
                    line.trim()
                );
            }
        }
    }
    for arm in REQUIRED_ENUM_ARMS {
        if !code.iter().any(|(_, line)| line.contains(arm)) {
            bail!(
                "check-uniform-vsock-egress: `pub enum AnyBackend` no longer binds the \
                 `{arm}` runner arm. Firecracker + libkrun must dispatch through \
                 `WorkloadRunner`, not a raw backend."
            );
        }
    }
    Ok(())
}

/// Assertion B — the converged driver surface spawns no egress endpoint. Returns
/// the number of guarded files scanned.
fn check_no_driver_egress_spawn(workspace: &Path) -> Result<usize> {
    let re = forbidden_regex();
    let rs_files = guarded_rs_files(workspace)?;
    let hits = scan_files_forbidden(workspace, &rs_files, &re);
    if !hits.is_empty() {
        bail!(
            "check-uniform-vsock-egress: a per-VM egress endpoint is spawned on the \
             converged driver surface. The only legal spawn site is \
             `RealEndpointSpawner::spawn` in workload_runner/runner.rs; a driver wires \
             the guest port through and spawns nothing:\n{}",
            hits.join("\n")
        );
    }
    Ok(rs_files.len())
}

fn alias_regex(alias: &RunnerAlias) -> Regex {
    let pattern = format!(
        r"type\s+{}\s*=\s*WorkloadRunner\s*<\s*{}\s*,\s*RealEndpointSpawner\s*,\s*RealBrokerRegistrar\s*>",
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
            "fn wire() {\n    spawn_substitution_endpoint(params);\n}\n",
        )
        .expect("write rogue driver");

        let err = check_no_driver_egress_spawn(root.path())
            .expect_err("a driver spawning an endpoint must fail the gate");
        assert!(
            err.to_string().contains("spawn_substitution_endpoint"),
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
            "type FcRunner = WorkloadRunner<FcDriver, RealEndpointSpawner, RealBrokerRegistrar>;"
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
            "type FcRunner = WorkloadRunner<FcDriver, RealEndpointSpawner, RealBrokerRegistrar>;\n\
             type LibkrunRunner = WorkloadRunner<LibkrunDriver, RealEndpointSpawner, RealBrokerRegistrar>;\n\
             type HvfRunner = WorkloadRunner<HvfDriver, RealEndpointSpawner, RealBrokerRegistrar>;\n\
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
}
