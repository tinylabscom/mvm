# Build-time Compilation of Native Per-VM Host Helpers — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `cargo run -- machine run …` compile the native per-VM host helpers during its build phase instead of shelling out to `cargo` at run time, so all compilation finishes before the command executes.

**Architecture:** `mvm-cli/build.rs` (which already cross-compiles + embeds musl host-vm bins via a nested `cargo` aimed at a dedicated target dir to dodge cargo's build-lock deadlock) is extended to also build the native host helpers into `OUT_DIR/aux-helper-target/<profile>/` and export that dir via `cargo:rustc-env=MVM_AUX_BIN_DIR`. `mvm-cli` bridges that compile-time value into the process env at startup; `mvm-backend/src/aux_bin.rs` drops its run-time `cargo build` and becomes a pure resolver.

**Tech Stack:** Rust (edition 2024), Cargo build scripts, `mvm-cli`, `mvm-backend`.

Design doc: `specs/notes/buildtime-aux-helper-compilation-design.md`.

## Global Constraints

- Edition **2024**: `std::env::set_var` is `unsafe` (the codebase already wraps it in `unsafe { … }` in `apply_startup_env`). Do not introduce a safe-wrapper illusion.
- **No spec/plan/PR/ADR references in code comments** (`Plan N`, `ADR-\d+`, `#NNNN`, `W\d.` are CI-banned by `xtask check-no-spec-refs-in-comments`). Reword to the concept.
- **No `#[allow(clippy::too_many_arguments)]`** in hand-written code.
- **No `Co-Authored-By: Claude`** trailer; attribute commits to the user.
- Verification gate before "done": `cargo fmt --all -- --check`, `cargo nextest run --workspace`, `cargo test --workspace --doc`, `cargo clippy --workspace -- -D warnings`, and `cargo build --all-targets` clean.
- Scope is the **native host helpers only** (`aux_bin.rs`). Do **not** touch the guest (`guest_agent_build.rs`) or embedded-host-vm (`host_binaries/source_build.rs`) cross-compile paths.
- Work happens in the existing worktree `/Users/auser/work/tinylabs/mvmco/.worktrees/mvm-buildtime-aux-helpers` (branch `feat/buildtime-aux-helpers`). Edit under that absolute path.

---

## File Structure

- `crates/mvm-cli/build_aux_helpers.rs` — **new** pure module: which helpers to build for a given host, and the skip policy. No I/O.
- `crates/mvm-cli/tests/build_aux_helpers.rs` — **new** integration-test shim (mirrors `tests/build_embed_mode.rs`): `#[path]`-includes the build-script module and runs its tests. Build-script modules' inline `#[cfg(test)]` are invisible to `cargo test`, so tests for `build_aux_helpers.rs` must live in a `tests/` shim to execute.
- `crates/mvm-cli/build.rs` — **modify**: include the new module, probe libkrun, run the native builds into a dedicated target dir, always emit `MVM_AUX_BIN_DIR`, add `rerun-if-changed`.
- `crates/mvm-cli/src/commands/mod.rs` — **modify**: bridge the baked `MVM_AUX_BIN_DIR` into the process env at startup (`apply_startup_env`), plus a pure decision helper + test.
- `crates/mvm-backend/src/aux_bin.rs` — **rewrite** to resolve-only: new `AuxBin { bin, env_var }`, `resolve()`, a pure candidate-ordering fn, precise missing-helper error. Delete `build_in_workspace`, the mtime auto-rebuild, and `helper_binaries_need_rebuild`.
- `crates/mvm-backend/src/libkrun.rs` — **modify**: update `resolve_supervisor_path`, delete `LIBKRUN_SUPERVISOR_INPUT_ROOTS`, fix the stale doc-comment.
- `crates/mvm-backend/src/hvf_backend.rs` — **modify**: update `resolve_supervisor_path`, fix the stale doc-comment.
- `crates/mvm-backend/src/substitution_spawn.rs` — **modify**: update `resolve_substitution_endpoint_path`, fix the stale doc-comment.
- `Justfile` — **modify**: correct the `build-supervisors` comment; simplify `e2e-core-demo`.

---

## Task 1: build.rs compiles the native helpers up front

**Files:**
- Create: `crates/mvm-cli/build_aux_helpers.rs`
- Create: `crates/mvm-cli/tests/build_aux_helpers.rs` (integration-test shim — build-script modules' inline `#[cfg(test)]` don't run under `cargo test`; mirror `tests/build_embed_mode.rs`)
- Modify: `crates/mvm-cli/build.rs`
- Test command: `cargo test -p mvm-cli --test build_aux_helpers`

**Interfaces:**
- Produces: env var `MVM_AUX_BIN_DIR` (via `cargo:rustc-env`) pointing at `OUT_DIR/aux-helper-target/<profile>`, always emitted (even when the build is skipped) so `env!("MVM_AUX_BIN_DIR")` compiles in mvm-cli. Helper binaries land at `<MVM_AUX_BIN_DIR>/<bin>`.
- Produces (for Task tests): `build_aux_helpers::aux_helper_specs(target_os, target_arch, libkrun_present, skip) -> Vec<AuxHelperSpec>` and `build_aux_helpers::should_skip_aux_helpers(skip_env: Option<&str>) -> bool`.

- [ ] **Step 1: Write the failing test** — create `crates/mvm-cli/build_aux_helpers.rs` with the module below. Put the `#[cfg(test)] mod tests` cases in the `tests/` shim (Step 2), NOT inline — a build-script module's inline tests never run under `cargo test`. The module (functions only):

```rust
//! Pure selection logic for the native per-VM host helpers that mvm-cli's build
//! script compiles up front. Kept I/O-free so the host-conditional and skip
//! rules are unit-tested without running a real build.

/// A native host helper the build script compiles for this host, so that
/// `cargo run` produces it before `mvmctl` executes (cargo on its own builds
/// only the run target, never sibling `[[bin]]`s in other crates).
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct AuxHelperSpec {
    pub package: &'static str,
    pub bin: &'static str,
    pub features: &'static [&'static str],
}

/// The helpers to build for `(target_os, target_arch)`, given whether libkrun
/// is installed and whether the explicit skip flag is set. Empty when skipping.
/// The libkrun supervisor is included only where libkrun is present because it
/// links `-lkrun`; the HVF supervisor only on macOS/aarch64.
pub(crate) fn aux_helper_specs(
    target_os: &str,
    target_arch: &str,
    libkrun_present: bool,
    skip: bool,
) -> Vec<AuxHelperSpec> {
    if skip {
        return Vec::new();
    }
    let mut specs = vec![AuxHelperSpec {
        package: "mvm-hostd",
        bin: "mvm-substitution-endpoint",
        features: &[],
    }];
    if target_os == "macos" && target_arch == "aarch64" {
        specs.push(AuxHelperSpec {
            package: "mvm-vm-host",
            bin: "mvm-hvf-supervisor",
            features: &[],
        });
    }
    if libkrun_present {
        specs.push(AuxHelperSpec {
            package: "mvm-vm-host",
            bin: "mvm-libkrun-supervisor",
            features: &["libkrun-sys"],
        });
    }
    specs
}

/// Whether to skip the native-helper build. Unlike the embedded musl bins
/// (which stub out in debug by default), the native helpers must build in every
/// profile — the debug `cargo run` loop is the whole point — so only the
/// explicit escape hatch skips them.
pub(crate) fn should_skip_aux_helpers(skip_env: Option<&str>) -> bool {
    matches!(skip_env, Some("1"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bins(specs: &[AuxHelperSpec]) -> Vec<&str> {
        specs.iter().map(|s| s.bin).collect()
    }

    #[test]
    fn substitution_endpoint_builds_on_every_host() {
        let specs = aux_helper_specs("linux", "x86_64", false, false);
        assert_eq!(bins(&specs), vec!["mvm-substitution-endpoint"]);
    }

    #[test]
    fn hvf_supervisor_only_on_macos_aarch64() {
        let mac = aux_helper_specs("macos", "aarch64", false, false);
        assert!(bins(&mac).contains(&"mvm-hvf-supervisor"));
        let linux = aux_helper_specs("linux", "aarch64", false, false);
        assert!(!bins(&linux).contains(&"mvm-hvf-supervisor"));
        let intel_mac = aux_helper_specs("macos", "x86_64", false, false);
        assert!(!bins(&intel_mac).contains(&"mvm-hvf-supervisor"));
    }

    #[test]
    fn libkrun_supervisor_only_when_libkrun_present() {
        let present = aux_helper_specs("macos", "aarch64", true, false);
        let spec = present
            .iter()
            .find(|s| s.bin == "mvm-libkrun-supervisor")
            .expect("libkrun supervisor present");
        assert_eq!(spec.features, &["libkrun-sys"]);
        let absent = aux_helper_specs("macos", "aarch64", false, false);
        assert!(!bins(&absent).contains(&"mvm-libkrun-supervisor"));
    }

    #[test]
    fn skip_yields_no_specs() {
        assert!(aux_helper_specs("macos", "aarch64", true, true).is_empty());
    }

    #[test]
    fn only_explicit_flag_skips() {
        assert!(should_skip_aux_helpers(Some("1")));
        assert!(!should_skip_aux_helpers(None));
        assert!(!should_skip_aux_helpers(Some("0")));
    }
}
```

Put the five tests in the shim `crates/mvm-cli/tests/build_aux_helpers.rs` (not an inline `#[cfg(test)]` mod — those don't run for a build-script module), mirroring `tests/build_embed_mode.rs`:

```rust
#[path = "../build_aux_helpers.rs"]
mod build_aux_helpers;

use build_aux_helpers::{AuxHelperSpec, aux_helper_specs, should_skip_aux_helpers};

fn bins(specs: &[AuxHelperSpec]) -> Vec<&str> {
    specs.iter().map(|s| s.bin).collect()
}
// …the five #[test] fns from Step 1, referencing the imported items directly.
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p mvm-cli --test build_aux_helpers 2>&1 | tail -5`
Expected: compile error / no functions — `aux_helper_specs` not defined yet.

- [ ] **Step 3: Wire the module into build.rs and add the build step** — at the very top of `crates/mvm-cli/build.rs`, next to the existing `#[path = "build_embed_mode.rs"] mod build_embed_mode;`, add:

```rust
#[path = "build_aux_helpers.rs"]
mod build_aux_helpers;
```

Then, inside `fn main()`, after the guest-binaries block (right before `let embedded_rs = render_embedded_rs(&entries);`), add a call:

```rust
    build_native_aux_helpers(&workspace_root, &out_dir);
```

And add these three functions to `build.rs` (place them after `should_skip_embed_binaries`):

```rust
/// Compile the native per-VM host helpers into a dedicated target dir under
/// OUT_DIR and export that dir as `MVM_AUX_BIN_DIR`, so `cargo run` produces
/// them during its build phase rather than mvmctl shelling out to `cargo` at
/// run time. The dedicated target dir avoids the outer build-lock deadlock the
/// same way the embedded-bins path does (see the note in `main`).
fn build_native_aux_helpers(workspace_root: &Path, out_dir: &Path) {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());
    let aux_target = out_dir.join("aux-helper-target");
    let bin_dir = aux_target.join(&profile);

    // Always export the dir — even on skip or an unbuildable helper — so
    // `env!("MVM_AUX_BIN_DIR")` compiles in mvm-cli; resolution `is_file`-checks
    // each candidate, so a dir with missing bins is harmless.
    println!("cargo:rustc-env=MVM_AUX_BIN_DIR={}", bin_dir.display());
    println!("cargo:rerun-if-env-changed=MVM_SKIP_EMBED_BINARIES");
    println!(
        "cargo:rerun-if-changed={}",
        workspace_root.join("crates/mvm-vm-host/src").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        workspace_root.join("crates/mvm-hostd/src").display()
    );

    let skip = build_aux_helpers::should_skip_aux_helpers(
        std::env::var("MVM_SKIP_EMBED_BINARIES").ok().as_deref(),
    );
    let libkrun_present = libkrun_header_present();
    for spec in build_aux_helpers::aux_helper_specs(&target_os, &target_arch, libkrun_present, skip)
    {
        run_cargo_native_build(workspace_root, &aux_target, &profile, &spec);
    }
}

/// Nested native `cargo build` for one helper into `target_dir`. Fail-open: a
/// helper this host can't build must not break the outer compile — aux_bin
/// surfaces a precise error only if the helper is actually needed at run time.
fn run_cargo_native_build(
    root: &Path,
    target_dir: &Path,
    profile: &str,
    spec: &build_aux_helpers::AuxHelperSpec,
) {
    eprintln!(
        "[build.rs] building per-VM host helper: {} (-p {})",
        spec.bin, spec.package
    );
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut cmd = Command::new(cargo);
    cmd.args(["build", "-p", spec.package, "--bin", spec.bin]);
    if profile == "release" {
        cmd.arg("--release");
    }
    if !spec.features.is_empty() {
        cmd.arg("--features").arg(spec.features.join(","));
    }
    // Dedicated target dir — the outer `cargo` holds the workspace `target/`
    // lock for the whole build-script run; a nested cargo aimed at it deadlocks.
    cmd.env("CARGO_TARGET_DIR", target_dir).current_dir(root);
    match cmd.status() {
        Ok(status) if status.success() => {}
        other => eprintln!(
            "[build.rs] per-VM helper {} not built ({other:?}); it will be \
             resolved at run time only if needed",
            spec.bin
        ),
    }
}

/// Whether `libkrun.h` is installed, mirroring the probe `libkrun-sys`'s build
/// script uses to decide the `-lkrun` link. Gate for building the libkrun
/// supervisor so an HVF-only / CI host does not attempt (and noisily fail) it.
fn libkrun_header_present() -> bool {
    if let Some(p) = std::env::var_os("MVM_LIBKRUN_HEADER") {
        if Path::new(&p).is_file() {
            return true;
        }
    }
    [
        "/opt/homebrew/include/libkrun.h",
        "/usr/local/include/libkrun.h",
        "/usr/include/libkrun.h",
    ]
    .iter()
    .any(|p| Path::new(p).is_file())
}
```

- [ ] **Step 4: Run the module tests to verify they pass**

Run: `cargo test -p mvm-cli --test build_aux_helpers 2>&1 | tail -15`
Expected: the five `build_aux_helpers` tests run and PASS.

- [ ] **Step 5: Verify a real build produces the helpers and emits the env** — on this macOS/aarch64 host:

Run: `cargo build -p mvm-cli 2>&1 | grep -i 'per-VM host helper' ; ls "$(cargo build -p mvm-cli 2>/dev/null; find target/debug/build -type d -name aux-helper-target | head -1)/debug"`
Expected: build-script log lines for `mvm-substitution-endpoint` and `mvm-hvf-supervisor` (and `mvm-libkrun-supervisor` if libkrun is installed), and those binaries present under the `aux-helper-target/debug` dir.

- [ ] **Step 6: Commit**

```bash
cd /Users/auser/work/tinylabs/mvmco/.worktrees/mvm-buildtime-aux-helpers
git add crates/mvm-cli/build_aux_helpers.rs crates/mvm-cli/build.rs
git commit -m "build(mvm-cli): compile native per-VM host helpers up front"
```

---

## Task 2: Bridge MVM_AUX_BIN_DIR into the process env at startup

**Files:**
- Modify: `crates/mvm-cli/src/commands/mod.rs` (`apply_startup_env`, ~line 223)
- Test: `crates/mvm-cli/src/commands/mod.rs` (inline `#[cfg(test)]`)

**Interfaces:**
- Consumes: `env!("MVM_AUX_BIN_DIR")` (baked by Task 1's build.rs).
- Produces: process env `MVM_AUX_BIN_DIR` set to the baked dir when the caller hasn't set it — the value `mvm-backend`'s resolver (Task 3) reads. Pure helper `aux_bin_dir_to_apply(baked: &str, already_set: bool) -> Option<String>`.

- [ ] **Step 1: Write the failing test** — add to the `#[cfg(test)]` module in `crates/mvm-cli/src/commands/mod.rs` (create one if none exists at file end):

```rust
    #[test]
    fn aux_bin_dir_applied_only_when_unset_and_nonempty() {
        assert_eq!(
            super::aux_bin_dir_to_apply("/x/aux/debug", false),
            Some("/x/aux/debug".to_string())
        );
        assert_eq!(super::aux_bin_dir_to_apply("/x/aux/debug", true), None);
        assert_eq!(super::aux_bin_dir_to_apply("", false), None);
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p mvm-cli --lib aux_bin_dir_applied 2>&1 | tail -5`
Expected: FAIL — `aux_bin_dir_to_apply` not found.

- [ ] **Step 3: Implement the helper and wire it into `apply_startup_env`** — add the pure helper near `apply_startup_env`:

```rust
/// The value to write to `MVM_AUX_BIN_DIR`, or `None` to leave the env alone.
/// The build script bakes in the dir where it compiled the per-VM helpers; we
/// surface it to mvm-backend's resolver unless the caller already set it (an
/// explicit override wins) or the build produced no path.
fn aux_bin_dir_to_apply(baked: &str, already_set: bool) -> Option<String> {
    if already_set || baked.is_empty() {
        return None;
    }
    Some(baked.to_string())
}
```

Then, inside `apply_startup_env`, after the existing `MVM_BUILDER_BACKEND` block, add:

```rust
    if let Some(dir) = aux_bin_dir_to_apply(
        env!("MVM_AUX_BIN_DIR"),
        std::env::var_os("MVM_AUX_BIN_DIR").is_some(),
    ) {
        unsafe { std::env::set_var("MVM_AUX_BIN_DIR", dir) };
    }
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p mvm-cli --lib aux_bin_dir_applied 2>&1 | tail -5`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd /Users/auser/work/tinylabs/mvmco/.worktrees/mvm-buildtime-aux-helpers
git add crates/mvm-cli/src/commands/mod.rs
git commit -m "feat(mvm-cli): bridge baked MVM_AUX_BIN_DIR into the process env"
```

---

## Task 3: Make aux_bin a pure resolver; drop run-time compilation

**Files:**
- Modify (rewrite): `crates/mvm-backend/src/aux_bin.rs`
- Modify: `crates/mvm-backend/src/libkrun.rs` (`resolve_supervisor_path`, delete `LIBKRUN_SUPERVISOR_INPUT_ROOTS`)
- Modify: `crates/mvm-backend/src/hvf_backend.rs` (`resolve_supervisor_path`)
- Modify: `crates/mvm-backend/src/substitution_spawn.rs` (`resolve_substitution_endpoint_path`)
- Test: `crates/mvm-backend/src/aux_bin.rs` (inline `#[cfg(test)]`)

**Interfaces:**
- Consumes: process env `MVM_AUX_BIN_DIR` (Task 2), per-bin override env vars, `current_exe`.
- Produces: `AuxBin { bin: &str, env_var: &str }` and `pub(crate) fn resolve(spec: &AuxBin) -> Result<PathBuf>`. Pure ordering fn `assemble_candidate_dirs(exe_dir: Option<PathBuf>, aux_dir: Option<PathBuf>, target_dirs: Vec<PathBuf>) -> Vec<PathBuf>` and `first_existing_bin(bin: &str, dirs: &[PathBuf]) -> Option<PathBuf>`.

- [ ] **Step 1: Write the failing tests** — replace the entire `#[cfg(test)] mod tests` in `crates/mvm-backend/src/aux_bin.rs` with:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_order_is_exe_then_aux_then_targets() {
        let dirs = assemble_candidate_dirs(
            Some(PathBuf::from("/exe")),
            Some(PathBuf::from("/aux/debug")),
            vec![PathBuf::from("/repo/target/release"), PathBuf::from("/repo/target/debug")],
        );
        assert_eq!(
            dirs,
            vec![
                PathBuf::from("/exe"),
                PathBuf::from("/aux/debug"),
                PathBuf::from("/repo/target/release"),
                PathBuf::from("/repo/target/debug"),
            ]
        );
    }

    #[test]
    fn candidate_order_skips_absent_exe_and_aux() {
        let dirs = assemble_candidate_dirs(None, None, vec![PathBuf::from("/repo/target/debug")]);
        assert_eq!(dirs, vec![PathBuf::from("/repo/target/debug")]);
    }

    #[test]
    fn first_existing_returns_first_dir_holding_the_bin() {
        let tmp = tempfile::tempdir().unwrap();
        let a = tmp.path().join("a");
        let b = tmp.path().join("b");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        std::fs::write(b.join("mvm-hvf-supervisor"), b"bin").unwrap();
        let found = first_existing_bin("mvm-hvf-supervisor", &[a.clone(), b.clone()]);
        assert_eq!(found, Some(b.join("mvm-hvf-supervisor")));
    }

    #[test]
    fn first_existing_none_when_absent_everywhere() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(
            first_existing_bin("mvm-hvf-supervisor", &[tmp.path().to_path_buf()]),
            None
        );
    }

    #[test]
    fn libkrun_missing_hint_mentions_libkrun() {
        assert!(missing_hint("mvm-libkrun-supervisor").contains("libkrun"));
        assert_eq!(missing_hint("mvm-hvf-supervisor"), "");
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p mvm-backend --lib aux_bin 2>&1 | tail -15`
Expected: compile error — `assemble_candidate_dirs`, `first_existing_bin`, `missing_hint` don't exist yet.

- [ ] **Step 3: Rewrite `aux_bin.rs` as a resolver** — replace everything above the `#[cfg(test)]` module with:

```rust
//! Resolver for the per-VM host helper binaries `mvmctl` spawns — the backend
//! supervisors (`mvm-hvf-supervisor`, `mvm-libkrun-supervisor`) and the
//! substitution endpoint. Each is a separate `[[bin]]` in a workspace crate,
//! which cargo does not build for a plain `cargo run` of mvmctl; the mvm-cli
//! build script compiles them during the build phase instead.
//!
//! Resolution order (first existing file wins): `$<ENV_VAR>` override →
//! alongside the current exe (a downloaded release ships them there) →
//! `$MVM_AUX_BIN_DIR` (the build script's dir, bridged into the env at startup)
//! → workspace `target/{release,debug}` (an explicit `just build-supervisors`).

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

/// A per-VM helper binary and its path-override env var.
pub(crate) struct AuxBin<'a> {
    /// Binary/file name, e.g. `mvm-hvf-supervisor`.
    pub bin: &'a str,
    /// Path-override env var, e.g. `MVM_HVF_SUPERVISOR_PATH`.
    pub env_var: &'a str,
}

/// Resolve `spec` to an on-disk binary. Never builds — the build script
/// produces these; a missing one is a hard error with a recovery hint.
pub(crate) fn resolve(spec: &AuxBin) -> Result<PathBuf> {
    if let Some(p) = std::env::var_os(spec.env_var).map(PathBuf::from) {
        if p.is_file() {
            return Ok(p);
        }
        bail!(
            "{} points at {} which is not a file",
            spec.env_var,
            p.display()
        );
    }
    let dirs = assemble_candidate_dirs(
        current_exe_dir(),
        aux_bin_dir_from_env(),
        workspace_target_dirs(),
    );
    if let Some(found) = first_existing_bin(spec.bin, &dirs) {
        return Ok(found);
    }
    bail!(
        "{bin} not found. It is a per-VM host helper compiled by mvmctl's build \
         script; on a source checkout run `cargo build` (or `just \
         build-supervisors`), or set {env}=<path>.{hint}",
        bin = spec.bin,
        env = spec.env_var,
        hint = missing_hint(spec.bin),
    )
}

/// Ordered directories to search for a helper: exe dir, then the build script's
/// dir, then the workspace target dirs. Absent optional dirs are dropped.
fn assemble_candidate_dirs(
    exe_dir: Option<PathBuf>,
    aux_dir: Option<PathBuf>,
    target_dirs: Vec<PathBuf>,
) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    dirs.extend(exe_dir);
    dirs.extend(aux_dir);
    dirs.extend(target_dirs);
    dirs
}

fn first_existing_bin(bin: &str, dirs: &[PathBuf]) -> Option<PathBuf> {
    dirs.iter().map(|d| d.join(bin)).find(|p| p.is_file())
}

/// Extra recovery hint for helpers with a host prerequisite. Empty otherwise.
fn missing_hint(bin: &str) -> &'static str {
    if bin == "mvm-libkrun-supervisor" {
        " This helper links libkrun; install it (`brew install slp/krun/libkrun`) and rebuild."
    } else {
        ""
    }
}

fn current_exe_dir() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(Path::to_path_buf))
}

fn aux_bin_dir_from_env() -> Option<PathBuf> {
    let dir = std::env::var_os("MVM_AUX_BIN_DIR")?;
    if dir.is_empty() {
        return None;
    }
    Some(PathBuf::from(dir))
}

fn workspace_root_from_manifest_dir() -> Option<PathBuf> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir.parent()?.parent().map(Path::to_path_buf)
}

/// `target/{release,debug}` under each workspace target dir (default plus a
/// `CARGO_TARGET_DIR` override), the fallback for `just build-supervisors`.
fn workspace_target_dirs() -> Vec<PathBuf> {
    let Some(root) = workspace_root_from_manifest_dir() else {
        return Vec::new();
    };
    let mut dirs = Vec::new();
    for base in source_checkout_target_dirs(&root) {
        dirs.push(base.join("release"));
        dirs.push(base.join("debug"));
    }
    dirs
}

fn source_checkout_target_dirs(workspace_root: &Path) -> Vec<PathBuf> {
    let default_target_dir = workspace_root.join("target");
    let effective_target_dir = effective_cargo_target_dir(workspace_root);
    if effective_target_dir == default_target_dir {
        vec![default_target_dir]
    } else {
        vec![effective_target_dir, default_target_dir]
    }
}

fn effective_cargo_target_dir(workspace_root: &Path) -> PathBuf {
    cargo_target_dir_from_env(workspace_root, std::env::var_os("CARGO_TARGET_DIR"))
}

fn cargo_target_dir_from_env(workspace_root: &Path, target_dir: Option<OsString>) -> PathBuf {
    let Some(target_dir) = target_dir else {
        return workspace_root.join("target");
    };
    if target_dir.is_empty() {
        return workspace_root.join("target");
    }
    let target_dir = PathBuf::from(target_dir);
    if target_dir.is_absolute() {
        target_dir
    } else {
        workspace_root.join(target_dir)
    }
}
```

Keep the `cargo_target_dir_from_env` unit test from the old file (append it into the test module) since that helper survives:

```rust
    #[test]
    fn cargo_target_dir_from_env_honors_absolute_and_relative_overrides() {
        let root = Path::new("/repo/mvm");
        assert_eq!(cargo_target_dir_from_env(root, None), root.join("target"));
        assert_eq!(
            cargo_target_dir_from_env(root, Some(OsString::from("/tmp/mvm-target"))),
            Path::new("/tmp/mvm-target")
        );
        assert_eq!(
            cargo_target_dir_from_env(root, Some(OsString::from("build/target"))),
            root.join("build/target")
        );
    }
```

- [ ] **Step 4: Update the three call sites** — in `crates/mvm-backend/src/libkrun.rs`, delete the `LIBKRUN_SUPERVISOR_INPUT_ROOTS` const (the `const … = [ … ];` block ending at `crates/mvm-hostd/src` / `];`) and replace `resolve_supervisor_path`:

```rust
/// Resolve the absolute path to the `mvm-libkrun-supervisor` binary. Compiled
/// by mvmctl's build script; see [`crate::aux_bin`] for the search order.
pub(crate) fn resolve_supervisor_path() -> Result<PathBuf> {
    crate::aux_bin::resolve(&crate::aux_bin::AuxBin {
        bin: "mvm-libkrun-supervisor",
        env_var: "MVM_LIBKRUN_SUPERVISOR_PATH",
    })
}
```

In `crates/mvm-backend/src/hvf_backend.rs`, replace `resolve_supervisor_path`:

```rust
/// Locate the per-VM HVF supervisor binary. Compiled by mvmctl's build script;
/// see [`crate::aux_bin`] for the search order.
pub(crate) fn resolve_supervisor_path() -> Result<PathBuf> {
    crate::aux_bin::resolve(&crate::aux_bin::AuxBin {
        bin: "mvm-hvf-supervisor",
        env_var: "MVM_HVF_SUPERVISOR_PATH",
    })
}
```

In `crates/mvm-backend/src/substitution_spawn.rs`, replace `resolve_substitution_endpoint_path`:

```rust
/// Locate the `mvm-substitution-endpoint` binary. Compiled by mvmctl's build
/// script; see [`crate::aux_bin`] for the search order.
fn resolve_substitution_endpoint_path() -> Result<PathBuf> {
    crate::aux_bin::resolve(&crate::aux_bin::AuxBin {
        bin: "mvm-substitution-endpoint",
        env_var: "MVM_SUBSTITUTION_ENDPOINT_PATH",
    })
}
```

- [ ] **Step 5: Run the tests to verify they pass and the crate builds**

Run: `cargo test -p mvm-backend --lib aux_bin 2>&1 | tail -20`
Expected: the six `aux_bin` tests PASS; `mvm-backend` compiles (no dangling `LIBKRUN_SUPERVISOR_INPUT_ROOTS` / `resolve_or_build` references).

- [ ] **Step 6: Commit**

```bash
cd /Users/auser/work/tinylabs/mvmco/.worktrees/mvm-buildtime-aux-helpers
git add crates/mvm-backend/src/aux_bin.rs crates/mvm-backend/src/libkrun.rs \
        crates/mvm-backend/src/hvf_backend.rs crates/mvm-backend/src/substitution_spawn.rs
git commit -m "refactor(mvm-backend): resolve per-VM helpers without run-time compile"
```

---

## Task 4: Justfile cleanup, full gate, and live verification

**Files:**
- Modify: `Justfile` (`build-supervisors` comment; `e2e-core-demo`)

**Interfaces:**
- Consumes: everything from Tasks 1–3.

- [ ] **Step 1: Correct the `build-supervisors` comment** — in `Justfile`, replace the comment above `build-supervisors:` (the lines starting `# Build the per-VM host helper bins …` through `# self-builds them on the first \`machine run\`, so this is just the explicit route.`) with:

```
# Build the per-VM host helper bins explicitly. mvmctl's build script already
# compiles them during `cargo build`/`cargo run`; this is the manual route for
# a targeted rebuild or CI.
```

- [ ] **Step 2: Simplify `e2e-core-demo`** — the demo's manual supervisor build is now redundant with the build script. Remove the `cargo build -p mvm-vm-host --bin mvm-libkrun-supervisor --features libkrun-sys` line and its two-line comment from the `e2e-core-demo:` recipe, keeping the `cargo build --bin mvmctl` line (which triggers the build script that produces the supervisor).

- [ ] **Step 3: Run the full verification gate**

Run:
```bash
cd /Users/auser/work/tinylabs/mvmco/.worktrees/mvm-buildtime-aux-helpers
cargo fmt --all -- --check && \
cargo clippy --workspace -- -D warnings && \
cargo build --all-targets && \
cargo nextest run --workspace && \
cargo test --workspace --doc
```
Expected: all pass, zero warnings.

- [ ] **Step 4: Live end-to-end verification** — confirm the antipattern is gone. Run the exact command from the report and capture ordering:

```bash
cd /Users/auser/work/tinylabs/mvmco/.worktrees/mvm-buildtime-aux-helpers
cargo run -- machine run --image alpine -it --allow-host google.com -- /bin/sh </dev/null 2>&1 | \
  grep -nE 'Compiling mvm-vm-host|Compiling mvm-substitution|building per-VM host helper|Running .*mvmctl|Finished'
```
Expected: every helper-compile / "building per-VM host helper" line appears **before** the `Running …/mvmctl …` line; none after it. A second run with no source change prints no helper-compile lines at all.

- [ ] **Step 5: Confirm the CI spec-ref gate is clean** (comments must not cite plans/PRs/ADRs):

Run: `cargo run -p xtask -- check-no-spec-refs-in-comments && cargo run -p xtask -- check-spec-numbers`
Expected: both report clean (243 is a unique prefix).

- [ ] **Step 6: Commit**

```bash
cd /Users/auser/work/tinylabs/mvmco/.worktrees/mvm-buildtime-aux-helpers
git add Justfile
git commit -m "chore: build-supervisors is now the explicit route; simplify e2e-core-demo"
```

---

## Self-Review

- **Spec coverage:** build.rs up-front build → Task 1; host-conditional + fail-open + skip flag → Task 1 (`aux_helper_specs`, `run_cargo_native_build` fail-open, `should_skip_aux_helpers`); `MVM_AUX_BIN_DIR` bridge → Tasks 1+2; resolve-only precedence (override → aux dir → sibling → target; aux dir precedes the exe-sibling so a stale `target/debug` copy can't shadow the fresh build, fixed post-review) → Task 3; release-safe skip of a non-existent baked dir → Task 3 (`is_file` checks, `aux_bin_dir_from_env` empty-guard); precise missing-helper error → Task 3 (`missing_hint`); freshness via `rerun-if-changed` → Task 1; Justfile/e2e cleanup → Task 4; live verification → Task 4.
- **Type consistency:** `resolve` (not `resolve_or_build`) used at all three call sites and defined in Task 3; `AuxBin { bin, env_var }` shape matches all call sites (no `package`/`features`/`input_roots`); `aux_helper_specs`/`should_skip_aux_helpers`/`AuxHelperSpec` names identical across Task 1 def and tests; `MVM_AUX_BIN_DIR` spelled identically in build.rs emit, mvm-cli `env!`, and mvm-backend read.
- **Out-of-scope confirmed untouched:** `guest_agent_build.rs` and `host_binaries/source_build.rs` are not modified.
