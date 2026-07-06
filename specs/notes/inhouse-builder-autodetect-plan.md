# In-house HVF Builder — Auto-detect Selection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the HVF builder the auto-detected builder backend on macOS-26 Apple Silicon (no flag/env), with a Vz-free `[InHouse, Libkrun]` fallback that keeps bare builds working before #1401.

**Architecture:** `mvm-build` owns the pure selection surface (`BuilderBackendChoice::InHouse`, auto-detect flip, Vz-free attempt order, failure classification) plus a `OnceLock` registration hook so a higher crate can supply the hvf constructor without inverting the crate graph. `mvm-cli` registers that hook at startup with an image auto-resolver that derives an HVF-bootable builder image (config-hash-keyed cache) and constructs `InHouseBuilderVm`.

**Tech Stack:** Rust, cargo workspace, `mvm-core::config` paths, `mvm_build::rootfs_inject`, `mvm-backend` `InHouseBuilderVm`/`BuilderRunner`.

## Global Constraints

- Design spec: `specs/notes/hvf-builder-autodetect-design.md`. Issue #1403; related #1401.
- No plan/PR/ADR/sprint citations in source **code comments** (`xtask check-no-spec-refs-in-comments`). Citations belong in commit messages / this plan only.
- No `#[allow(clippy::too_many_arguments)]`; use a params struct + builder if a fn trips it.
- All `~/.mvm` + `~/.cache/mvm` paths go through `mvm-core::config` helpers / `mvm_build::builder_vm::builder_vm_cache_dir()` — never inline `$HOME`.
- Vz is being deprecated: no new code may add Vz to a default or fallback path. Do **not** delete Vz code in this plan (final consolidated step).
- Gates (run before every commit that touches Rust): `cargo fmt --all -- --check`; `cargo clippy --workspace --all-targets -- -D warnings`; `cargo nextest run -p mvm-build` (and `-p mvm-cli` for CLI tasks). Use `~/.cargo/bin/cargo` (rustup), not Homebrew.
- Commit trailer: `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.
- Branch: `feat/plan-214-hvf-builder-select` (worktree `.worktrees/mvm-1403-hvf-builder`).

---

## File Structure

- `crates/mvm-build/src/builder_backend_select.rs` — Tasks 1–5 (variant, auto-detect, attempt order, classification, registration hook).
- `crates/mvm-build/src/builder_vm.rs` — Task 4 (new `BuilderVmError` mapping helper, if needed).
- `crates/mvm-backend/src/builder_runner/hvf_builder.rs` — Task 4 (map run failures to VMM-level errors).
- `crates/mvm-cli/src/commands/build/hvf_builder_image.rs` *(new)* — Task 6 (image auto-resolver).
- `crates/mvm-cli/src/commands/mod.rs` — Task 7 (register hook at startup; `--builder` possible values).
- `crates/mvm-cli/src/doctor.rs` — Task 7 (builder-backend line reports hvf).
- `CLAUDE.md` — Task 7 (auto-detect wording).
- `crates/mvm-cli/tests/` or an in-crate `#[cfg(test)]` module — Task 8 (fallback-keeps-builds test + gated e2e).

---

## Task 1: `BuilderBackendChoice::InHouse` variant

**Files:**
- Modify: `crates/mvm-build/src/builder_backend_select.rs` (enum ~59-69, `name` ~73-79, `resolve_env_override` ~116-133)
- Test: same file's `#[cfg(test)] mod tests`

**Interfaces:**
- Produces: `BuilderBackendChoice::InHouse`; `BuilderBackendChoice::InHouse.name() == "hvf"`; `resolve_env_override()` returns `Some(InHouse)` for `"hvf"` (case-insensitive, trimmed).

- [ ] **Step 1: Write failing tests** — add to `mod tests`:

```rust
#[test]
fn resolve_env_override_hvf() {
    with_env(Some("hvf"), || {
        assert_eq!(resolve_env_override(), Some(BuilderBackendChoice::InHouse));
    });
}

#[test]
fn resolve_env_override_hvf_case_insensitive_trimmed() {
    with_env(Some("  InHouse  "), || {
        assert_eq!(resolve_env_override(), Some(BuilderBackendChoice::InHouse));
    });
}

#[test]
fn backend_choice_name_hvf() {
    assert_eq!(BuilderBackendChoice::InHouse.name(), "hvf");
}
```

- [ ] **Step 2: Run, verify fail**

Run: `cargo test -p mvm-build resolve_env_override_hvf -- --nocapture`
Expected: FAIL — `no variant named InHouse`.

- [ ] **Step 3: Add the variant + name + parse**

In the enum, after `Qemu,`:

```rust
    /// In-house HVF builder VM (the destination macOS backend). The
    /// auto-detected default on macOS-26 Apple Silicon; opt-in elsewhere via
    /// `MVM_BUILDER_BACKEND=hvf` / `--builder hvf`.
    InHouse,
```

In `name`, add the arm:

```rust
            BuilderBackendChoice::InHouse => "hvf",
```

In `resolve_env_override`'s match, add before `other =>`:

```rust
        "hvf" => Some(BuilderBackendChoice::InHouse),
```

- [ ] **Step 4: Run, verify pass** — `cargo test -p mvm-build resolve_env_override_hvf backend_choice_name_hvf`. Expected: PASS. Adding the variant makes `resolve_builder_backend_with_override` and `resolve_stage0_backend_for_choice` non-exhaustive; add their real `InHouse` arms now (Stage-0 arm per §1b, factory arm per §1d) — **no temporary `unreachable!`**. Tasks 1a–1d are one dispatch and must leave the crate compiling with all tests passing.

- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(build): BuilderBackendChoice::InHouse variant" ...`

---

## Task 2: Auto-detect flip + Stage 0 mapping

**Files:**
- Modify: `crates/mvm-build/src/builder_backend_select.rs` (`auto_detect_default_for` ~91-97; `resolve_stage0_backend_for_choice` ~197-205)
- Test: same file

**Interfaces:**
- Produces: `auto_detect_default_for(true) == BuilderBackendChoice::InHouse`; `resolve_stage0_backend_for_choice(InHouse, _)` returns a libkrun driver.

- [ ] **Step 1: Update failing tests** — replace the body of `auto_detect_default_for_macos_26_apple_silicon_picks_vz` and rename it:

```rust
#[test]
fn auto_detect_default_for_macos_26_apple_silicon_picks_hvf() {
    assert_eq!(auto_detect_default_for(true), BuilderBackendChoice::InHouse);
}
```

(`auto_detect_default_for_everything_else_picks_libkrun` stays as-is.)

- [ ] **Step 2: Run, verify fail** — `cargo test -p mvm-build auto_detect_default_for_macos_26`. Expected: FAIL (returns `Vz`).

- [ ] **Step 3: Flip auto-detect + Stage 0**

`auto_detect_default_for`:

```rust
pub fn auto_detect_default_for(is_macos_26_apple_silicon: bool) -> BuilderBackendChoice {
    if is_macos_26_apple_silicon {
        BuilderBackendChoice::InHouse
    } else {
        BuilderBackendChoice::Libkrun
    }
}
```

Update its doc comment: "macOS 26+ Apple Silicon → HVF builder; everything else → libkrun." In `resolve_stage0_backend_for_choice`, the existing `_ => Box::new(LibkrunBuilderVm::default()...)` arm already covers `InHouse` (hvf Stage 0 is a gap → libkrun, same as Vz) — remove the temporary `unreachable!` arm added in Task 1 so `InHouse` falls into `_`.

- [ ] **Step 4: Run, verify pass** — `cargo test -p mvm-build auto_detect_default_for`. Expected: PASS.

- [ ] **Step 5: Commit** — `feat(build): auto-detect the hvf builder on macOS-26 (Stage 0 stays libkrun)`

---

## Task 3: Vz-free fallback attempt order

**Files:**
- Modify: `crates/mvm-build/src/builder_backend_select.rs` (`builder_attempt_order` ~246-266)
- Test: same file

**Interfaces:**
- Produces: `builder_attempt_order(InHouse, false, _, _) == vec![InHouse, Libkrun]`; `builder_attempt_order(InHouse, true, _, _) == vec![InHouse]`.

- [ ] **Step 1: Write failing tests**

```rust
#[test]
fn attempt_order_hvf_auto_falls_back_to_libkrun_no_vz() {
    use BuilderBackendChoice::*;
    assert_eq!(builder_attempt_order(InHouse, false, false, false), vec![InHouse, Libkrun]);
    assert_eq!(builder_attempt_order(InHouse, false, true, false), vec![InHouse, Libkrun]);
    // Explicit → single attempt, no fallback.
    assert_eq!(builder_attempt_order(InHouse, true, false, false), vec![InHouse]);
}
```

- [ ] **Step 2: Run, verify fail** — `cargo test -p mvm-build attempt_order_hvf_auto`. Expected: FAIL (`InHouse` hits `_ => vec![selected]`).

- [ ] **Step 3: Add the InHouse arm** — in `builder_attempt_order`'s `match selected`, before the `_ =>` arm:

```rust
        BuilderBackendChoice::InHouse => {
            vec![BuilderBackendChoice::InHouse, BuilderBackendChoice::Libkrun]
        }
```

(The `if explicit { return vec![selected]; }` guard above already handles the explicit single-attempt case.)

- [ ] **Step 4: Run, verify pass** — `cargo test -p mvm-build attempt_order`. Expected: PASS (all attempt-order tests).

- [ ] **Step 5: Commit** — `feat(build): hvf builder falls back to libkrun (Vz-free)`

---

## Task 4: Classify hvf VMM-level failures for fallback

**Files:**
- Modify: `crates/mvm-backend/src/builder_runner/hvf_builder.rs` (map `run_build` boot/transport/power-off failures to a VMM-level `BuilderVmError`)
- Modify: `crates/mvm-build/src/builder_backend_select.rs` (`is_builder_vm_level_failure` ~216-221) if a new variant is used
- Verify: `crates/mvm-build/src/builder_vm.rs` (`BuilderVmError` variants)
- Test: `builder_backend_select.rs` tests + `hvf_builder.rs` tests

**Interfaces:**
- Consumes: `is_builder_vm_level_failure(&BuilderVmError) -> bool` (Task-3 file).
- Produces: an hvf boot/transport/timeout failure returns a `BuilderVmError` for which `is_builder_vm_level_failure` is `true`, so `run_with_builder_fallback` retries libkrun.

- [ ] **Step 1: Read `BuilderVmError`** — open `crates/mvm-build/src/builder_vm.rs`, find the `BuilderVmError` enum. Reuse the existing VMM-level variant `SupervisorExited { exit_code, vm_state_dir }` for the "did not power off" / runner-boot case (it is already classified VMM-level). Only add a new variant if none fits; if you add one, extend `is_builder_vm_level_failure` to match it.

- [ ] **Step 2: Write failing test** — in `hvf_builder.rs` tests, assert the power-off-timeout path is VMM-level. Because a real boot can't run in unit tests, test the **classification** in `builder_backend_select.rs` instead:

```rust
#[test]
fn hvf_boot_failure_is_vmm_level_so_fallback_fires() {
    // The variant InHouseBuilderVm::run_build returns for a boot/power-off
    // failure must be classified VMM-level so the auto path retries libkrun.
    assert!(is_builder_vm_level_failure(&BuilderVmError::SupervisorExited {
        exit_code: 1,
        vm_state_dir: "/x".into(),
    }));
}
```

And add an `hvf_builder.rs` unit test asserting the mapping shape (no VM boot needed) — a helper `fn map_runner_failure(msg: String) -> BuilderVmError` returns `SupervisorExited { .. }`:

```rust
#[test]
fn runner_failure_maps_to_vmm_level_error() {
    let e = map_runner_failure("hvf builder VM did not power off".into());
    assert!(matches!(e, BuilderVmError::SupervisorExited { .. }));
}
```

- [ ] **Step 3: Implement the mapping** — in `hvf_builder.rs`, add:

```rust
/// Boot / disk-transport / power-off failures are VMM-level (the builder VM
/// could not run the build), so the auto-detect fallback retries the next
/// backend rather than surfacing a false build error.
fn map_runner_failure(detail: String) -> BuilderVmError {
    BuilderVmError::SupervisorExited { exit_code: 1, vm_state_dir: detail }
}
```

Replace the two `BuilderVmError::ExtractionFailed(...)` returns in `run_build` (the `BuilderRunner::new(...).build(...).map_err(...)` and the `!outcome.stopped` guard) with `map_runner_failure(...)`. Keep the `finalize_flake_job` error (a genuine artifact/build error) unchanged.

- [ ] **Step 4: Run, verify pass** — `cargo test -p mvm-backend -p mvm-build hvf_boot_failure runner_failure_maps`. Expected: PASS.

- [ ] **Step 5: Commit** — `fix(build): classify hvf builder boot failures as VMM-level for fallback`

---

## Task 5: Registration hook so mvm-cli supplies the hvf constructor

**Files:**
- Modify: `crates/mvm-build/src/builder_backend_select.rs` (add `OnceLock` hook + use it in `resolve_builder_backend_with_override` ~168-176)
- Test: same file

**Interfaces:**
- Produces:
  - `pub type InHouseBuilderCtor = Box<dyn Fn() -> Result<Box<dyn BuilderVm>, BuilderVmError> + Send + Sync>;`
  - `pub fn register_hvf_builder(ctor: InHouseBuilderCtor)` — idempotent (first wins).
  - `resolve_builder_backend_with_override(Some(InHouse))` invokes the registered ctor; unregistered → `BuilderVmError::VmmUnavailable { requested: "hvf", reason }`.

- [ ] **Step 1: Write failing test**

```rust
#[test]
fn hvf_uses_registered_ctor() {
    // Registered ctor returns a stub; resolution routes InHouse to it.
    register_hvf_builder(Box::new(|| Ok(Box::new(crate::builder_vm::StubBuilderVm::default()))));
    let _b = resolve_builder_backend_with_override(Some(BuilderBackendChoice::InHouse))
        .expect("registered ctor constructs a builder");
}
```

(If `StubBuilderVm` is not `Default`, construct it however `builder_vm.rs` allows — check its constructor.)

- [ ] **Step 2: Run, verify fail** — `cargo test -p mvm-build hvf_uses_registered_ctor`. Expected: FAIL — `register_hvf_builder` not found / `resolve_builder_backend_with_override` returns non-Result.

- [ ] **Step 3: Add the hook** — near the top of the module:

```rust
use std::sync::OnceLock;

/// Constructor for the hvf builder, registered by the CLI (which can name
/// `InHouseBuilderVm` and resolve its image). `mvm-build` sits below
/// `mvm-backend`, so it cannot construct the hvf builder itself.
pub type InHouseBuilderCtor =
    Box<dyn Fn() -> Result<Box<dyn BuilderVm>, BuilderVmError> + Send + Sync>;

static HVF_CTOR: OnceLock<InHouseBuilderCtor> = OnceLock::new();

/// Register the hvf builder constructor (first registration wins).
pub fn register_hvf_builder(ctor: InHouseBuilderCtor) {
    let _ = HVF_CTOR.set(ctor);
}
```

Change the two constructor factories to return `Result`. Add a fallible variant used by the fallback loop:

```rust
/// As `resolve_builder_backend_with_override` but fallible — the hvf arm
/// depends on a registered constructor.
pub fn try_resolve_builder_backend_with_override(
    flag: Option<BuilderBackendChoice>,
) -> Result<Box<dyn BuilderVm>, BuilderVmError> {
    match resolve_choice_with_override(flag) {
        BuilderBackendChoice::Libkrun => Ok(Box::new(LibkrunBuilderVm::default())),
        BuilderBackendChoice::Vz => Ok(Box::new(VzBuilderVm::new())),
        BuilderBackendChoice::Qemu => Ok(Box::new(QemuBuilderVm::new())),
        BuilderBackendChoice::InHouse => match HVF_CTOR.get() {
            Some(ctor) => ctor(),
            None => Err(BuilderVmError::VmmUnavailable {
                requested: "hvf".into(),
                reason: "hvf builder constructor not registered (CLI startup did not run)"
                    .into(),
            }),
        },
    }
}
```

Keep `resolve_builder_backend_with_override` for the non-hvf callers by delegating and `expect`-ing on the infallible backends, **or** migrate its two callers (`dev_build.rs`, `dev_vz.rs`) to the `try_` form. Preferred: update the `run_with_builder_fallback*` closures in `dev_build.rs:645` and `dev_vz.rs:4672/5091` to call `try_resolve_builder_backend_with_override(Some(choice))?`. Grep first: `rg 'resolve_builder_backend_with_override' crates/`.

- [ ] **Step 4: Run, verify pass** — `cargo test -p mvm-build hvf_uses_registered_ctor` and `cargo build -p mvm-build -p mvm-cli`. Expected: PASS / compiles.

- [ ] **Step 5: Commit** — `feat(build): registration hook for the CLI-supplied hvf builder`

---

## Task 6: In-house builder-image auto-resolver (mvm-cli)

**Files:**
- Create: `crates/mvm-cli/src/commands/build/hvf_builder_image.rs`
- Modify: `crates/mvm-cli/src/commands/build/mod.rs` (add `pub mod hvf_builder_image;`)
- Test: in-file `#[cfg(test)]`

**Interfaces:**
- Consumes: `mvm_build::builder_vm::builder_vm_cache_dir()`; `mvm_build::rootfs_inject::{build_inject_initramfs, InjectBinary}`; `mvm_backend::builder_runner::hvf_builder::InHouseBuilderVm`.
- Produces:
  - `pub fn resolve_hvf_builder_image() -> Result<(PathBuf, PathBuf), BuilderVmError>` returning `(kernel_image, injected_rootfs)`.
  - `fn hvf_image_cache_key(vmlinux: &Path, rootfs: &Path, host_init: &Path) -> String` (sha256 of the three input digests) — pure, unit-tested.

- [ ] **Step 1: Write failing test** — cache key is stable + input-sensitive:

```rust
#[test]
fn cache_key_is_stable_and_input_sensitive() {
    let dir = tempfile::tempdir().unwrap();
    let (k, r, h) = (dir.path().join("k"), dir.path().join("r"), dir.path().join("h"));
    std::fs::write(&k, b"kernelA").unwrap();
    std::fs::write(&r, b"rootfsA").unwrap();
    std::fs::write(&h, b"initA").unwrap();
    let key1 = hvf_image_cache_key(&k, &r, &h);
    let key2 = hvf_image_cache_key(&k, &r, &h);
    assert_eq!(key1, key2, "same inputs → same key");
    std::fs::write(&h, b"initB").unwrap();
    assert_ne!(key1, hvf_image_cache_key(&k, &r, &h), "host-init change → new key");
}
```

- [ ] **Step 2: Run, verify fail** — `cargo test -p mvm-cli cache_key_is_stable`. Expected: FAIL — module/function missing.

- [ ] **Step 3: Implement the resolver** — key + cache + inject. Use `mvm_core::crypto::image_verify::sha256_file` for digests (same hasher the rest of the codebase uses). Cache under `builder_vm_cache_dir().join("hvf").join(&key)`. Resolve the base `vmlinux`+`rootfs.ext4` from `builder_vm_cache_dir().join(std::env::consts::ARCH)` (the same location libkrun/vz use). Ensure the kernel is a raw arm64 `Image` (the cached `vmlinux` is already the boot Image on this arch per libkrun's resolver; if a conversion is needed, defer with a clear error). Inject `mvm-host-vm-init` (locate via the embedded-bin path the other builders use — grep `host_bin_dir` / `mvm-host-vm-init`). On cache hit, return the cached pair without rebuilding.

```rust
use std::path::{Path, PathBuf};
use mvm_build::builder_vm::{builder_vm_cache_dir, BuilderVmError};
use mvm_core::crypto::image_verify::sha256_file;

fn hvf_image_cache_key(vmlinux: &Path, rootfs: &Path, host_init: &Path) -> String {
    let mut h = sha2::Sha256::new();
    for p in [vmlinux, rootfs, host_init] {
        h.update(sha256_file(p).unwrap_or_default().as_bytes());
    }
    hex::encode(h.finalize())
}

pub fn resolve_hvf_builder_image() -> Result<(PathBuf, PathBuf), BuilderVmError> {
    let arch_dir = builder_vm_cache_dir().join(std::env::consts::ARCH);
    let vmlinux = arch_dir.join("vmlinux");
    let base_rootfs = arch_dir.join("rootfs.ext4");
    // NOTE: producing arch_dir if absent reuses the existing builder-vm image
    // resolution (grep libkrun_builder's resolver); this fn assumes it present
    // and returns VmmUnavailable with an actionable message if not.
    let host_init = locate_host_vm_init()?; // grep: how other builders find mvm-host-vm-init
    let key = hvf_image_cache_key(&vmlinux, &base_rootfs, &host_init);
    let out_dir = builder_vm_cache_dir().join("hvf").join(&key);
    let injected_rootfs = out_dir.join("rootfs.ext4");
    let kernel = out_dir.join("Image");
    if injected_rootfs.is_file() && kernel.is_file() {
        return Ok((kernel, injected_rootfs)); // warm
    }
    std::fs::create_dir_all(&out_dir).map_err(|e| BuilderVmError::VmmUnavailable {
        requested: "hvf".into(),
        reason: format!("create {}: {e}", out_dir.display()),
    })?;
    // ... copy vmlinux → kernel; rootfs_inject mvm-host-vm-init into base_rootfs → injected_rootfs ...
    Ok((kernel, injected_rootfs))
}
```

**Bake mechanism (corrected):** applying the inject requires booting a VM (macOS can't mount ext4 host-side), but the patcher VM is **vsock-less** and therefore NOT gated on #1401. Use the ready-made primitive `mvm_backend::builder_runner::inject_host_binaries(&InjectRequest { kernel, base_rootfs, out_rootfs, work_dir, patcher, binaries })` (see `crates/mvm-backend/src/builder_runner/inject.rs`). It copies `base_rootfs → out_rootfs`, builds the patcher initramfs, boots the HVF supervisor with `vsock: false` on the writable rootfs disk, and blocks until poweroff. So the resolver's `// ...` step is:

```rust
use mvm_backend::builder_runner::inject::{inject_host_binaries, InjectRequest};
use mvm_build::rootfs_inject::InjectBinary;
// kernel: byte-copy the base HVF Image into out_dir/Image (or symlink if the base is already a raw arm64 Image)
std::fs::copy(&base_image, &kernel)?;
let patcher = std::fs::read(&patcher_bin)?;      // the mvm-rootfs-patcher static musl bin
let host_init = std::fs::read(&host_init_bin)?;  // the mvm-host-vm-init static musl bin
inject_host_binaries(&InjectRequest {
    kernel: &kernel,
    base_rootfs: &base_rootfs,
    out_rootfs: &injected_rootfs,
    work_dir: &out_dir.join("work"),
    patcher: &patcher,
    binaries: &[InjectBinary { name: "mvm-host-vm-init", install_path: "/sbin/mvm-host-vm-init", mode: 0o755, data: &host_init }],
}).map_err(|e| BuilderVmError::InHouseVmmFailed { detail: format!("bake hvf builder rootfs: {e}") })?;
```

(Confirm `InjectBinary`'s exact field names in `rootfs_inject.rs` — adapt if they differ.) Locate the `mvm-rootfs-patcher` + `mvm-host-vm-init` static bins at runtime via the embedded-host-binary extractor — grep `host_binaries::extract::ensure_extracted_for_boot` (used in `dev_vz.rs`), which returns a `host_bin_dir`; confirm both bins are embedded (grep `mvm-rootfs-patcher` in `crates/mvm-cli/build.rs`). If `mvm-rootfs-patcher` is NOT embedded, report DONE_WITH_CONCERNS naming that gap — the resolver's bake needs it. On any bake failure return `BuilderVmError::InHouseVmmFailed { detail }` so the auto-detect fallback (built in Dispatch 1/2) retries libkrun. The `HVF Image` kernel: the cached `builder-vm/<arch>/vmlinux` is already a raw arm64 boot Image on this arch (per libkrun's resolver); use it directly and only error if `file(1)`-style detection shows ELF.

- [ ] **Step 4: Run, verify pass** — `cargo test -p mvm-cli cache_key_is_stable`. Expected: PASS. (The full resolve path is exercised in Task 8.)

- [ ] **Step 5: Commit** — `feat(cli): hvf builder-image auto-resolver (hash-keyed cache)`

---

## Task 7: CLI wiring — register hook, accept flag, doctor + docs

**Files:**
- Modify: `crates/mvm-cli/src/commands/mod.rs` (`--builder` possible values ~48-52; register hook near startup, before dispatch ~190-200)
- Modify: `crates/mvm-cli/src/doctor.rs` (builder-backend line ~1594-1640: add `InHouse` arm)
- Modify: `CLAUDE.md` (Builder backend selection section: macOS-26 default is hvf)
- Test: `crates/mvm-cli/src/commands/tests.rs` (`--builder` help lists hvf)

**Interfaces:**
- Consumes: `mvm_build::builder_backend_select::register_hvf_builder`; `resolve_hvf_builder_image` (Task 6); `InHouseBuilderVm::new` (Task 4 file).

- [ ] **Step 1: Write failing test** — in `commands/tests.rs`, near the existing `--builder` help test:

```rust
#[test]
fn builder_flag_lists_hvf() {
    let help = /* render the same top-level help the sibling test uses */;
    assert!(help.contains("hvf"), "expected --builder to accept hvf");
}
```

- [ ] **Step 2: Run, verify fail** — `cargo test -p mvm-cli builder_flag_lists_hvf`. Expected: FAIL.

- [ ] **Step 3a: Accept the flag** — find the `#[arg(...)]` on `pub builder: Option<String>` (mod.rs:52). Add `hvf` to its `PossibleValuesParser` / possible-values list so clap accepts + advertises it. (Grep `value_parser` / `PossibleValuesParser` near the field.)

- [ ] **Step 3b: Register the hook at startup** — in the dispatch fn (mod.rs, near line 196 where `--builder` folds to env), before the `match cli.command`, register the hvf constructor:

```rust
mvm_build::builder_backend_select::register_hvf_builder(Box::new(|| {
    let (kernel, rootfs) =
        crate::commands::build::hvf_builder_image::resolve_hvf_builder_image()?;
    Ok(Box::new(
        mvm_backend::builder_runner::hvf_builder::InHouseBuilderVm::new(kernel, rootfs),
    ) as Box<dyn mvm_build::builder_vm::BuilderVm>)
}));
```

- [ ] **Step 3c: doctor arm** — in `doctor.rs` builder-backend reporting (~1621-1635 has `Libkrun`/`Vz`/`Qemu` arms), add:

```rust
        BuilderBackendChoice::InHouse => {
            // HVF builder; macOS-26 default
        }
```

Match the surrounding arms' structure (they format a description string). Report "hvf — <source> — <availability>".

- [ ] **Step 3d: CLAUDE.md** — in "Builder backend selection", change the macOS-26 default from Vz to the HVF builder; note Vz is opt-in/deprecated and the `[hvf, libkrun]` fallback. Keep it terse.

- [ ] **Step 4: Run, verify pass** — `cargo test -p mvm-cli builder_flag_lists_hvf` + `cargo build -p mvm-cli`. Expected: PASS.

- [ ] **Step 5: Commit** — `feat(cli): auto-detect + --builder hvf wiring, doctor + docs`

---

## Task 8: Fallback-safety test + gated live e2e

**Files:**
- Test: `crates/mvm-build/src/builder_backend_select.rs` (fallback-keeps-builds-working, pure) + a gated e2e note.

**Interfaces:**
- Consumes: `run_with_builder_fallback` / `try_resolve_builder_backend_with_override`.

- [ ] **Step 1: Write the fallback-safety test** — a failing hvf attempt on the auto path retries libkrun and succeeds:

```rust
#[test]
fn auto_hvf_failure_falls_back_to_libkrun_and_succeeds() {
    use std::cell::RefCell;
    let scratch = tempfile::TempDir::new().unwrap();
    let mut env = TestEnv::new();
    env.set("MVM_CACHE_DIR", scratch.path().join(".cache"));
    let calls = RefCell::new(Vec::new());
    // Drive the order directly (host-agnostic): hvf fails VMM-level, libkrun ok.
    let order = builder_attempt_order(BuilderBackendChoice::InHouse, false, false, false);
    assert_eq!(order, vec![BuilderBackendChoice::InHouse, BuilderBackendChoice::Libkrun]);
    let result = run_with_builder_fallback(BuilderBackendChoice::InHouse, false, |c| {
        calls.borrow_mut().push(c);
        match c {
            BuilderBackendChoice::Libkrun => Ok(()),
            _ => Err(BuilderVmError::SupervisorExited { exit_code: 1, vm_state_dir: "/x".into() }),
        }
    });
    assert!(result.is_ok());
    assert_eq!(*calls.borrow(), vec![BuilderBackendChoice::InHouse, BuilderBackendChoice::Libkrun]);
}
```

- [ ] **Step 2: Run, verify pass** — `cargo test -p mvm-build auto_hvf_failure_falls_back`. Expected: PASS (logic already in place from Tasks 3–4). If it fails, the classification/order is wrong — fix in the owning task.

- [ ] **Step 3: Add the gated live-e2e note** — add a `#[test] #[ignore]` stub documenting the manual proof (it needs a real macOS-26 host + a working hvf builder; wire it live once #1401's `fix/plan-214-hvf-vsock-io-thread` lands on main):

```rust
#[test]
#[ignore = "live: needs macOS-26 + working hvf builder (gated on #1401 vsock fix landing)"]
fn live_hvf_builds_sleeper_flake() {
    // Manual: `mvmctl machine run --flake examples/sleeper` on macOS-26 with no
    // flags must auto-detect the hvf builder and produce artifacts.
}
```

- [ ] **Step 4: Run full gate** — `cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo nextest run -p mvm-build -p mvm-cli && cargo test -p mvm-build -p mvm-cli --doc`. Expected: all green.

- [ ] **Step 5: Commit** — `test(build): hvf auto-detect fallback safety + gated live e2e`

---

## Self-Review

**Spec coverage:** Unit 1 → Tasks 1–2; Unit 1b → Tasks 3–4; Unit 2 (inversion) → Task 5 (registration hook refinement); Unit 3 (resolver) → Task 6; Unit 4 (CLI/doctor/docs) → Task 7; Unit 5 (proof) → Task 8. Non-goals (Vz deletion, workload `--hypervisor` flip, Install pipeline) are untouched. ✓

**Placeholder scan:** Task 6's `// ...` (rootfs_inject call) and `locate_host_vm_init` are the only under-specified spots — flagged with exact grep targets (`examples/hvf-rootfs-inject.rs`, `host_bin_dir`) because their exact API is in files the implementer opens for that task; not a silent TODO. Task 7 Step 3a/3c reference clap/doctor sites by line with grep anchors. Acceptable for execution; no bare "add error handling".

**Type consistency:** `BuilderBackendChoice::InHouse`, `register_hvf_builder`, `try_resolve_builder_backend_with_override`, `resolve_hvf_builder_image`, `InHouseBuilderVm::new(kernel, rootfs)`, `map_runner_failure` — used consistently across Tasks 1/3/4/5/6/7. ✓
