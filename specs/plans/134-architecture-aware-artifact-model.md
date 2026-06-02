# Plan 134 — Architecture-aware microVM artifact model (slice 1)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a typed, architecture- and backend-aware artifact model — `GuestArch`, a data-driven `BackendCompat` matrix, a build `ArtifactManifest`, a static validator, and a `mvmctl artifact` CLI — layered over the existing (CI-gated, claim-backed) builders, without a new crate.

**Architecture:** Option **B** from the design spec (`docs/superpowers/specs/2026-06-01-architecture-aware-artifact-model-design.md`): extend existing crates in place. Pure types (`GuestArch`, `KernelFormat`) go to `mvm-core`. Backend identity + capabilities (`MicrovmBackend`, `RootfsFormat`, `NetworkingModel`, `BackendCompat`) and the whole `artifacts` module (traits, spec/artifact types, `ArtifactManifest`, `NixMicrovmBuilder`, `FirecrackerConfigWriter`, `ArtifactValidator`) go to `mvm-backend` — which **already depends on `mvm-build`** (verified: `crates/mvm-backend/Cargo.toml:44`), so the Nix adapter can call `BuilderVm` with no dependency cycle. The CLI lands in `mvm-cli`.

**Tech Stack:** Rust; reuse in-tree crates only — `serde`/`serde_json`, `thiserror`+`anyhow`, `sha2`, `uuid`, `ext4-view`. **No new dependencies in this slice** (`arcbox_ext4`, QEMU/vfkit writers, dynamic smoke-tests, `microvm.nix` are deferred to their own plans).

**Prereqs:** Spec approved. Module homes pinned (above). Branch `feat/artifact-model`.

**Why a dedicated plan:** the typed model touches three crates and renames a load-bearing manifest; it deserves its own sequenced, test-first cycle separate from the runtime/builder work.

---

## Phase 0 — Pinned decisions (no code)

- [ ] **Step 1:** Confirm dep direction once more before starting: `rg -n "mvm-build" crates/mvm-backend/Cargo.toml` shows the dep exists. Therefore: `artifacts` module + `BackendCompat` live in **`mvm-backend`**; `GuestArch`/`KernelFormat` in **`mvm-core`**; CLI in **`mvm-cli`**. No new crate.

## Phase A — Typed core (`mvm-core`)

### Task A1: `GuestArch`

**Files:**
- Create: `crates/mvm-core/src/arch.rs`
- Modify: `crates/mvm-core/src/lib.rs` (add `pub mod arch;`)

- [ ] **Step 1: Write failing tests** in `crates/mvm-core/src/arch.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn aliases_normalize() {
        assert_eq!("x86_64".parse::<GuestArch>().unwrap(), GuestArch::X86_64);
        assert_eq!("amd64".parse::<GuestArch>().unwrap(), GuestArch::X86_64);
        assert_eq!("aarch64".parse::<GuestArch>().unwrap(), GuestArch::Aarch64);
        assert_eq!("arm64".parse::<GuestArch>().unwrap(), GuestArch::Aarch64);
        assert!("riscv64".parse::<GuestArch>().is_err());
    }
    #[test]
    fn nix_system_strings() {
        assert_eq!(GuestArch::X86_64.nix_system(), "x86_64-linux");
        assert_eq!(GuestArch::Aarch64.nix_system(), "aarch64-linux");
    }
    #[test]
    fn serde_roundtrips_lowercase() {
        let j = serde_json::to_string(&GuestArch::Aarch64).unwrap();
        assert_eq!(j, "\"aarch64\"");
        assert_eq!(serde_json::from_str::<GuestArch>(&j).unwrap(), GuestArch::Aarch64);
    }
}
```

- [ ] **Step 2:** `cargo test -p mvm-core arch::` → FAIL (type missing).
- [ ] **Step 3: Implement** in the same file:

```rust
//! Canonical guest CPU architecture. `arm64` canonicalizes to
//! `aarch64`; `amd64` to `x86_64`. This is the single arch type —
//! it replaces `mvm-build`'s `runtime_overlay::Arch` and the stringly
//! `target_arch` fields.
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuestArch {
    X86_64,
    Aarch64,
}

impl GuestArch {
    /// The Nix `system` string (`<arch>-linux`) used for flake attrs.
    pub fn nix_system(self) -> &'static str {
        match self {
            GuestArch::X86_64 => "x86_64-linux",
            GuestArch::Aarch64 => "aarch64-linux",
        }
    }
    /// The host's arch at compile time. Replaces `host_system_linux()`.
    pub const fn host() -> Self {
        #[cfg(target_arch = "x86_64")]
        { GuestArch::X86_64 }
        #[cfg(not(target_arch = "x86_64"))]
        { GuestArch::Aarch64 }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("unsupported guest architecture: {0:?} (expected one of: x86_64/amd64, aarch64/arm64)")]
pub struct UnknownArch(pub String);

impl FromStr for GuestArch {
    type Err = UnknownArch;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Accept bare arch or `<arch>-linux`.
        let base = s.split('-').next().unwrap_or(s).trim().to_ascii_lowercase();
        match base.as_str() {
            "x86_64" | "amd64" | "x64" => Ok(GuestArch::X86_64),
            "aarch64" | "arm64" => Ok(GuestArch::Aarch64),
            _ => Err(UnknownArch(s.to_string())),
        }
    }
}

impl std::fmt::Display for GuestArch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            GuestArch::X86_64 => "x86_64",
            GuestArch::Aarch64 => "aarch64",
        })
    }
}
```

Add `pub mod arch;` to `crates/mvm-core/src/lib.rs` and confirm `thiserror` is a `mvm-core` dep (`rg thiserror crates/mvm-core/Cargo.toml`; it is).

- [ ] **Step 4:** `cargo test -p mvm-core arch::` → PASS.
- [ ] **Step 5: Commit** `feat(core): add canonical GuestArch enum`.

### Task A2: Move `KernelFormat` to `mvm-core`, extend with `Image`/`Pe`

**Files:**
- Create: `crates/mvm-core/src/kernel_format.rs` (+ `pub mod kernel_format;` in `lib.rs`)
- Modify: `crates/mvm-libkrun/src/sys.rs` (delete local enum; import from core; map new variants)
- Modify: `crates/mvm-libkrun/src/lib.rs` (re-export from core or update the `pub use`)

- [ ] **Step 1: Implement** `crates/mvm-core/src/kernel_format.rs` (carries the existing libkrun variants + the uncompressed `Image`/`Pe` the model needs):

```rust
//! Backend-neutral kernel artifact format. Backends accept a subset
//! (see `mvm_backend::BackendCompat`); libkrun maps the ones it can
//! load to its FFI constants.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KernelFormat {
    Raw,
    /// Uncompressed ELF `vmlinux` (Firecracker x86_64, libkrun).
    Elf,
    /// Uncompressed arm64 `Image` (Firecracker aarch64).
    Image,
    ImageGz,
    ImageBz2,
    ImageZstd,
    /// Uncompressed PE.
    Pe,
    PeGz,
}
```

- [ ] **Step 2:** In `crates/mvm-libkrun/src/sys.rs`, delete the local `pub enum KernelFormat { … }`, add `use mvm_core::kernel_format::KernelFormat;`, and make the FFI mapping return an error for formats libkrun can't load (the new `Image`/`Pe` have no `KRUN_KERNEL_FORMAT_*`):

```rust
fn to_krun_format(f: KernelFormat) -> Result<u32, Error> {
    Ok(match f {
        KernelFormat::Raw => bindings::KRUN_KERNEL_FORMAT_RAW,
        KernelFormat::Elf => bindings::KRUN_KERNEL_FORMAT_ELF,
        KernelFormat::PeGz => bindings::KRUN_KERNEL_FORMAT_PE_GZ,
        KernelFormat::ImageBz2 => bindings::KRUN_KERNEL_FORMAT_IMAGE_BZ2,
        KernelFormat::ImageGz => bindings::KRUN_KERNEL_FORMAT_IMAGE_GZ,
        KernelFormat::ImageZstd => bindings::KRUN_KERNEL_FORMAT_IMAGE_ZSTD,
        KernelFormat::Image | KernelFormat::Pe => {
            return Err(Error::Init {
                context: format!("libkrun cannot load uncompressed {f:?}; \
                    use the bundled kernel or a compressed format"),
            });
        }
    })
}
```

(Replace the existing inline `match` that produced the constant with a call to this fn; adjust the one call site in `sys.rs`. Update `crates/mvm-libkrun/src/lib.rs`'s `pub use` to re-export `mvm_core::kernel_format::KernelFormat`.)

- [ ] **Step 3:** `cargo build -p mvm-core -p mvm-libkrun` → builds. `cargo test -p mvm-libkrun` → PASS.
- [ ] **Step 4: Commit** `refactor(core): move+extend KernelFormat into mvm-core`.

### Task A3: Migrate `mvm-build`'s `Arch` + stringly `target_arch` to `GuestArch`

**Files:**
- Modify: `crates/mvm-build/src/runtime_overlay.rs:66-90` (delete `Arch`; use `GuestArch`)
- Modify: `crates/mvm-build/src/packed_artifact.rs:150,184,251` (`target_arch: String` → `GuestArch`)
- Modify: call sites surfaced by the compiler

- [ ] **Step 1:** Delete `pub enum Arch { Aarch64, X86_64 }` and its `host()` from `runtime_overlay.rs`; replace usages with `mvm_core::arch::GuestArch` (`Arch::Aarch64` → `GuestArch::Aarch64`, `Arch::host()` → `GuestArch::host()`, the `=> "aarch64-linux"` match → `.nix_system()`).
- [ ] **Step 2:** Change `packed_artifact`'s `target_arch: String` fields to `target_arch: GuestArch`; update the `"aarch64"`-literal test fixtures to `GuestArch::Aarch64`; serde now emits `"aarch64"` (snake_case) — keep wire compatibility by confirming the JSON string is unchanged (`"aarch64"`).
- [ ] **Step 3:** `cargo build -p mvm-build 2>&1` and fix each reported call site (mechanical). Then `cargo test -p mvm-build` → PASS.
- [ ] **Step 4: Commit** `refactor(build): migrate Arch + target_arch to GuestArch`.

## Phase B — Backend compatibility (`mvm-backend`)

### Task B1: `MicrovmBackend`, `RootfsFormat`, `NetworkingModel`

**Files:**
- Create: `crates/mvm-backend/src/compat.rs` (+ `pub mod compat;` in `crates/mvm-backend/src/lib.rs`)

- [ ] **Step 1: Implement** the enums:

```rust
use mvm_core::arch::GuestArch;
use mvm_core::kernel_format::KernelFormat;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MicrovmBackend {
    Firecracker, Libkrun, Vz, AppleContainer, CloudHypervisor, Docker, Qemu, Vfkit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RootfsFormat { Ext4, InitramfsCpioGz, Squashfs, Raw }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkingModel { Tap, Gvproxy, Passt, UserModeVirtio, None }
```

- [ ] **Step 2: Commit** `feat(backend): MicrovmBackend + RootfsFormat + NetworkingModel`.

### Task B2: `BackendCompat` matrix + `compat()`

**Files:** Modify `crates/mvm-backend/src/compat.rs`

- [ ] **Step 1: Write failing tests:**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use GuestArch::*;
    #[test]
    fn firecracker_kernel_formats_are_arch_specific() {
        let c = compat(MicrovmBackend::Firecracker);
        assert!(kernel_format_ok(c, X86_64, KernelFormat::Elf));
        assert!(!kernel_format_ok(c, X86_64, KernelFormat::Image));
        assert!(kernel_format_ok(c, Aarch64, KernelFormat::Image));
        assert!(!kernel_format_ok(c, Aarch64, KernelFormat::Elf));
    }
    #[test]
    fn firecracker_rejects_unsupported_rootfs() {
        let c = compat(MicrovmBackend::Firecracker);
        assert!(c.rootfs_formats.contains(&RootfsFormat::Ext4));
        assert!(!c.rootfs_formats.contains(&RootfsFormat::Squashfs));
    }
    #[test]
    fn every_backend_has_a_row() {
        for b in [MicrovmBackend::Firecracker, MicrovmBackend::Libkrun,
                  MicrovmBackend::Vz, MicrovmBackend::AppleContainer,
                  MicrovmBackend::CloudHypervisor, MicrovmBackend::Docker,
                  MicrovmBackend::Qemu, MicrovmBackend::Vfkit] {
            assert_eq!(compat(b).backend, b);
        }
    }
}
```

- [ ] **Step 2:** `cargo test -p mvm-backend compat::` → FAIL.
- [ ] **Step 3: Implement** the struct + the `kernel_format_ok` helper + the static rows. Show Firecracker + Libkrun fully; the remaining rows follow the same shape (fill each with that backend's real capabilities — Vz/AppleContainer aarch64-only, CloudHypervisor both, Qemu/Vfkit declared-but-unimplemented):

```rust
pub struct BackendCompat {
    pub backend: MicrovmBackend,
    pub guest_arches: &'static [GuestArch],
    pub kernel_formats: &'static [(GuestArch, &'static [KernelFormat])],
    pub rootfs_formats: &'static [RootfsFormat],
    pub required_boot_args: &'static [&'static str],
    pub supports_snapshots: bool,
    pub supports_jailer: bool,
    pub networking: NetworkingModel,
}

/// Is `fmt` an accepted kernel format for `arch` on this backend?
pub fn kernel_format_ok(c: &BackendCompat, arch: GuestArch, fmt: KernelFormat) -> bool {
    c.kernel_formats.iter()
        .find(|(a, _)| *a == arch)
        .map(|(_, fmts)| fmts.contains(&fmt))
        .unwrap_or(false)
}

use GuestArch::*;
use KernelFormat as K;
use RootfsFormat as R;

static FIRECRACKER: BackendCompat = BackendCompat {
    backend: MicrovmBackend::Firecracker,
    guest_arches: &[X86_64, Aarch64],
    kernel_formats: &[(X86_64, &[K::Elf]), (Aarch64, &[K::Image])],
    rootfs_formats: &[R::Ext4, R::InitramfsCpioGz],
    required_boot_args: &["console=ttyS0", "reboot=k", "panic=1"],
    supports_snapshots: true,
    supports_jailer: true,
    networking: NetworkingModel::Tap,
};

static LIBKRUN: BackendCompat = BackendCompat {
    backend: MicrovmBackend::Libkrun,
    guest_arches: &[X86_64, Aarch64],
    kernel_formats: &[(X86_64, &[K::Elf, K::ImageGz, K::ImageZstd]),
                      (Aarch64, &[K::Elf, K::ImageGz, K::ImageZstd])],
    rootfs_formats: &[R::Ext4],
    required_boot_args: &["console=hvc0"],
    supports_snapshots: false,
    supports_jailer: false,
    networking: NetworkingModel::Gvproxy,
};
// VZ, APPLE_CONTAINER, CLOUD_HYPERVISOR, DOCKER, QEMU, VFKIT: same shape,
// each populated with that backend's real capabilities.

pub fn compat(b: MicrovmBackend) -> &'static BackendCompat {
    match b {
        MicrovmBackend::Firecracker => &FIRECRACKER,
        MicrovmBackend::Libkrun => &LIBKRUN,
        MicrovmBackend::Vz => &VZ,
        MicrovmBackend::AppleContainer => &APPLE_CONTAINER,
        MicrovmBackend::CloudHypervisor => &CLOUD_HYPERVISOR,
        MicrovmBackend::Docker => &DOCKER,
        MicrovmBackend::Qemu => &QEMU,
        MicrovmBackend::Vfkit => &VFKIT,
    }
}
```

- [ ] **Step 4:** `cargo test -p mvm-backend compat::` → PASS.
- [ ] **Step 5: Commit** `feat(backend): data-driven BackendCompat matrix`.

## Phase C — Artifacts module: types, traits, manifest (`mvm-backend`)

### Task C1: Spec + artifact types

**Files:** Create `crates/mvm-backend/src/artifacts/mod.rs`, `artifacts/spec.rs`, `artifacts/artifact.rs` (+ `pub mod artifacts;` in lib.rs)

- [ ] **Step 1: Implement** `spec.rs` (`KernelSpec`/`RootfsSpec`/`MicrovmBuildSpec` + `KernelSource`/`RootfsSource` per the spec's shapes, using `std::path::PathBuf`, `GuestArch`, `MicrovmBackend`, `KernelFormat`, `RootfsFormat`) and `artifact.rs` (`KernelArtifact { path, format, hash, version: Option<String> }`, `RootfsArtifact { path, format, hash, size_bytes }`, `MicrovmArtifact { id, arch, backend, kernel, rootfs, boot_args, config_path: Option<PathBuf> }`, `BackendConfigArtifact { backend, path }`, `ValidationReport { ok: bool, checks: Vec<ValidationCheck> }`, `ValidationCheck { name: String, ok: bool, detail: String }`). All `#[derive(Serialize, Deserialize)]`.
- [ ] **Step 2:** `cargo build -p mvm-backend` → builds. **Commit** `feat(backend): artifact + spec types`.

### Task C2: Trait surface

**Files:** Create `crates/mvm-backend/src/artifacts/traits.rs`

- [ ] **Step 1: Implement** the five traits exactly as in the spec (`KernelBuilder`, `RootfsBuilder`, `MicrovmArtifactBuilder`, `BackendConfigWriter`, `ArtifactValidator`), each returning `Result<_, ArtifactError>`.
- [ ] **Step 2:** Define `ArtifactError` (`thiserror`) with variants for incompatibility (carries `backend`, `arch`, `expected`/`got` so the message reads `Cannot build {backend} artifact for arch={arch}: kernel format {got:?} not accepted; expected one of {expected:?}`), `Io`, `HashMismatch`, `NotImplemented { backend }`.
- [ ] **Step 3:** `cargo build -p mvm-backend` → builds. **Commit** `feat(backend): artifact builder/validator/config traits`.

### Task C3: Build-level `ArtifactManifest`

**Files:** Create `crates/mvm-backend/src/artifacts/manifest.rs`

- [ ] **Step 1: Write failing test** (serde roundtrip + `write_to_dir`/`read_from_dir` to `manifest.json`):

```rust
#[test]
fn manifest_roundtrips() {
    let m = fixture_manifest();
    let dir = tempfile::tempdir().unwrap();
    let p = m.write_to_dir(dir.path()).unwrap();
    assert_eq!(p, dir.path().join("manifest.json"));
    assert_eq!(ArtifactManifest::read_from_dir(dir.path()).unwrap().unwrap(), m);
}
```

- [ ] **Step 2:** `cargo test -p mvm-backend manifest` → FAIL.
- [ ] **Step 3: Implement** `ArtifactManifest` with the fields from spec §4 (`artifact_id: uuid::Uuid`, `build_id`, `tenant_id: Option<String>`, `arch: GuestArch`, `backend: MicrovmBackend`, `kernel: KernelArtifact`-derived `{path, format, hash, version}`, `rootfs: {path, format, hash, size}`, `config_path: Option<PathBuf>`, `provenance: Option<Provenance>` with `flake_ref`/`lock_hash`, `builder_version: String`, `timestamp_unix: u64` (caller-supplied), `validation: Option<ValidationReport>`), `MANIFEST_FILENAME = "manifest.json"`, `write_to_dir`/`read_from_dir` mirroring `mvm_build::builder_vm::GuestSidecar`'s pattern (post Task C4). Hashing helper uses `sha2::Sha256` (reuse the existing `.mvm-artifacts.sha256` logic).
- [ ] **Step 4:** `cargo test -p mvm-backend manifest` → PASS. **Commit** `feat(backend): build-level ArtifactManifest`.

### Task C4: Rename mkGuest sidecar `ArtifactManifest` → `GuestSidecar`

**Files:**
- Modify: `crates/mvm-build/src/builder_vm.rs` (rename the struct + `ArtifactManifest::path_in`/`write_to_dir`/`read_from_dir`/`is_overlay_aware`; `SIDECAR_FILENAME` stays)
- Modify: call sites — `admit_overlay_aware` (same file), `crates/mvm/src/vm/runtime_meta.rs`, and the `mvm-backend` W2 gate consumer

- [ ] **Step 1:** Rename `pub struct ArtifactManifest` → `pub struct GuestSidecar` in `builder_vm.rs` and every method/`impl`. Update the doc to say "mkGuest runtime sidecar."
- [ ] **Step 2:** `cargo build --workspace 2>&1` and fix each call site the compiler flags (mechanical rename; no behavior change). Update the existing sidecar tests' type name.
- [ ] **Step 3:** `cargo test -p mvm-build -p mvm` → PASS. **Commit** `refactor: rename mkGuest sidecar ArtifactManifest -> GuestSidecar`.

## Phase D — Implementations (`mvm-backend`)

### Task D1: Static `ArtifactValidator`

**Files:** Create `crates/mvm-backend/src/artifacts/validate.rs`

- [ ] **Step 1: Write failing tests:** (a) a `MicrovmArtifact` with `(Firecracker, X86_64, Elf, Ext4)` and matching hashes validates `ok=true`; (b) the same with `KernelFormat::Image` fails with an incompatibility check naming the expected set; (c) a rootfs missing `/sbin/init` (real ext4 fixture, Linux-gated, reusing the Phase-A `mke2fs_from_dir` pattern) fails the init check.
- [ ] **Step 2:** `cargo test -p mvm-backend validate` → FAIL.
- [ ] **Step 3: Implement** `StaticValidator` impl of `ArtifactValidator` running the seven checks from spec §5 in order: file existence; `sha2` hash match vs manifest; `compat()` arch support; `kernel_format_ok`; rootfs-format membership; required-boot-args present in `artifact.boot_args`; and init-presence via `ext4_view::Ext4::load_from_path(rootfs).exists("/sbin/init")` (generalize from `verify_stage0_rootfs_has_init`). Build a `ValidationReport` accumulating each `ValidationCheck`; `ok = all checks ok`.
- [ ] **Step 4:** `cargo test -p mvm-backend validate` → PASS. **Commit** `feat(backend): static ArtifactValidator over the compat matrix + ext4-view`.

### Task D2: `FirecrackerConfigWriter`

**Files:** Create `crates/mvm-backend/src/artifacts/config/firecracker.rs`

- [ ] **Step 1: Write a snapshot test:** given a fixed `MicrovmArtifact`, `write_config` emits Firecracker JSON with `boot-source` (kernel_image_path + boot_args), a `drives` entry for the rootfs (`is_root_device: true`, `is_read_only` from spec), `machine-config`, and (when set) `vsock` — assert the serialized JSON equals a checked-in expected string.
- [ ] **Step 2:** `cargo test -p mvm-backend firecracker_config` → FAIL.
- [ ] **Step 3: Implement** `FirecrackerConfigWriter` building a `serde_json::Value` (or typed structs mirroring `mvm-backend`'s existing `FirecrackerConfig`/`FlakeRunConfig` where they fit) and writing `firecracker.json` next to the artifact; return `BackendConfigArtifact`. Paths come from the artifact, not hardcoded.
- [ ] **Step 4:** `cargo test -p mvm-backend firecracker_config` → PASS. **Commit** `feat(backend): FirecrackerConfigWriter from ArtifactManifest`.

### Task D3: `NixMicrovmBuilder` adapter

**Files:** Create `crates/mvm-backend/src/artifacts/builders/nix.rs`

- [ ] **Step 1: Write a test** with a stub `BuilderVm` (reuse `mvm_build::builder_vm::StubBuilderVm` shape or a local mock) returning a `BuilderArtifacts::Image { rootfs_path, kernel_path, revision_hash, .. }`, and assert `NixMicrovmBuilder::build_microvm` maps it into a `MicrovmArtifact` with the right arch/backend/format and writes a `manifest.json`.
- [ ] **Step 2:** `cargo test -p mvm-backend nix_builder` → FAIL.
- [ ] **Step 3: Implement** `NixMicrovmBuilder` (`impl MicrovmArtifactBuilder`): translate `MicrovmBuildSpec` → a `BuilderJob::Flake`, call the injected `&dyn mvm_build::builder_vm::BuilderVm`, hash the resulting kernel+rootfs (`sha2`), infer `KernelFormat` from the artifact (ELF magic / arm64 `Image` magic / extension), assemble `MicrovmArtifact`, run the `StaticValidator`, embed the `ValidationReport`, and `write_to_dir` the `ArtifactManifest`.
- [ ] **Step 4:** `cargo test -p mvm-backend nix_builder` → PASS. **Commit** `feat(backend): NixMicrovmBuilder adapter over BuilderVm`.

## Phase E — CLI (`mvm-cli`)

### Task E1: `mvmctl artifact inspect|validate|config`

**Files:**
- Create: `crates/mvm-cli/src/commands/artifact.rs` (+ wire into the clap command tree + `commands/mod.rs`)

- [ ] **Step 1:** Add a clap `Artifact` subcommand with `Inspect { id }`, `Validate { id }`, `Config { id, --backend <MicrovmBackend> }`, and a thin `Build { --arch, --backend, --flake }` that delegates to the existing build pipeline. Resolve `<id>` to the artifact dir under the artifacts root (`mvm_core::config` dir + `artifacts/<id>/`).
- [ ] **Step 2: Implement** the handlers: `inspect` reads + pretty-prints `ArtifactManifest`; `validate` loads the `MicrovmArtifact` and runs `StaticValidator`, printing the `ValidationReport` and exiting nonzero on failure; `config` runs `FirecrackerConfigWriter` and prints the written path. Follow the existing `commands/` clap + `ui::` conventions.
- [ ] **Step 3:** Add a `tests/cli.rs` case asserting `mvmctl artifact --help` lists the three subcommands (mirrors existing CLI help tests).
- [ ] **Step 4:** `cargo test -p mvm-cli artifact` → PASS. **Commit** `feat(cli): mvmctl artifact inspect|validate|config`.

## Phase F — Docs + verification

### Task F1: "How to add an arch or backend" doc

**Files:** Create `public/src/content/docs/contributing/adding-an-arch-or-backend.md`

- [ ] **Step 1:** Document the recipe: add a `GuestArch` variant (+ `from_str` alias + `nix_system`); add a `MicrovmBackend` variant + a `BackendCompat` static row + `compat()` arm; (optionally) a `BackendConfigWriter`. State that no other file needs editing (validation + config consume the matrix). **Commit** `docs: how to add an arch or backend`.

### Task F2: Final verification

- [ ] **Step 1:** `cargo fmt --all -- --check`; `cargo clippy --workspace --all-targets -- -D warnings`; `cargo test --workspace`; `cargo run -p xtask -- check-spec-numbers`. All green.
- [ ] **Step 2:** Tick the spec's acceptance criteria + this plan's checkboxes; **commit** `chore: tidy + verify artifact-model slice 1`.

## Success criteria (from the spec)

> **Status: IMPLEMENTED** on branch `feat/artifact-model-impl` (subagent-driven, each task spec+quality reviewed; final whole-branch review ✅). All criteria met; `cargo build/clippy/fmt/check-spec-numbers` green workspace-wide.

- [x] `GuestArch` is the single arch type; `runtime_overlay::Arch` + stringly `target_arch` migrated.
- [x] `KernelFormat` in `mvm-core`, covers `Image`/`Pe`, consumed by `mvm-libkrun`.
- [x] `MicrovmBackend` + `BackendCompat` matrix in `mvm-backend`; `compat()` lookup.
- [x] Build-level `ArtifactManifest` written; mkGuest sidecar renamed `GuestSidecar`.
- [x] `FirecrackerConfigWriter` generates config from a manifest.
- [x] `ArtifactValidator` enforces compat + init presence, stores a `ValidationReport`.
- [x] `mvmctl artifact` model commands (`model-inspect|model-validate|model-config`) work over existing artifacts. (Namespaced `model-*` because the existing `mvmctl artifact pack|verify|inspect` for signed `.mvm` archives already owns `inspect`.)
- [x] Tests cover arch parsing, compat checks, manifest handling, config generation.
- [x] Adding an arch/backend is a new row + variant — documented (`public/src/content/docs/contributing/adding-an-arch-or-backend.md`).
- [x] No new third-party dependencies in this slice (reused `uuid`, `ext4-view`, `sha2`, `thiserror`).

### Bonus (unplanned, landed during A2)
- [x] Inverted the `mvm-core → mvm-libkrun` dependency (a violation of mvm-core's "no runtime deps" rule) → `mvm-libkrun → mvm-core`; `mvm-core` is now a pure sink. libkrun install paths deduped into one `LIBKRUN_LIB_PATHS` const with a drift-guard test.

## Deferred follow-ups (slice-1 review findings — own future slices)

- [ ] **Persist `boot_args` in `ArtifactManifest`.** Today it isn't stored, so when the CLI reconstructs a `MicrovmArtifact` from a manifest it re-seeds `boot_args` from `compat()`, making `ArtifactValidator` check #6 (required-boot-args-present) a tautology on the manifest-driven path. Record real cmdline args at build time to make the check meaningful.
- [ ] **Persist `RootfsArtifact.read_only` in the manifest** (`ManifestRootfs`). CLI reconstruction currently defaults it to `true` (ADR-002 W3); a writable dev/sandbox rootfs needs the real value round-tripped.
- [ ] **Wire `mvmctl artifact model-build` fully** (currently a documented stub delegating to `mvmctl build`/`dev`).
- [ ] **Reconcile the `artifact` CLI namespace** — the `model-*` prefix coexists with the `.mvm`-archive `pack|verify|inspect`; a cleaner unification (or rename) is a UX follow-up.
- [ ] The deferred design slices remain: `arcbox_ext4` rootfs builder, QEMU + vfkit `BackendConfigWriter`s, dynamic boot smoke-tests, `microvm.nix` integration (see §"Out of scope").
