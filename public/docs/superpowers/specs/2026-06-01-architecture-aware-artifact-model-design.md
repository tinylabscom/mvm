# Architecture-aware microVM artifact model — design (slice 1)

**Date:** 2026-06-01
**Status:** Approved (design); ready for implementation plan
**Scope:** First slice of an architecture-aware, backend-aware artifact model. Extends existing crates in place (option **B**); no new crate.

## Context

The goal is a Rust-orchestrated, architecture- and backend-aware model for microVM boot artifacts (kernel + rootfs + backend config), so MVM can represent and validate artifacts across CPU architectures (`x86_64`, `aarch64`) and hypervisor backends (Firecracker, libkrun, Vz, …) without assuming every kernel is `vmlinux` or every backend is Firecracker.

A full investigation showed **most of the requested capability already exists, scattered**: `mvm_libkrun::KernelFormat`, six backend impls behind `VmBackend`/`VmBackendForBuilder` in `mvm-backend`, an `Arch` enum in `mvm-build`, `ArtifactManifest` + `.mvm-provenance.json` + `.mvm-artifacts.sha256`, deterministic ext4 via `mke2fs` (`oci_to_rootfs::ext4`), and Firecracker config in `mvm-backend`. Three project rules shape the approach:

- **ADR-066** consolidates 32→17 crates and prefers *modules over crates*; a new crate must earn its place (external-consumer trait seam, separate process, proc-macro, or distinct dep closure). A greenfield `mvm-artifacts` crate meets none today.
- **Dependency-limiting rule**: reuse in-tree crates; question every new one.
- **ADR-050 / hermetic invariant**: production ext4 is built *inside* the builder VM (`mke2fs`), never on the host; `mvmctl` never uses host Nix/tools.

**Decision: option B — extend the existing primitives in place.** The real value the original spec adds is the *typed model* that's missing today (a `GuestArch` enum, a data-driven backend-compat matrix, a unified validator + manifest, a CLI surface) — not new builders. We reuse the validated, CI-gated, claim-backed builders and add the typed layer over them.

### Slice 1 scope (this spec)

`GuestArch` + `KernelFormat` consolidation, the `MicrovmBackend` + `BackendCompat` matrix, the trait surface, manifest reconciliation, static validation (reusing `ext4-view`), and the `mvmctl artifact inspect|validate|config` CLI.

**Explicitly deferred to their own later specs:** the `arcbox_ext4` pure-Rust rootfs prototype, QEMU and vfkit `BackendConfigWriter`s, dynamic boot smoke-tests, and `microvm.nix` integration.

## Section 1 — Placement & typed core (no new crate)

- **`GuestArch`** → **`mvm-core`** (pure types). Variants `X86_64 | Aarch64`. `FromStr`/`from_alias` normalizes `amd64|x86_64 → X86_64` and `arm64|aarch64 → Aarch64` (canonicalize `arm64`→`aarch64` internally). A `nix_system()` method returns `"x86_64-linux"`/`"aarch64-linux"`, replacing `host_system_linux()`. **Unifies and replaces** `mvm-build::runtime_overlay::Arch` and the stringly `packed_artifact.target_arch` (hard rename; no compat shims, per the no-backcompat rule).
- **`KernelFormat`** → **moved to `mvm-core`** (pure enum) and extended. Keep the existing compression-aware variants (`Raw, Elf, ImageGz, ImageBz2, ImageZstd, PeGz`) and add the uncompressed cases the model needs (`Image`, `Pe`). `mvm-libkrun` imports it from core instead of owning it; its loader mapping is unchanged.
- **`MicrovmBackend` enum + `BackendCompat`** → **`mvm-backend`** (capabilities authority), built on the core types. Enum: `Firecracker, Libkrun, Vz, AppleContainer, CloudHypervisor, Docker, Qemu, Vfkit`. Reconciliation note: **`Vz` *is* Apple Virtualization.framework** here, so there is no separate `AppleVirtualization` variant; `Vfkit` is the future CLI wrapper. Backends with no runtime impl (`Qemu`, `Vfkit`) still declare compat — the model expresses requirements even where the runtime is absent.

Net: `mvm-core` gains two pure enums; `mvm-backend` gains the backend enum + compat data. No new crate, no parallel types.

## Section 2 — Compatibility matrix

A data-driven table, not scattered `match`es:

```rust
pub struct BackendCompat {
    pub backend: MicrovmBackend,
    pub guest_arches: &'static [GuestArch],
    /// Accepted kernel formats, keyed per-arch where they differ
    /// (Firecracker: ELF vmlinux on x86_64, Image on aarch64).
    pub kernel_formats: &'static [(GuestArch, &'static [KernelFormat])],
    pub rootfs_formats: &'static [RootfsFormat],
    pub required_boot_args: &'static [&'static str],
    pub supports_snapshots: bool,
    pub supports_jailer: bool,
    pub networking: NetworkingModel,
}

pub fn compat(backend: MicrovmBackend) -> &'static BackendCompat;
```

`RootfsFormat` (`Ext4 | InitramfsCpioGz | Squashfs | Raw`) and `NetworkingModel` are new enums in `mvm-backend`. Validation **and** config generation both consume this one table, so adding a backend or arch is a new row, never edits scattered across the codebase.

## Section 3 — Trait surface (thin adapters over existing builders)

Define the full seam; slice 1 only *implements* the parts that add value over artifacts the existing pipeline already produces.

```rust
pub trait KernelBuilder          { fn build_kernel(&self, &KernelSpec) -> Result<KernelArtifact>; }
pub trait RootfsBuilder          { fn build_rootfs(&self, &RootfsSpec) -> Result<RootfsArtifact>; }
pub trait MicrovmArtifactBuilder { fn build_microvm(&self, &MicrovmBuildSpec) -> Result<MicrovmArtifact>; }
pub trait BackendConfigWriter    { fn write_config(&self, &MicrovmArtifact) -> Result<BackendConfigArtifact>; }
pub trait ArtifactValidator      { fn validate(&self, &MicrovmArtifact) -> Result<ValidationReport>; }
```

`KernelSpec`/`RootfsSpec`/`MicrovmBuildSpec` follow the original prompt's shapes (`GuestArch` + `MicrovmBackend` + format + source), using std paths (not `camino`).

- **Slice-1 impls:** `NixMicrovmBuilder` — a *thin adapter* over the existing `BuilderVm`/`run_build` flake path, which already emits kernel+rootfs together as `BuilderArtifacts::Image`; the adapter maps that into typed `KernelArtifact`/`RootfsArtifact`/`MicrovmArtifact` and writes the manifest. Plus `FirecrackerConfigWriter` and the static `ArtifactValidator`.
- **Deferred (later slices):** `Ext4RootfsBuilder` (arcbox prototype), `MicrovmNixBuilder`, QEMU/vfkit `BackendConfigWriter`s. The traits exist now so those slot in without touching callers.

**Module home (pin during planning against the real crate dep graph):** the validator and config-writer need `BackendCompat`, which lives in `mvm-backend`, so they (plus the trait definitions, spec/artifact types, and `ArtifactManifest`) most naturally live in an `artifacts` module **in `mvm-backend`** — it already owns the backends, compat, and Firecracker config. The single piece that needs the Nix `BuilderVm` is the `NixMicrovmBuilder` adapter, which lives in **`mvm-build`** and depends on `mvm-backend` for the types. The first planning step verifies this direction (`mvm-build → mvm-backend`) introduces no cycle; if `mvm-backend` already depends on `mvm-build`, the trait surface stays in `mvm-build` and `BackendCompat` is what moves down to `mvm-core` instead. Either way: types in `mvm-core`, compat where the backends are, the Nix adapter in `mvm-build`, no new crate.

## Section 4 — Manifest reconciliation

Three manifest-ish files exist today, and the name `ArtifactManifest` is taken by the wrong thing:

| Existing | What it really is | Action |
|---|---|---|
| `mvm_build::builder_vm::ArtifactManifest` (`mvm-meta.json`) | mkGuest **runtime sidecar** (accessible/sealed/overlayAware) | **rename → `GuestSidecar`** (hard rename, no shim) |
| `.mvm-provenance.json` (`BuilderVmSourceCacheProvenance`) | builder-VM source-cache provenance | keep; **embed** into the new manifest |
| `.mvm-artifacts.sha256` | sha256 of vmlinux/rootfs/cmdline | keep the hashing; **fold** into the manifest's hash fields |

New **`ArtifactManifest`** (`manifest.json`, written next to artifacts): `artifact_id` (`uuid`, in-tree), `build_id`, optional `tenant_id`, `GuestArch`, `MicrovmBackend`, `kernel { path, format, hash, version? }`, `rootfs { path, format, hash, size }`, `config_path`, embedded provenance (flake ref + lock hash where used), `builder_version`, `timestamp` (passed in; `Date::now` is unavailable in some contexts), and `ValidationReport`. **Hashing stays `sha2`/SHA-256** (in-tree; already what `.mvm-artifacts.sha256` uses) — *not* `blake3`.

## Section 5 — Static validation

`ArtifactValidator::validate(&MicrovmArtifact) -> ValidationReport` runs, in order:

1. kernel + rootfs files exist;
2. hashes match the manifest (sha256);
3. backend supports the arch (matrix);
4. kernel format accepted for `(backend, arch)` (matrix, per-arch keyed);
5. rootfs format accepted (matrix);
6. required boot args present (matrix);
7. **rootfs carries an init path** — via **`ext4-view`** (generalizes the existing `verify_stage0_rootfs_has_init`: open the ext4 read-only, assert `/sbin/init` or the configured init exists).

`ValidationReport` is serializable and stored in the manifest. Errors are typed via **`thiserror`** (in-tree; *not* `miette`) and produce messages of the form: `Cannot build Firecracker artifact for arch=aarch64: kernel format VmlinuxElf not accepted; expected one of [Image].`

## Section 6 — CLI, dependencies, testing

- **CLI** (existing clap style under `mvmctl`): `mvmctl artifact inspect <id>`, `artifact validate <id>`, `artifact config <id> --backend firecracker`. `artifact build` is a thin wrapper over the existing build pipeline. `smoke-test` is deferred.
- **Dependencies — none new in slice 1.** Reuse `anyhow`+`thiserror`, `sha2`, `serde`/`serde_json`, `uuid`, `ext4-view`. Justified divergences from the original prompt (dep-limiting rule): `sha2` not `blake3`; `uuid` not `ulid`; `thiserror` not `miette`; std paths not `camino`; std subprocess not `duct`. `arcbox_ext4` arrives only with its deferred slice; `cap-std` only if a concrete unsafe-path need appears.
- **Tests:** arch alias parsing/normalization; compat-matrix accept+reject per `(backend, arch, kernel/rootfs format)`; invalid-combo typed errors; `ArtifactManifest` serde roundtrip; sha256 verification; Firecracker config snapshot; `ext4-view` init-presence (reusing the Linux-gated real-ext4 fixture pattern). Boot smoke behind a deferred `--features integration-boot`.

## Acceptance criteria (slice 1)

1. `GuestArch` is the single arch type; `runtime_overlay::Arch` and stringly `target_arch` are migrated to it.
2. `KernelFormat` lives in `mvm-core`, covers uncompressed `Image`/`Pe`, and `mvm-libkrun` consumes it.
3. `MicrovmBackend` + `BackendCompat` matrix exist in `mvm-backend`; lookup is `compat(backend)`.
4. `ArtifactManifest` (build manifest) is written for an artifact; the old sidecar is renamed `GuestSidecar`.
5. `FirecrackerConfigWriter` generates a Firecracker config from a manifest.
6. `ArtifactValidator` enforces arch/backend/kernel/rootfs compatibility + init presence before launch, returning a stored `ValidationReport`.
7. `mvmctl artifact inspect|validate|config` work over existing artifacts.
8. Tests cover arch parsing, compatibility checks, manifest handling, and config generation.
9. Adding a new arch or backend is a new `BackendCompat` row + `GuestArch`/`MicrovmBackend` variant — documented.

## Out of scope (future slices, each its own spec→plan)

- `Ext4RootfsBuilder` via `arcbox_ext4` (host-side pure-Rust ext4) — prototype + benchmark; must not replace the hermetic `mke2fs`-in-VM production path (ADR-050).
- QEMU + vfkit/Apple-Virtualization `BackendConfigWriter`s.
- Dynamic boot smoke-tests (`mvmctl artifact smoke-test`).
- `microvm.nix` integration (`MicrovmNixBuilder`).
- Cross-arch builds via remote builders / binfmt (explicit, not faked).
