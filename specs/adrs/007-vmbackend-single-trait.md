---
title: "ADR-007: `VmBackend` single trait; backend-as-impl pattern"
status: Proposed
date: 2026-05-07
related: ADR-013 (libkrun pivot), plan 60-mvm-libkrun-migration
---

## Status

Proposed. Implementation lands in Phase 0 (workspace reshape) and Phase 1 (Firecracker + libkrun impls).

## Context

The current `mvm` skeleton introduces two parallel backend abstractions:

- `mvm-backend/src/backend/sandbox.rs` defines `Backend<Sandbox, Context>` with `prepare/boot/teardown` (most methods `todo!()`).
- `mvm-builder/src/builder/mod.rs` defines `BuilderBackend` with `prepare/build/extract_artifacts/cleanup` (no impls).

Meanwhile, the previous iteration at `../mvm/crates/mvm-core/src/protocol/vm_backend.rs` already defines a stable `VmBackend` trait (~700 LOC) that **mvmd's agent + hostd already depend on** through the `mvmctl` facade. mvmd's `LifecycleDispatch` enum routes either to direct trait calls (dev mode) or to `mvm-hostd` IPC (production), and the dispatch types are the `VmBackend` trait's request/response shapes.

Maintaining two parallel abstractions would require either:
1. A bridge layer translating between `Backend<S,C>` and `VmBackend` — pure overhead.
2. mvmd refactoring to consume the new trait — breaks the facade contract.

Neither is acceptable.

## Decision

1. **Delete the hand-written `Backend<S,C>` and `BuilderBackend` traits.** They were placeholder skeletons the user OK'd replacing.
2. **Adopt `mvm_core::protocol::vm_backend::VmBackend` as the single backend trait** (port verbatim from `../mvm/crates/mvm-core/src/protocol/vm_backend.rs` in Phase 0).
3. **Implementations live in their own modules**, not their own traits:
   - `mvm/src/vm/firecracker.rs` → `impl VmBackend for FirecrackerBackend`
   - `mvm/src/vm/libkrun.rs` → `impl VmBackend for LibkrunBackend`
   - Future: `mvm/src/vm/cloud_hypervisor.rs` (post-Phase-10, gated by `backend-cloud-hypervisor` feature)
4. **Build vs. execution split is preserved** via a separate (existing) abstraction: `mvm_core::build_env::{ShellEnvironment, BuildEnvironment}`. `mvm-build` consumes `BuildEnvironment`; this is an orthogonal concern from `VmBackend`.
5. **Backend selection** is centralized in `mvm-cli/src/commands/mod.rs::pick_backend()`:
   - env override `MVM_BACKEND` (explicit)
   - else: KVM available + Linux → Firecracker; macOS/Windows/no-KVM → libkrun
6. **Plug-in registration** via `inventory` crate (post-Phase-10): new backends register at startup; core code stays closed for modification but open for extension.

## Consequences

**Positive**:
- mvmd's compile gate stays unbroken — same trait shape, same paths, same wire format.
- Single source of truth for backend semantics; no bridge layer.
- New backends are a file + an `impl VmBackend`, not a new trait + bridge.

**Negative**:
- We inherit `VmBackend`'s current shape, which still carries a few argument names from the previous iteration's pre-pivot layout (when Lima was in scope). We accept this for facade stability; a follow-up ADR can rename if a specific name proves load-bearing-confusing.
- The trait isn't `dyn`-safe today (uses `async fn` in trait via `async-trait`). Plug-in registration via `inventory` works but precludes some advanced compositions; acceptable trade-off.

**Neutral**:
- Both `Backend<S,C>` and `BuilderBackend` go away — the user's hand-written code is replaced, but no consumer uses them.

## Alternatives considered

- **Two traits, `BuildBackend` + `RunBackend`**: rejected. The previous iteration tried this and the lines blurred (snapshots, sleep policy, etc. cross both); a single richer trait + sub-namespaces is cleaner.
- **Trait objects (`Box<dyn VmBackend>`)**: deferred. Async-fn-in-trait works for static dispatch but not yet `dyn`-safe. We use enums (`BackendKind`) for dispatch today; switch to trait objects when the toolchain supports it.

## Threat model impact

None — purely a refactor of the abstraction layer. The same security operations (jailer, seccomp, dm-verity) bind to the same trait methods.

## Compliance impact

None.


## Consolidated from ADR-046 — Move the builder VM off libkrun onto libkrun + firecracker

> **Consolidation note:** an earlier draft of this ADR proposed itself as the canonical builder-VM architecture doc, consolidating ADR-013, ADR-057, and ADR-065 — that merge was never carried out (those three remained standalone files). The ADR-wide consolidation pass folded ADR-046 itself into this document (ADR-007, the backends/hypervisor-abstraction canonical); ADR-013, ADR-057, and ADR-065 were separately folded into ADR-004 (the builder-VM/Stage-0/seed canonical). Current state reflects ADR-065's single `builder-vm` flake with `default`/`dev` attrs.

## Status

Proposed. Implementation sequenced in `specs/plans/72-builder-vm-via-libkrun.md`. This ADR replaces the **builder VM** half of ADR-013, leaving the runtime backend selection unchanged.

## Context

ADR-013 chose libkrun for two distinct jobs:

1. **The builder VM** — a Linux microVM that runs `nix build` so the host doesn't need Nix.
2. **The macOS / no-KVM execution backend** — the runtime hypervisor for user microVMs on machines where Firecracker isn't available.

The second job is already migrating to a direct libkrun integration (`crates/mvm-backend/src/libkrun.rs`, plan 57 spike). The first job — the builder VM — is the only thing still routing through libkrun, and it's been the source of the friction described below.

### What we actually use libkrun for, and what it costs

The builder-VM call site (`mvm_cli::commands::env::apple_container::build_image_via_libkrun` → `mvm_build::builder_vm::LibkrunBuilderVm`) needs:

| Need | libkrun API surface |
|---|---|
| Boot a Linux VM via libkrun on macOS, KVM on Linux | `Sandbox::builder().image().cpus().memory()` |
| Bind-mount workspace read-only | `.volume(...).bind(...).readonly()` |
| Bind-mount artifact dir read-write | `.volume(...).bind(...)` |
| Run a shell script and capture stdout/stderr/exit | `.shell(...)` |
| Pull a pinned OCI image (`nixos/nix:2.24.10`) | `.pull_policy(IfMissing).registry(...auth(Anonymous))` |

That's the entire used surface. In exchange, libkrun brings:

- ~40 transitive crates, including database, image, network, filesystem,
  signature, OCI, and object-store support that this project does not need
- A SQLite-backed sandbox/volume database in `~/.libkrun/`
- An EROFS + ext4 overlay rootfs system
- A snapshot/agent/named-volume/disk-image system we don't use
- **A 4 GiB hardcoded overlay size** (`libkrun-image-0.4.5/lib/ext4/mod.rs:25`) with no public knob

The 4 GiB is the load-bearing problem. The Nix build closure for the dev image is rustc + ~480 cargo crate derivations substituted from cache.nixos.org. The closure pages into the writable overlay and overflows around derivation ~150 with `error: writing to file: No space left on device`. No combination of `host_nix_store` bind-mount, named volume, or volume seeding fixes this without losing access to the OCI image's read-only `/nix/store/...-bash` (which `/bin/sh` symlinks into).

### What we tried before writing this ADR

Documented for the next reader so they don't waste the cycles:

1. **Bind-mount empty host dir at `/nix`** — shadows the image's `/nix`, breaks `/bin/sh`.
2. **`path:` URL with workspace mounted at `/work`** — works for path resolution after we also pass `MVM_WORKSPACE_PATH=/work` to the flake (because `path:` URL store-copies the flake subdir and `../../..` resolves outside the workspace mount), but doesn't help the overlay-size problem.
3. **`git config --global` before `cd /work`** — necessary for git-worktree workspaces (the worktree's `.git` is a file whose `gitdir:` redirect targets a host path that doesn't exist in the sandbox); landed in plan 72 W0 anyway because it's the correct order regardless of the broader strategy.

These three fixes are kept in the codebase under plan 72 W0. They're not libkrun-specific — they describe how to safely run a Nix build inside any sandboxed Linux. They will still apply once the builder VM moves to libkrun.

### Why not just patch libkrun

Considered. The `Ext4FormatOptions::size_bytes` field is `pub`, but the `create_upper_ext4` call site in `libkrun-0.4.5/lib/sandbox/mod.rs:1948` hardcodes `Ext4FormatOptions::default()` and the `SandboxBuilder` exposes no override. A minimal upstream patch (a `pub fn upper_size_mib(self, mib: u32) -> Self` on the builder) is plausibly one day of work plus a PR cycle.

We're not opposed to filing that PR. But:

- It doesn't change the underlying argument that we're paying for ~40 transitive crates to use 5 API methods.
- The libkrun library is one developer at one company. Even with an accepted PR, we'd be coupled to their release cadence for any future builder-side change (network policy, mount semantics, init replacement).
- The libkrun backend already in mvm's tree (plan 57 spike) is the substrate we'd build on regardless. Reusing it for the builder VM consolidates the macOS-VM story.

The vendoring option (fork libkrun in-tree) is on the table as a fallback if the libkrun spike (plan 57) doesn't progress on the timeline plan 72 needs.

## Decision

The builder VM moves to a direct libkrun (macOS Apple Silicon / Intel) and Firecracker (Linux) launcher. libkrun is removed from the build-time dependency closure once plan 72 ships.

### Two artifact layers, two acquisition paths

mvm builds and launches **two different VM images**, and they have different lifecycles:

1. **Builder VM image** — kernel + rootfs.ext4 containing Nix + bash + coreutils + git + curl + `mvm-builder-init`. Slow-changing infrastructure. The thing libkrun/Firecracker boots to *run* the Nix build.
2. **Dev shell image (and any user microVM)** — kernel + rootfs.ext4 produced *by* the builder VM from a flake in the user's workspace (`nix/images/dev-shell/flake.nix` for `mvmctl dev shell`; arbitrary user flakes for `mvmctl run`).

Each has an acquisition rule keyed off "is this a source checkout of mvm itself?"

#### In a source checkout (contributor workflow)

```
mvmctl dev up
   │
   ▼
Is this a source checkout?  (find_dev_image_flake() returns Some)
   │
   ▼ yes
   │
   ├─ Step 1: ensure builder VM image
   │    Always build it locally from nix/images/builder-vm/flake.nix.
   │    Cache the result at ~/.cache/mvm/builder-vm/<flake-narHash>/.
   │    Cache key = the flake's content hash, so any modification to
   │    nix/images/builder-vm/ invalidates and rebuilds automatically.
   │
   │    The builder VM image is produced by the project release
   │    pipeline and hash-verified when downloaded.
   │
   │    Host Nix is NEVER used, even if installed on the host. See
   │    CLAUDE.md §"Host Nix is never used by mvmctl" for rationale.
   │
   ├─ Step 2: build the dev shell image (or any user microVM)
   │    Always build it locally from the workspace's flake using the
   │    builder VM produced in Step 1. Cache at
   │    ~/.cache/mvm/dev/<flake-narHash>/.
   │
   └─ The mvm-published prebuilt is NEVER touched in this path.
      A contributor developing the builder VM image observes their
      changes on the very next `mvmctl dev up` — no release pipeline
      round-trip, no checksum that lags behind their edits.
```

#### Outside a source checkout (installed binary, end-user workflow)

```
mvmctl dev up
   │
   ▼
Is this a source checkout?
   │
   ▼ no
   │
   ├─ Step 1: ensure builder VM image
   │    No flake to build from — download the mvm-published prebuilt
   │    matching mvmctl's version. Hash-verified per ADR-001 §W5.1
   │    against the release's `builder-checksums-sha256.txt`. Cache
   │    at ~/.cache/mvm/builder-vm/v<version>/.
   │
   ├─ Step 2: build the user's microVM
   │    User supplies a flake (or uses the bundled default-tenant
   │    flake from a prior release). Builder VM runs `nix build`
   │    against it.
   │
   └─ Host Nix is not required. mvmctl never asks the user to
      install Nix.
```

### Launcher architecture (same on both paths)

```
LibkrunBuilderVm::run_build(job, mounts)
   │
   ├─ stage the per-build command at
   │    ~/.cache/mvm/builder-vm/jobs/<job-id>/{cmd.sh,env,result}
   │
   ├─ launch the VM via the runtime backend:
   │    macOS  → libkrun  (mvm_libkrun::start_with_config)
   │    Linux  → Firecracker (mvm_backend::firecracker)
   │
   ├─ attach mounts:
   │    /work        virtio-fs  ← <workspace>          (read-only)
   │    /out         virtio-fs  ← <artifact_out>       (read-write)
   │    /nix-store   virtio-blk ← <store-disk.img>     (read-write, 64 GiB sparse)
   │    /job         virtio-fs  ← <job dir>            (read-write, holds cmd.sh + result)
   │
   ├─ guest init reads /job/cmd.sh, runs it, writes exit code + tail logs
   │   to /job/result, then powers off.
   │
   └─ host reads /job/result and returns BuilderArtifacts.
```

The persistent Nix store lives on a host-backed sparse virtio-blk image — sized at provision time, grows on host disk up to the configured cap. The image's own rootfs (read-only) holds the seed Nix store; the writable virtio-blk store at `/nix-store` is bind-mounted over `/nix` inside the guest's init (using `mount --bind`, which works fine because the guest owns CAP_SYS_ADMIN). No chicken-and-egg.

### Why the contributor path doesn't download

The whole point of having `nix/images/builder-vm/flake.nix` in the source tree is that contributors can change it and see results. A "first download a prebuilt, then use it" rule for source checkouts would make this loop fundamentally broken — every modification to the builder VM would require a release-and-download cycle before it could be tested. That's not a development environment; that's a binary distribution mechanism in disguise.

The final design removed the libkrun Stage 0 path entirely. Source checkouts use the builder VM release artifact as the bootstrap layer, while edits to the builder VM image itself are validated by the release/build pipeline.

The mvm-published builder VM image exists for *end users* who installed mvmctl as a binary. Its purpose is to remove host Nix from the user's prerequisites. It is not part of the contributor toolchain.

### What we keep vs. drop from libkrun

| Concern | Today (libkrun is the user-facing builder) | After plan 72 (libkrun is the user-facing builder) |
|---|---|---|
| Default `mvmctl dev up` runtime path | libkrun | libkrun (macOS) / Firecracker (Linux) |
| Builder VM disk size on the user-facing path | 4 GiB hardcoded | Configurable per-host (default 64 GiB sparse) |
| OCI image pulling on the user-facing path | libkrun `oci-client` | Not needed; we ship a Nix-built rootfs |
| Volume/sandbox DB on the user-facing path | SQLite at `~/.libkrun/` | No DB — job dirs at `~/.cache/mvm/builder-vm/jobs/<id>/` |
| Bind-mount surface on the user-facing path | libkrun volume API (Bind/Named/Tmpfs/DiskImage) | virtio-fs (DAX-on-Linux, share-on-macOS) |
| Sandbox lifecycle on the user-facing path | `Sandbox::create_detached`, `.shell()`, `.stop()` | `mvm_libkrun::start_with_config` + power-off-from-guest |
| Snapshot/named volumes/agent | Available, unused | Not implemented (unused features dropped) |
| User-facing build-trust boundary | libkrun + nixos/nix OCI image | Our own builder VM image (hash-verified per ADR-001 §W5.1) |

### Trust-zone shift

ADR-013 §"Linux builder via libkrun" placed the user-facing builder behind a pinned third-party OCI image (`docker.io/nixos/nix:2.24.10`). Plan 72 replaces that **on the user-facing path** with an mvm-published builder VM image — kernel + rootfs.ext4 built on a Linux CI runner via `nix/images/builder-vm/flake.nix` (a slimmed split of the current `nix/images/builder/`), signed by the project's release key, and verified by the same SHA-256 manifest path used today for `download_dev_image` (`mvm_cli::commands::env::apple_container::download_dev_image`, ADR-001 §W5.1).

- **End users**: trust boundary is mvm's release pipeline + signing + hash manifest. Same as the dev image today.
- **Contributors**: source-checkout builds use the same builder VM artifact path as end users unless they are directly changing the builder VM image, in which case validation happens through the builder-image build pipeline.

This is a *narrower* trust boundary than before:

- We control the rootfs contents (Nix + Bash + Coreutils + Git + Curl — same set as `builderPackages` in `nix/images/builder/flake.nix:71`).
- We control the kernel cmdline (`init=/sbin/mvm-builder-init`, no SSH, no extra services).
- We control the init binary (10–50 LoC of Rust or shell that reads `/job/cmd.sh`, runs it, writes `/job/result`, powers off via `/sbin/reboot -f`).
- No Docker Hub credentials, no OCI runtime, no libkrun database.

The trade we're accepting: we now ship a kernel + rootfs as part of every mvm release. CI cost: ~+12 min per release for the two-architecture builder build (already an existing cost — the `dev-image` job in `.github/workflows/release.yml` does exactly this for the dev image and is the model we copy).

## Consequences

### Positive

- Builder disk capacity becomes a host-configurable per-build setting, not a library-internal constant.
- Builder VM image is mvm-controlled — kernel cmdline, init, package set, release cadence.
- The default `cargo build` no longer pulls in libkrun's transitive crates.
- Consolidates user-facing VM launching: macOS execution (plan 57) and builder VM (plan 72) share the libkrun substrate. One C-library to track, one set of HVF/KVM bug patterns to learn.
- virtio-fs / virtio-blk mount semantics are standard and well-documented — no overlay-vs-bind confusion.
- The published builder image is the *same artifact* a user would download for `mvmctl run` against a minimal Linux microVM. The end-user-runtime story and the no-host-Nix-end-user-build story share a binary.
- Contributors developing the builder VM image see their changes on the next `mvmctl dev up` with no release-pipeline round-trip — the user-facing acquisition path (download + hash-verify) is not on the contributor critical path.

### Negative

- Real implementation work — 2–3 sprints by the plan-71 estimate (W0 through W6).
- Plan 72 W0–W2 depend on plan 57 (libkrun spike) reaching at least "boot a Nix-built kernel + ext4 rootfs on macOS Apple Silicon." If plan 57 stays in spike status, plan 72 W0–W2 stall; the vendoring fallback (fork libkrun, expose `upper_size_mib`) is the named escape hatch.
- During the transition, the migration adds a temporary `builder-vm` flag, default-on once W5 lands.
- The published builder image is a new release artifact. The release pipeline grows two new `builder-vmlinux-{arch}` + `builder-rootfs-{arch}.ext4` outputs alongside the existing dev-image outputs.
- Contributors who modify `nix/images/builder-vm/flake.nix` validate that change through the builder-image build path rather than a libkrun bootstrap path.

### Neutral

- ADR-013 §"Execution backend selection" is unchanged. Linux + KVM → Firecracker; macOS / Windows / no-KVM → libkrun (per plan 57). libkrun stays available as an opt-in execution backend during the deprecation window; it just isn't the default and isn't on the builder path.
- ADR-001 §W5.1 (image hash verification) applies to the builder image with no change — same manifest + streaming SHA-256 path as the dev image.
- The flake (`nix/images/builder/flake.nix`) and the in-sandbox build script (`crates/mvm-build/src/builder_vm.rs:543`) keep the three fixes from plan 72 W0 (workspace mount at `/work`, `MVM_WORKSPACE_PATH=/work`, `git config --global` before cd). They're correct regardless of launcher and they're load-bearing for the published builder image too.

## Fallback / escape hatch

If plan 57's libkrun spike doesn't progress before plan 72 needs it, **vendor libkrun in-tree and patch in the `upper_size_mib` knob**. That unblocks the immediate user pain (`mvmctl dev up` doesn't fail with disk-full anymore) and buys time for plan 72 W0–W2 to land. Vendoring is reversible — once plan 72 W5 lands, the vendored copy is deleted.

The vendoring path is *not* the same as the libkrun path. It addresses one symptom (disk size) without addressing the structural cost (transitive deps, narrow API use, coupled release cadence). Plan 72 supersedes it.

## Open questions (for plan 72 to answer)

1. **Init in the builder VM**: 50-LoC shell + busybox vs. a small Rust binary built from `crates/mvm-build/src/builder_init.rs` (new). Rust is consistent with the rest of mvm; shell is simpler to audit. Plan 72 W3 picks one.
2. **Network access in the builder VM**: `nix build` needs cache.nixos.org. Plan 72 W4 wires virtio-net + the host's DNS resolver. Confirms `--no-substituters` still works for the air-gapped contributor case.
3. **First-build latency**: cold cache pulls ~2 GB of substitutes. virtio-blk-backed `/nix` persists across builds, so warm cache is fast. Plan 72 acceptance criterion: warm-cache rebuild of the unchanged dev image completes in <30 s.
4. **GPU / SIMD acceleration for cryptography**: not needed for the builder path. Documented to avoid scope creep.

## Vz as a second builder backend (Plan 98)

> Added 2026-05-27 by Plan 98 — extends this ADR's scope from "the builder VM is libkrun" to "the builder VM is one of {libkrun, Vz}, picked by host platform."

### Selection policy

The builder backend is selected by a single resolver
(`mvm_build::builder_backend_select::resolve_choice_with_override`)
with the following priority:

1. **CLI flag** `--builder <libkrun|vz>` — highest priority. Folded into `MVM_BUILDER_BACKEND` at startup by `mvm_cli::commands::run`.
2. **Env var** `MVM_BUILDER_BACKEND` — case-insensitive, whitespace-trimmed; unrecognised values log `tracing::warn!` and fall through to auto-detect (no abort).
3. **Auto-detect**:
   - macOS 26+ Apple Silicon → **Vz**.
   - Everywhere else (macOS 13-25, Linux, Windows) → **libkrun**.

Vz on macOS 13-25 stays opt-in only via the override path. The auto-detect predicate is intentionally conservative — the deployment baseline is macOS 26+ Apple Silicon (mirrors the Apple Container runtime tier), so the older macOS minor versions stay on the libkrun path that's been hardened since 2026-05-14 (Lima removal). When Slice 2C eventually adds the entitlement / MDM probe (§2.S4), auto-detect refuses Vz when the entitlement check fails and falls through to libkrun rather than failing mid-build.

### Parallel drivers, not a generic seam

The Vz path ships as a **parallel** driver (`VzBuilderVm`, `VzPersistentBuilderVm`) alongside the libkrun driver (`LibkrunBuilderVm`, `LibkrunPersistentBuilderVm`), each implementing `BuilderVm` independently. Both drivers share the orchestration helpers extracted by Plan 97 Phase C (`stage_job_dir`, `JobResult`, `finalize_flake_job`, `finalize_install_job`, `NixStoreImageLock`, `builder_vm_timeout`, stderr-tail formatters) via `mvm_build::builder_vm_runtime`, but each driver owns its own `start()` / `run_build()` / handle.

This was a deliberate choice over a single `BuilderVm`-generic-over-`Vmm`-trait abstraction. The two VMM impls have meaningfully different shapes:

- libkrun is an in-process C library — the host process *is* the VMM. Panic detection is the host's responsibility because `krun_start_enter` blocks indefinitely on a panicked guest.
- Vz is an out-of-process Swift supervisor — the host spawns `mvm-vz-supervisor` and waits on the child. Vz exits cleanly on guest panic; no console-log scanner is needed.

A generic seam would have to either erase that difference (forcing libkrun to fake out-of-process semantics or Vz to fake in-process semantics) or split into two trait paths with awkward shared parts. Parallel drivers keep each path readable on its own merits and let the shared orchestration live where it belongs — in helper functions, not in trait erasure.

### State-dir isolation + coexistence

Both backends' persistent builder state dirs live under the same parent — `~/.cache/mvm/builder-vm/vms/` — distinguished by name prefix:

- `mvm-persistent-builder-vm-<session>` for libkrun.
- `mvm-persistent-builder-vz-<session>` for Vz.

The Stage 0 reaper (Plan 99 PR-1, `crates/mvm-cli/src/commands/env/apple_container.rs::clean_orphan_state_dirs`) walks the parent and is prefix-agnostic — it picks up both backends' dirs without code changes. `mvmctl cache prune` honours running PIDs across both prefixes (§2.C2).

Cross-backend `mvmctl dev` coexistence (`up` refuses cleanly when the *other* backend's persistent dir has a live PID; `down` enumerates both prefixes; `status` reports per-backend state) is Slice 2B follow-up work — the prefix isolation in this ADR is the foundation it builds on.

### Resource ceilings

Vz defaults match libkrun's `LibkrunBuilderVm::default` constants (`VZ_BUILDER_DEFAULT_VCPUS`, `VZ_BUILDER_DEFAULT_MEMORY_MIB`, `VZ_BUILDER_DEFAULT_NIX_STORE_MIB` cross-reference the libkrun consts directly so a future bump on either side flows through). Plan 72 W5.D RAM cap (4 → 8 → 16 GiB defaults, with the stage0/init.sh `/nix` tmpfs `size=` cap bumped alongside) applies to both backends identically.

### Image source (ADR-046 §"Source-checkout builds never depend on mvm-published artifacts")

Both backends resolve the builder VM image (`vmlinux` + `rootfs.ext4` + `cmdline.txt`) through `mvm_build::libkrun_builder::ensure_builder_vm_image()` — the single shared entry point. There is no Vz-specific image resolver, no "Vz pulls a prebuilt from GitHub releases" backdoor. The source-checkout contributor invariant from this ADR's earlier sections applies to the Vz path verbatim. Plan 98 §2.11 ships hermetic source-grep tests (`crates/mvm-build/tests/vz_builder_flake_invariant.rs`) that fail any future regression that adds a download path to `vz_builder.rs`.

### Security claim parity

The builder VM is the dev tier per `feedback_dev_vm_vs_prod_security_tiers.md`, *but* its Install arm (ADR-047, Claim 9) is the prod-grade path that produces the sealed deps volumes the runtime supervisor verifies. So the ADR-001 security claims that apply to the builder VM hold across **both** backends, with the same evidence:

- **Claim 1** (no host-fs access beyond explicit shares). Both backends construct `VirtioFsShare`s for `/work` `/out` `/job` `/nix-store` only. §2.S8 ships a hermetic test asserting set-equality of `(host_path, guest_path, read_only)` triples between the two drivers for the same input.
- **Claim 5** (vsock framing + supervisor-config JSON fuzzed). libkrun's `crates/mvm-libkrun/fuzz/fuzz_supervisor_config.rs` covers the libkrun supervisor's parser. Vz's `crates/mvm-vz/fuzz/` adds a parallel target against `mvm_vz::SupervisorConfig` — Slice 2C §2.S6. The host-side Vz control-socket parser (Phase E pause/resume/balloon/snapshot) is host-process-local with `0700` parent dir; ADR-001's host-trust assumption covers the residual surface (justified in the Slice 2C ADR-001 sub-note).
- **Claim 7** (cargo deps audited). `crates/mvm-vz` participates in `deny` + `audit` like every other workspace member; Slice 2C §2.S5 confirms `deny.toml` scope.
- **Claim 8** (signed/audited `ExecutionPlan`). `mvmctl up --prod` admission emits `plan.admitted` / `plan.launched` / `plan.failed` from the same `AuditEmitter` regardless of which builder backend resolved the Install. Slice 2C §2.S3 runs `mvmctl audit verify` after a Vz-driven `mvmctl up --prod` to assert chain cleanliness.
- **Claim 9** (sealed deps volumes hash-locked + attestation-checked + CVE-scanned + SBOM-enumerated + audit-bound). Cross-backend byte-equivalence of the sealed volume contents (`content/` tree, `sbom.cdx.json`, `fetch.log`, `cve.json`) is asserted by Slice 2C §2.S2. Builder VM kernel + rootfs parity (the Install-arm prod-grade path) is §2.S9 — if divergence is unavoidable, the volume-byte-level equivalence still holds because both backends produce the same Nix store closure. `meta.json` backend-neutrality (§2.S10) is asserted by decoding a libkrun-sealed and a Vz-sealed Install on the same input and comparing byte-for-byte.

The other ADR-001 claims (2, 3, 4, 6, 10) are guest-side or end-user-runtime concerns — they don't depend on which host VMM booted the builder, so the existing libkrun-side evidence applies unchanged.

Per `feedback_adr_out_of_scope_discipline.md` this Security-claim-parity subsection lists ONLY items in the same threat model as the parent ADR-001 claim. Adjacent surfaces (Sprint 56 Claim 10 in-guest volume encryption, Plan 101 gateway audit) belong in their own ADRs and are not in scope here.

### Cross-reference summary

- **Plan 97** — Vz runtime backend (Phase A/B/D/E shipped, C parked → continued by Plan 98).
- **Plan 98** — this extension's implementation plan.
- **Plan 99 PR-1** — Stage 0 cache contract the prefix-agnostic reaper depends on.
- **ADR-001** — security posture; per-claim sub-notes in Claims 1, 5, 7, 8, 9 point back here.
- **ADR-047** — Claim 9 evidence pipeline; gains a one-paragraph "Backend symmetry" sub-section citing §2.S2 + §2.S10.
- **ADR-056** — Vz runtime backend ADR; gains a "Persistent builder variant" pointer to this section.
- **ADR-057** — Sprint 56 symmetric trust boundary; bidirectional cross-link (Vz builder narrows the asymmetric-trust gap on macOS that ADR-057 fully closes).

## Amendment: kernel acquisition — compile or download

The slim custom kernel is the slowest, most memory-hungry step of a
first `mvmctl dev up`: because the config is custom, `cache.nixos.org`
has no substitute, so every fresh machine compiles it from source
(3-10 min, ~5-6 GiB peak). To fix that DX without weakening this ADR's
invariants, the kernel becomes a *separately acquirable* artifact with
two sources, selected by `mvmctl kernel build --source`:

- **`compile`** — build the kernel attr (`builder-kernel` /
  `workload-kernel` on `nix/images/builder-vm`) through the **same**
  Stage 0 path `dev up` uses, writing a `/out/stage0-build.conf` that
  switches `init.sh` to the kernel attr in kernel-only output mode. The
  result lands in the persistent `nix-store-stage0` image (shared and
  locked with the image build), so the next `dev up` *substitutes* the
  compiled kernel rather than rebuilding it. Host-arch only — Stage 0
  boots a host-arch VM under libkrun and cannot cross-compile.
- **`download`** — fetch a published `vmlinux-<arch>-<variant>`,
  SHA-256-verified against the release's `kernel-<arch>-checksums-sha256.txt`
  (the Claim-6 / §W5.1 verify-or-reject pattern, with the documented
  `MVM_SKIP_HASH_VERIFY` escape). This is the *only* way to obtain the
  **other** arch's kernel (the GHA `kernel-build.yml` builds both arches
  on native runners and publishes them **on release tags only** — PRs
  build-and-verify but never publish, honouring "no prebuilt until
  release").

`dev up` consumes either source through the global `--kernel-source`
(`MVM_KERNEL_SOURCE`) flag. `download` builds *only* the rootfs
(`stage0-rootfs` attr — a third `init.sh` output mode that emits no
kernel) and pairs the fetched, verified `vmlinux` into the image, so a
fresh `dev up` skips the multi-minute in-image kernel compile. The
published kernel is the same flake derivation `default` bundles, so the
paired image is equivalent. `compile` (the default) stays on the
single-boot `default` build — splitting it would mean two Stage 0 boots
for no gain, since the compiled kernel derivation is already substituted
from the persistent nix store.

### Why this does not violate "the contributor path doesn't download"

The §"Why the contributor path doesn't download" and §"Source-checkout
builds never depend on mvm-published artifacts" invariants are
preserved exactly:

- **Source checkouts always compile.** `--source compile` requires
  `find_builder_vm_flake()` to resolve; a contributor who edits
  `nix/images/builder-vm/kernel/base.nix` or the builder delta sees that change in the
  very next compile — no release round-trip. Download is keyed by the
  **mvmctl release tag** + arch + variant, so it can only ever return
  the kernel that *shipped with that exact mvmctl* — never a substitute
  for in-tree edits.
- **Download is an installed-binary / explicit-opt-in path**, not a
  prerequisite of any source-checkout workflow. The full image build
  (`dev up`) is unchanged: absent the `stage0-build.conf`, `init.sh`
  builds `default` exactly as before, byte-for-byte.

Per `feedback_adr_out_of_scope_discipline.md` this section covers only
the kernel-acquisition decision; the build-tier security posture
(`feedback_dev_vm_vs_prod_security_tiers.md` — the builder/dev kernel is
the dev tier) is unchanged and not re-litigated here.

---

> **Superseded in part by ADR-065 (Plan 115).** ADR-046's
> "Two artifact layers, two acquisition paths" rule is amended:
> the dev image and the builder VM image collapse into a single
> flake with two attrs (`default` / `dev`); mvm's own Linux
> binaries are embedded in mvmctl at its own build time rather
> than re-built per `dev up`. See ADR-065.


## Consolidated from ADR-056 — Vz backend (Apple Virtualization.framework)

**Status:** accepted 2026-05-22, implements Plan 97. Vz is an opt-in
macOS backend (`MVM_BACKEND=vz` / `--backend vz`); `auto_select`
remains unchanged so libkrun is still the macOS default and
Firecracker the Linux deploy default. **Amended 2026-06-10 by
ADR-007 §"Consolidated from ADR-076":** Vz becomes the
**macOS-26 auto-default** and **absorbs `AppleContainerBackend`** — the
in-process `providers/apple_container` AVF path is deleted, leaving one
honestly-named `vz` AVF backend on the per-VM supervisor model. The
"opt-in only / libkrun stays the macOS default" stance above holds for
macOS 13–25; macOS-26 now auto-selects `vz`. The per-claim table and the
console/entitlement invariants below are unchanged.

## Context

Today on macOS, every workload microVM goes through **two** layers of
virtualization:

```
macOS host  →  libkrun Linux VM  →  Firecracker microVM (/dev/kvm)
```

The nesting exists because Firecracker requires `/dev/kvm`, which
only exists inside a Linux guest. libkrun (via
`Hypervisor.framework`) hosts that Linux guest; Firecracker then runs
the workload guest inside it. ADR-013 §"libkrun pivot" set up this
architecture when Lima was retired.

Apple's `Virtualization.framework` (Vz) — distinct from
`Hypervisor.framework` even though the former is implemented on top
of the latter — has supported Linux guests since macOS 11 and exposes
the exact virtio surface our guests already drive (virtio-blk,
virtio-net, virtio-vsock, virtio-console, virtio-rng, virtio-fs,
virtio-balloon). That means a Vz-backed workload microVM can run
directly on the macOS host without nesting Firecracker inside libkrun.

ADR-055 §"Cross-platform backends" established that gvproxy is the
canonical macOS network backend; Vz's `VZFileHandleNetworkDeviceAttachment`
attaches gvproxy by file handle without changing the host-side plumbing.

## Why now, why this shape

Three forces lined up:

1. **Coverage gap.** Apple Container (ADR / Plan 75) only works on
   macOS 26+ Apple Silicon. macOS 11–25 and Intel hosts have only
   the nested libkrun→Firecracker path even though Vz works on every
   one of them.
2. **Layer collapse.** Direct Vz hosting on macOS removes one VMM
   from the workload path, cutting cold-boot wall time and idle
   memory overhead.
3. **Balloon + snapshot on the boring path.** Vz on macOS 11+ ships
   a memory balloon. Vz on macOS 14+ ships save/restore via
   `saveMachineStateTo` / `restoreMachineStateFrom`. Both lower the
   bar for warm-pool / fast-restore features the libkrun path can't
   give us today.

The Vz backend lives in `crates/mvm-backend/src/vz.rs`. It implements
`VmBackend` by spawning a per-VM `mvm-vz-supervisor` Swift subprocess
(`crates/mvm-vz-supervisor/`) — same one-process-per-VM contract
`LibkrunBackend` uses, swapped underneath. The Swift binary owns the
Vz API surface (closed-source Swift framework, Apple-controlled); the
Rust side owns the type-safe JSON config that flows over stdin, the
PID-file lifecycle, and the integration with the rest of mvm
(`admit_for_run`, audit chain, runtime metadata).

`auto_select()` is unchanged — libkrun stays the macOS default,
Firecracker the Linux default and the production deploy default. Vz
is opt-in through `MVM_BACKEND=vz` / `--backend vz`.

## Security tier — Tier 2

Vz sits at the same isolation tier as libkrun. The reasoning:

- Both use Apple's `Hypervisor.framework` as the underlying
  hypervisor primitive. Vz is a closed-source Swift wrapper that
  constrains the host's API surface; libkrun is an open-source C
  library that exposes more knobs. From an isolation-property
  standpoint they're equivalent.
- Vz's vCPU isolation, memory isolation, and virtio device
  emulation surface are all hardware-isolated through the same
  `Hypervisor.framework` primitive.
- Apple Container (Plan 75) is also classified Tier 3 today because
  it adds a *containerization* abstraction on top of Vz. Vz used
  directly skips that abstraction.

ADR-001 claim coverage under Vz:

| Claim | Status   | Why                                                  |
|-------|----------|------------------------------------------------------|
| 1     | Holds    | Supervisor refuses non-admitted virtio-fs shares; default workload config attaches zero shares. |
| 2     | Holds    | Guest-side, hypervisor-independent.                  |
| 3     | DoesNotHold | dm-verity artifact pipeline targets Firecracker today; Vz can boot a verity-prepared kernel but the artifact path hasn't been wired. Mirrors `LibkrunBackend`'s status. |
| 4     | Holds    | Guest-side.                                          |
| 5     | Holds    | Vsock framing is fuzzed (`crates/mvm-guest/fuzz/`); Rust↔Swift `SupervisorConfig` corpus equivalence test added in this Plan (claim 5 hardening — Plan 97 Phase A). |
| 6     | Holds    | Host-side download path unchanged.                   |
| 7     | Holds    | Cargo deps audited; Swift PM `Package.resolved` pinned (Plan 97 cross-cutting).         |

Claim 7 *extends* the existing pipeline: the Swift package's
`Package.resolved` is the SPM equivalent of `Cargo.lock` and is
checked in alongside the Rust lockfile.

Defense-in-depth additions on top of the trait-level requirements:

- **Resource-cap parity (Plan 97 Security §8).** The Swift
  supervisor validates `cpu_count` and `memory_mib` against
  `VZVirtualMachineConfiguration.maximumAllowedCPUCount` /
  `min/maxAllowedMemorySize` before constructing the VM config and
  refuses over-allocated requests with exit code 3.
- **Console mode lockdown (Plan 97 Security §9).** Workload
  microVMs get capture-only console
  (`VZVirtioConsoleDeviceSerialPortConfiguration` with
  `fileHandleForReading: nil`); interactive console for dev mode
  is PTY-over-vsock on ports 20000+, never on virtio-console.
- **Supervisor binary entitlement (Plan 97 Security §2 / §11).**
  `mvm-vz-supervisor` is ad-hoc codesigned with
  `com.apple.security.virtualization` (the minimum Vz requires).
  No JIT, no library validation override, no plugin loading.
  `tools/build.sh` invokes `codesign --options runtime --entitlements
  Entitlements.plist`; verified at install time via
  `codesign -d --entitlements -`.
- **Kernel-cmdline lockdown (Plan 97 Security §7).**
  `VmStartConfig` has no user-supplied cmdline field; the backend
  constructs from `DEFAULT_CMDLINE = "console=hvc0 root=/dev/vda rw
  init=/init"`. Verity-token injection (`dm-mod.create=`,
  `mvm.runtime_roothash=`) is gated on the verified-boot pipeline
  targeting Vz (claim 3 follow-up).

## Relationship to other ADRs

- **ADR-001 (microvm security posture).** Adds a Vz row to the
  per-backend claim table at `specs/adrs/001-microvm-security-posture.md`.
  Tier 2; claim 3 partial (matches libkrun's posture).
- **ADR-013 (libkrun pivot).** Vz *adds* a parallel macOS backend; it
  does not retract ADR-013's decision to use libkrun as the macOS
  default. libkrun remains the macOS auto-select pick.
- **ADR-046 (two artifact layers).** Source-checkout builds never
  download mvm-published artifacts. The build.rs at
  `crates/mvm-vz/build.rs` invokes
  `crates/mvm-vz-supervisor/tools/build.sh` to build the Swift
  supervisor binary locally; no prebuilt path until a release is
  explicitly cut.
- **ADR-055 (passt + gvproxy networking).** Unchanged. The Vz
  supervisor's `Network.swift` connects a SOCK_DGRAM unix socket to
  gvproxy's `--listen-vfkit` endpoint and wraps it in
  `VZFileHandleNetworkDeviceAttachment`. No new frame parser
  introduced.

## Alternatives considered

- **Use Vz to replace libkrun entirely.** Rejected. The user
  constraint was explicit: libkrun stays the macOS default. Vz is
  additive. ADR-013's reasoning (cross-platform consistency,
  Linux + macOS parity) still holds — libkrun runs on both Linux
  KVM and macOS Hypervisor.framework, Vz is macOS-only.
- **Use Vz on Linux too via `cloud-hypervisor`-style wrapping.**
  Out of scope. ADR-055 + ADR-013 establish Firecracker as the
  Linux deploy default; Vz literally doesn't exist on Linux. The
  Plan 97 §"Out of scope" line is explicit.
- **Wrap Vz inside libkrun instead of bypassing it.** Doesn't make
  sense architecturally — libkrun is a C library; Vz is a Swift
  framework. There's no in-process way to combine them, and the
  whole point of using Vz directly is to skip libkrun.
- **Use Apple's higher-level `Containerization` framework
  (i.e. Apple Container) instead.** Already in the stack
  (Plan 75 / `AppleContainerBackend`). Apple Container only ships
  on macOS 26+ Apple Silicon; Vz fills the coverage gap and skips
  the container abstraction.

## Out of scope

- Vz on Linux (Vz is macOS-only by Apple's design).
- Live VM migration across hosts (Vz does not expose it).
- HVF concurrent-VM cap probe (Vz lacks a direct API for the
  ceiling; reactive classification needs structured supervisor exit
  codes — follow-up).
- Tenant-driven kernel cmdline (no field today; verity-token
  injection lands when the dm-verity pipeline targets Vz).
- mvmd backend-enum adoption (cross-repo follow-up after this
  ADR lands).

## Future work

- **Verified-boot pipeline for Vz** — flips claim 3 from
  DoesNotHold to Holds. Needs the rootfs build to emit verity
  sidecars + roothash that `build_supervisor_config` threads into
  the kernel cmdline (`dm-mod.create=`,
  `mvm.runtime_roothash=`). Same artifact-pipeline pieces libkrun
  needs.
- **Performance baseline numbers** — Plan 97 §"Performance
  baseline" commits to a CI lane comparing cold-boot wall time,
  idle memory, and build wall time for Vz vs. libkrun-direct
  vs. nested libkrun→Firecracker. The CI lane lands with the
  macOS test matrix. GHA-hosted macOS does not expose
  Hypervisor.framework to user processes, so this gates on a
  self-hosted runner; the **`vz-macos-26`** lane in
  `.github/workflows/ci.yml` is the placeholder, gated on
  `vars.MACOS_26_AVAILABLE`.
- **Snapshot RESTORE live-host acceptance smoke** — Phase E shipped
  both SAVE and RESTORE end-to-end with `mvmctl snapshot save/restore
  <vm> --path <p>`, machine-identifier sidecar persistence
  (`<snapshot_path>.machine-id`), SHA-256 hash-pinning, and
  audit-chain match labelling (`verified` / `mismatch` /
  `not_in_chain`). The residual is a live macOS 14+ runner that
  actually boots a dev-shell VM, saves it, kills it, restores it,
  and asserts the guest's `/proc/sys/kernel/random/boot_id` /
  `machine-id` survives the round-trip. Pairs with the
  `vz-macos-26` self-hosted runner work.
- **`VzBuilderVm` orchestration** — Phase C primitive
  (`VzBackend::run_attached`) is in place. The full builder-VM
  impl needs the seam refactor sketched in
  `specs/plans/97-vz-backend.md` §"Phase C seam design": lift the
  ~850 lines of hypervisor-agnostic orchestration from
  `LibkrunBuilderVm` behind a new `VmBackendForBuilder` trait,
  then `VzBuilderVm` reuses it with a Vz-side mount glue.
  Estimate: ~400-line impl + ~200-line glue once the seam exists.

  **Persistent builder variant (Plan 98 Slice 2A)** — ships
  `VzPersistentBuilderVm` parallel to `LibkrunPersistentBuilderVm`,
  reusing the same `mvm_vz::SupervisorConfig` surface this ADR
  introduced. Full design — selection policy, state-dir prefix
  isolation under `~/.cache/mvm/builder-vm/vms/`, and
  security-claim parity across both backends — lives in ADR-046
  §"Vz as a second builder backend (Plan 98)".
- **mvmd `BackendKind::Vz` adoption.** Cross-repo. Tracked under
  Plan 97 §"mvmd integration".
- **Windows host support via WHP.** Cataloged as a separate
  initiative — see [#428](https://github.com/tinylabscom/mvm/issues/428).

## Addendum (2026-06-07): Rust-native supervisor — threading model (Plan 152 WS-B)

Plan 152 reverses Plan 97's "keep the Swift supervisor" call: the VZ
supervisor moves to a Rust `[[bin]]` in `mvm-vm-host`, still a separate
per-VM codesigned process. The entitled-TCB invariant was always about
process separation, not language — `mvmctl` stays unentitled, the supervisor
carries `com.apple.security.virtualization` alone. `objc2`,
`objc2-virtualization`, `block2`, and `dispatch2` are already workspace deps
(the `apple_container` backend uses them), so the move adds no third-party
dependency. This addendum records the one decision WS-B was gated on — the
supervisor's threading model — from which the rest of WS-B follows.

**Decision: a private serial `DispatchQueue` + `VZVirtualMachineDelegate`,
not a main-thread `CFRunLoop`.** The shipping Swift supervisor already runs
exactly this shape: one serial `DispatchQueue("mvm.vz.supervisor")` passed to
`VZVirtualMachine(configuration:queue:)` services the VM, the control socket,
the vsock proxy, and the SIGTERM/SIGINT sources; the delegate's `guestDidStop`
/ `didStopWithError` fire on that queue; the start path blocks on a
`DispatchSemaphore`. Porting it 1:1 — `dispatch2` serial queue,
`declare_class!` delegate, `block2::RcBlock` completion handlers,
`QueueBound<Send>` for the `!Send` `Retained` handles — makes the mandatory
parity matrix a true apples-to-apples comparison of a known-good design,
which is the risk posture re-implementing a security-sensitive component
demands.

A main-thread `CFRunLoop` (one reviewed reference's model, and roughly what
`apple_container` does with NSRunLoop) was rejected. For a one-VM-per-process
supervisor it pins VZ to the main thread, still needs worker threads for the
control socket + vsock proxy, forces `main()` to be a runloop pump contending
with the async I/O runtime for thread ownership, and diverges from the proven
design for no payoff.

**I/O layer: a tokio current-thread runtime, never blocking accept loops.**
The control socket and vsock proxy run on a single-threaded tokio reactor
(`tokio = { features = ["rt", …] }` — `rt`, deliberately not
`rt-multi-thread`); the dup'd guest vsock fd is driven through `AsyncFd` and
spliced with `copy_bidirectional`, which gives correct half-close and
backpressure without a hand-written state machine. tokio is already in the
workspace lock and `AsyncFd` needs its reactor regardless, so this buys async
I/O at no new dependency cost. The supervisor then runs two single-purpose
schedulers: the VZ serial dispatch queue (libdispatch) owns every VZ API
call; the current-thread tokio reactor owns I/O. tokio tasks hop onto the VZ
queue only for the VZ calls themselves (`connect(toPort:)`, `pause`/`resume`/
`save`/`restore`), getting results back over a `oneshot`. `dispatch2`
`DispatchSource` read sources — a zero-new-dep, even-more-1:1 port of the
Swift sources — were considered and rejected: they would mean hand-rolling
the bidirectional splice, the wrong place to economize.

**`unsafe` surface.** Exactly one `unsafe impl Send for QueueBound<Retained<…>>`,
under the invariant that the wrapped handle is dereferenced only inside a
closure dispatched onto the VZ serial queue, never from a tokio worker. Each
`unsafe` block cites that invariant.

Security posture is unchanged from the per-claim table above. The rewrite
keeps the signed/audited `ExecutionPlan` admission (claim 8), the
capture-only console lockdown, the resource-cap parity check, and the
codesigned separate-process entitlement boundary — `apple_container::
ensure_signed()` is extended to sign the Rust binary with
`com.apple.security.virtualization`. The Swift crate is deleted only after the
WS-B parity matrix (boot, vsock round-trip, every control verb, save/restore)
is green; the entitled-TCB / drop-Swift rationale is the deferred Plan 97
note, now resolved.

## Addendum (2026-06-08) — Swift supervisor removed; Rust is the sole VZ supervisor

Plan 152 WS-B is complete. The Rust-native `objc2` supervisor (`mvm-vm-host`
`[[bin]] mvm-vz-supervisor`, landed in #700, live-validated boot / vsock /
control / save-restore) is now the **only** VZ supervisor. The Swift crate
(`crates/mvm-vz-supervisor/`), its `tools/build.sh` / `Package.swift` /
`Entitlements.plist`, and the `mvm-build/build.rs` auto-build hook are deleted;
`resolve_supervisor_path` (in `mvm-backend::vz` and the doctor chain) resolves
only the cargo-built Rust binary (override → adjacent-to-exe → release
`~/.mvm/bin/`), mirroring `mvm-libkrun-supervisor`.

**Motivating defect.** Running the WS-B parity gate live on macOS 26 revealed the
Swift control socket **self-deadlocks** on async VZ ops: `synchronousVZCall`
does `sema.wait()` on the VM's own serial `DispatchQueue` while
`vm.pause/resume/save`'s completion handler is dispatched back to that same
queue, wedging it after the first verb. The Rust supervisor's serial-queue→tokio
bridge (the WS-B threading decision) avoids this. Because the Swift baseline was
broken on PAUSE/RESUME/SAVE, byte-for-byte parity was unachievable and
undesirable; the gate (`crates/mvm-build/tests/vz_supervisor_parity.rs`) now
asserts **Rust correctness** directly rather than equivalence to a buggy
baseline.

**Follow-ups (tracked, not in this change):** dead-code sweep of the legacy
`BridgeEndpoints::VzIngest` + `mvm-vz-drainer` NDJSON ingest path (superseded by
the Rust supervisor's in-process `VzGvproxy` splice); the `workflow_dispatch` vz
lanes in `ci-full.yml` also carried pre-existing `-p mvm-vz` staleness from the
Plan 121 crate consolidation (repointed to `mvm-build`/`mvm-vm-host` here).


## Consolidated from ADR-072 — QEMU as the dev/builder backend; Firecracker stays the production runtime

**Status**: Proposed
**Date**: 2026-06-05
**Cross-refs**: ADR-001 (Firecracker-only *execution* — the production runtime path), ADR-001 (security posture / per-backend tier matrix), ADR-055 (passt/gvproxy virtio-net), ADR-022 §1 (name by role, front with a trait, hide impls), ADR-068 (Stage 0 dispatches through the `BuilderVm` trait), Plan 98 (`98-vz-builder-vm.md` — builder-backend selection libkrun/vz). Planning input: Plan 164 (multi-arch embed — surfaced the Linux provisioning pain that motivated this) + Plan 166 (this ADR's implementation).

## Context

On Linux, two distinct VM roles are both pinned to KVM-only VMMs:

- **The dev/builder substrate** — the builder VM that runs `nix build` (and the `mvmctl dev` shell). Today this is **libkrun** (the Plan 98 default on Linux), which on Linux uses `/dev/kvm`.
- **The workload runtime** — where tenant code actually runs. This is **Firecracker** (ADR-001), which requires `/dev/kvm` by design (the microVM is the security boundary).

Three problems fall out of pinning the *dev/builder* role to a KVM-only, hard-to-provision VMM:

1. **No-KVM hosts can't dev at all.** CI runners without nested virt, nested VMs, and restricted containers have no `/dev/kvm`, so neither libkrun nor Firecracker runs — the whole build/dev loop is unavailable, not just the (correctly KVM-gated) production runtime.
2. **libkrun is painful to provision on Linux.** It is not packaged on Debian/Ubuntu; bringing it up means building `libkrun` + `libkrunfw` from source (the latter compiles a kernel), installing `lld`/`clang`, and chasing `lib64` linker paths. Bringing up the Plan 164 x86_64 box took hours for exactly this.
3. **passt friction.** The Linux libkrun path needs passt (ADR-055), which self-sandboxes and stumbles on root priv-drop (`getpwnam: Permission denied`) — more setup surface for what is only a *dev* substrate.

Meanwhile the `VmBackend`/`AnyBackend` dispatch already supports many VMMs behind a trait (Firecracker, libkrun, Vz, Cloud Hypervisor, Apple Container, Docker, a microvm.nix runner, mock), `AnyBackend::auto_select` already favors Firecracker whenever `/dev/kvm` is present, and the builder side has its own `BuilderBackendChoice{Libkrun, Vz}` (Plan 98) fronting the `BuilderVm` trait (ADR-068). Adding a VMM is an impl, not a new pattern.

QEMU is the obvious fit for the *dev/builder* role: it is packaged everywhere (`apt`/`dnf`/`brew`), uses KVM when `/dev/kvm` is present (fast) and falls back to TCG software emulation when it is not (slow, but it *works anywhere*), needs no passt (user-mode `-netdev user`/slirp is zero-config), and can even emulate the other arch for cross-arch dev/test.

## Decision

**Add QEMU as a dev/builder-tier backend. Firecracker remains the sole production workload runtime — `/dev/kvm`-gated, and favored whenever KVM is present. QEMU never ships as a production runtime.**

**Platform scope: QEMU is the *Linux* dev/builder backend.** On macOS the built-in equivalent already exists — **Vz** (Apple Virtualization.framework ships with the OS, runs on Hypervisor.framework with no `/dev/kvm`, and is the macOS-26+ builder default with no third-party install; CLAUDE.md "Builder backend selection"). So the apt-vs-build-from-source portability win that motivates QEMU is a Linux concern; macOS uses Vz. The per-OS story:

- **macOS** → Vz (built-in) for dev/builder.
- **Linux** → QEMU (apt-installable) for dev/builder; Firecracker (KVM) for the production runtime.
- libkrun becomes optional/legacy on both (from-source pain on Linux; Vz supersedes it on macOS).

**Sibling gap — the builder VM needs networking on *both* VMMs.** The Vz *builder* VM is configured `network: None` today, so a cold `nix build` on it fails with the same "Could not resolve github.com" the Linux libkrun+passt path hit (masked only by libkrun-fallback in auto-detect; the Vz dev/workload VM already uses gvproxy). So the symmetric work is: **Linux = QEMU + slirp** (this ADR), **macOS = wire the Vz builder to gvproxy** (a separate, parallel task — *not* QEMU on macOS).

Two insertion points, mirroring the two roles:

1. **Builder VM** — add `Qemu` to `BuilderBackendChoice` (alongside `Libkrun`, `Vz`) implementing the `BuilderVm` trait (`run_build` + `run_stage0`, ADR-068). QEMU becomes the portable, trivially-provisioned Linux builder: KVM-accelerated where available, TCG where not.
2. **Dev/test workload runtime** — add a real `Qemu(QemuBackend)` variant to `AnyBackend` (replacing the vestigial `from_hypervisor("qemu") → MicrovmNix` alias) so a workload can be *run for dev/test* on a no-KVM host. This is a **dev tier only** — it is outside the ADR-001 security claims and is never selected for production.

### Production favors Firecracker — non-negotiable

- `AnyBackend::auto_select` keeps **Firecracker at Tier 1** whenever `platform::supports_native_runner()` (native Linux `/dev/kvm`) is true. QEMU is selected only when (a) there is no `/dev/kvm` *and* the caller is in a dev/test context, or (b) it is explicitly requested (`--hypervisor qemu` / `--builder qemu`).
- The **`--prod` admission gate (in mvmd, not mvm)** refuses QEMU outright: production requires an admitted Firecracker launch on real KVM. A `--prod` run on a no-KVM host fails closed with "Firecracker requires /dev/kvm" — it does **not** silently fall back to QEMU.
- Firecracker's `/dev/kvm` requirement becomes an explicit, fail-closed probe with a clear hint (use a KVM host for production, or the QEMU dev backend for local iteration) rather than an opaque spawn error.

### Networking

The QEMU dev backend defaults to **user-mode networking** (`-netdev user`, slirp) — zero-config, no passt/gvproxy, no root priv-drop. passt/`-netdev` socket parity with the Firecracker path (ADR-055) is an optional follow-on for dev that wants closer-to-prod network behavior, not the default.

### Security framing

QEMU is a **dev tier**, classified like the builder VM (ADR-001 out-of-scope for the hardened workload claims):

- **KVM-backed QEMU → Tier 2** (`tier2-fast-local`): real hardware virtualization, but unaudited against ADR-001.
- **TCG QEMU → Tier 3** (`tier3-fallback`): software emulation, no isolation guarantees; `mvmctl up`/`doctor` emit the loud Tier-3 banner already used for the Docker fallback.

Neither tier is ever promoted to production. The security claims (1–14) remain Firecracker/libkrun-specific; QEMU adds no claims and removes none.

## Consequences

- **Dev works everywhere.** A laptop, CI runner, or nested VM with no `/dev/kvm` can run the full build loop (TCG) and dev/test workloads — the production runtime stays correctly gated.
- **Linux provisioning collapses to a package install.** `apt install qemu-system-x86 qemu-utils` replaces libkrun-from-source for contributors and CI who only need the dev/builder substrate.
- **No change to the production path or ADR-001.** Firecracker remains the only runtime that executes admitted workloads; ADR-001 governs that path and is untouched. The builder VM already uses a non-Firecracker VMM (libkrun), so a QEMU builder is consistent, not novel.
- **One more backend to maintain** — QEMU argv/console(serial-or-vsock)/networking/lifecycle behind the existing trait. Bounded, but real.
- **TCG is slow.** Heavy nix builds under pure emulation are painful; the rule is KVM-where-present, TCG-only-as-fallback, with a loud "running unaccelerated" warning so the slowness is never a surprise.
- **libkrun stays supported** as a Linux builder option; QEMU becomes the recommended default for portability + provisioning ease (the default-flip is decided in Plan 166, behind doctor visibility).

## Alternatives considered

- **Keep libkrun-only on Linux.** Rejected: leaves no-KVM hosts unable to dev and keeps the from-source provisioning tax.
- **QEMU as a production runtime too.** Rejected: forks the security story (TCG has no isolation; KVM-QEMU is unaudited vs ADR-001) and contradicts ADR-001. QEMU is dev/test only; production favors Firecracker.
- **Reuse the existing `MicrovmNix` ("qemu") path.** Rejected as the primary mechanism: it boots via a microvm.nix runner script, not a directly-driven QEMU process, so it can't offer the KVM/TCG portability or the zero-config dev networking. Plan 166 retires the `"qemu" → MicrovmNix` alias in favor of the real backend.


## Consolidated from ADR-076 — Backend matrix consolidation (8 → 4) and AVF convergence

**Status:** accepted 2026-06-10. Implemented by
`specs/plans/177-backend-consolidation.md`. **Amends ADR-056** (Vz is no
longer opt-in — it becomes the macOS-26 default and absorbs
`AppleContainerBackend`) and **ADR-001** (the per-backend tier matrix loses
four rows — the matrix edit lands with Plan 177). Cross-refs: ADR-001
(multi-backend execution), ADR-013 (libkrun pivot), ADR-007 (single
`VmBackend` trait), ADR-022 (target architecture), ADR-025 (warm-snapshot
prior-art boundary).

## Context

`AnyBackend` (`crates/mvm-backend/src/backend.rs`) dispatches **eight**
`VmBackend` impls plus a mock: libkrun, firecracker, vz, apple_container,
docker, cloud_hypervisor, qemu, microvm_nix. Each is a module + trait impl
+ `from_hypervisor`/`auto_select`/`from_pid_files`/`tier`/`all()` wiring + a
`doctor` row + CI lanes. The matrix grew opportunistically; coupling and use
do not justify its width:

- `docker` (~450 LOC, Tier-3 "fallback") contradicts the project invariant
  "no Docker on the runtime path" (ADR-001). It is reachable only as an
  auto-select fallback and `doctor`/`ps` rows.
- `cloud_hypervisor` (~484 LOC, ~13 refs) is a second Tier-1-hardened
  Linux-KVM backend beside Firecracker with no auto-select path. Firecracker
  is the canonical Linux workload VMM (ADR-001); CH doubles hardened-tier
  maintenance for ~zero current use.
- `qemu` (~1,011 LOC) and `microvm_nix` (~299 LOC) are *both* Tier-2,
  dev/test-only, never auto-selected — two backends for "run locally without
  KVM."
- `vz` and `apple_container` are **both** Apple Virtualization.framework via
  `objc2` — neither uses Apple's Containerization framework (the
  `apple_container` name is a misnomer; the provider header reads "macOS
  Virtualization.framework VM lifecycle using objc2-virtualization", and its
  "Containerization / Swift-FFI / stub" doc header describes a design never
  built). They differ only in **process model**: `VzBackend` runs a per-VM
  supervisor (`mvm-vz-supervisor`, Rust objc2 since ADR-056's 2026-06-08
  addendum), `AppleContainerBackend` runs `VZVirtualMachine` **in-process**
  (raw `!Send` pointers). The in-process path reports `snapshots: false` and
  stubs pause/resume; the supervisor path implements real snapshot/restore
  (`saveMachineStateTo`/`restoreMachineStateFrom`) and pause/resume.

The cost is paid in the two pains driving the wider feature-reduction
effort: **cognitive load** (a change touches eight dispatch surfaces) and
**maintenance** (every backend is a CI lane and a refactor tax).

## Decision

Reduce the matrix to **four** backends (+mock): **libkrun, firecracker, vz,
qemu**.

1. **Delete `docker`.** Removes a runtime-path Docker affordance that should
   not exist, and a dead Tier-3 fallback.
2. **Delete `cloud_hypervisor`.** Firecracker is the sole Tier-1 Linux VMM.
3. **Fold `microvm_nix` into `qemu`.** Keep `QemuBackend` (the real TCG
   dev/test impl); delete `MicrovmNixBackend`; migrate `from_build_output`
   onto `QemuBackend`, porting any microvm.nix-specific config field.
4. **Converge AVF on the supervisor model.** Keep `VzBackend` (per-VM Rust
   objc2 supervisor, snapshot/restore, pause/resume); delete the in-process
   `providers/apple_container` path and `AppleContainerBackend`; expose one
   honestly-named `vz` AVF backend and make it the **macOS-26 auto-default**
   (reversing ADR-056's "opt-in only / libkrun stays the macOS default" for
   the macOS-26 tier). Port the in-process path's unique behaviors
   (admission-gate ordering, CoW per-instance rootfs clone, `runtime_meta`
   recording) onto `VzBackend`. Reattach the macOS-26 dev console over the
   supervisor's vsock via a **shared libkrun+vz console transport** (the
   pattern libkrun already uses) — a dedup, not a new mechanism. Drop the
   `apple-container` CLI input (no backcompat).

### Why the supervisor model wins the AVF convergence

- **Capability.** The supervisor path owns snapshot/restore — the
  warm-start / checkpoint / fork foundation (ADR-025, Plan 153). Keeping the
  in-process path as the survivor would amputate it.
- **Isolation.** One process per VM matches `LibkrunBackend`'s contract
  (uniform host architecture = less cognitive load), contains crashes,
  isolates the `!Send` `VZVirtualMachine` hazard, and gives each VM a
  sandboxable process boundary — load-bearing for the untrusted-workload
  posture (ADR-001, ADR-022 §"process isolation ≠ crate count").
- **Prior art.** The best-regarded external Rust AVF driver tools are
  themselves daemon-mediated (CLI → runtime daemon over UDS → AVF). The
  supervisor model *is* that architecture; mvm runs one supervisor per VM
  rather than one daemon for all, a deliberate isolation choice for the
  threat model.

The one real cost is the console reattach, which doubles as a libkrun+vz
console dedup. No capability is sacrificed.

## Sequencing

The AVF convergence is **gated** on the in-flight Plan 152 VZ-supervisor
work (`feat/plan-152-wsb-rust-vz-supervisor`,
`feat/plan-152-fix-vz-save-pause`) merging to `main` — it rewrites the
surface this decision edits. The three non-AVF cuts (docker,
cloud_hypervisor, microvm_nix→qemu) carry no VZ dependency and land first.
Plan 177 encodes this as Phase 1 (cuts) → Phase 2 (gated AVF).

## Security posture

No claim regresses. The deleted backends carried no unique claim coverage
(`docker` is Tier-3 and never workload-bearing; `cloud_hypervisor`'s Tier-1
claim-3 path was "in flight", unshipped; `microvm_nix` folds into `qemu`,
unchanged Tier-2 dev/test). The surviving `vz` keeps ADR-056's per-claim
table and the claim-15 capture-only / sealed-console invariants
(`prod_console_attachment_has_no_input`, `console_refused_on_sealed_image`)
through the shared console transport.

## Alternatives considered

- **Keep all eight, document better.** Rejected — documentation does not pay
  the per-backend CI and refactor tax; the pains are A (cognitive) and B
  (maintenance), which only deletion addresses.
- **Converge AVF on the in-process model** (delete `VzBackend`, avoid the
  console reattach). Rejected — sacrifices snapshot/restore, pause/resume,
  crash isolation, and the warm-start future to save a bounded one-time
  task. Trades a permanent capability for convenience.
- **Keep `cloud_hypervisor` for future VFIO/GPU passthrough.** Deferred, not
  kept — when a workload genuinely needs VFIO, re-add a backend then (YAGNI).
  The ADR-001 matrix note about CH's VFIO niche is removed with the row.

## Out of scope

- The DX-parity follow-on (surface `save`/`restore`, cached fast-boot
  default, base pinning) — its own plan after Plan 177 lands.
- mvmd's backend-enum adoption (cross-repo).
- Re-adding any deleted backend (a future need writes its own ADR).


## Consolidated from ADR-093 — Linux builder: auto-fallback over libkrun, default unchanged

**Status:** Proposed
**Date:** 2026-06-22
**Relates to:** [ADR-001](001-microvm-security-posture.md) §"Per-backend tier
matrix", [Plan 98 — builder backend selection](../plans/98-vz-builder-vm.md),
[Plan 166 — QEMU dev builder backend](../plans/166-qemu-dev-builder-backend.md)

## Context

The builder VM — the Linux guest that runs `nix build` for `mvmctl build` /
`up` / `dev` / `machine run --image` — picks a host VMM. Plan-98 auto-detect:
macOS 26+ Apple Silicon → Vz; **everywhere else → libkrun**.

On a bare-metal Linux box (Intel i7-7700, kernel 6.1, 62 GiB RAM, libkrun
1.18.0) the libkrun builder **cannot create its VM**: libkrun's
`KVM_SET_USER_MEMORY_REGION` ioctl returns `EINVAL` (`rc -22`) for any guest
memory region spanning above ~4 GiB (the region above the PCI hole). Surfaced
via `MVM_KRUN_LOG=trace` as `Internal(Vm(SetUserMemoryRegion(Error(22))))`, and
confirmed by experiment: a 16 GiB and an 8 GiB builder VM both fail at memory
setup; a 2 GiB VM boots past it but is far too small for a `nix build` (which
peaks at 5–6 GiB). The builder fundamentally needs >4 GiB, so this is **not
tunable** — and it is a libkrun/kernel defect, not an mvm bug; mvm cannot make
that ioctl succeed.

The QEMU/microvm_nix builder (Plan 166) works on the same box — proven live: an
alpine microVM materialized via qemu and booted through Firecracker on
`/dev/kvm`.

Two tensions:

- The "Key Design Decisions" prose in `CLAUDE.md` says builds run "Firecracker
  on Linux KVM," but the dispatch (`resolve_stage0_backend` /
  `resolve_builder_backend`) only implements **libkrun / vz / qemu** —
  firecracker-as-*builder* is not wired. The real Linux default is libkrun.
- The qemu builder is documented "`mvm`-only dev/test, never `mvmd`" — so it is
  available to the *local* dev/build path but must not become the fleet
  builder.

Before this work, a Linux user on an affected host hit an opaque
`materialize OCI rootfs failed: rc -22` with no hint that `--builder qemu`
(which works) is the escape.

## Decision

1. **Keep the Plan-98 auto-detect default unchanged** — Linux still defaults to
   libkrun. We do **not** flip the Linux default to qemu.
2. **Add a transparent VMM-level auto-fallback.** When an *auto-detected* (not
   explicitly forced) builder fails to **create its VM** — a VMM-level failure,
   distinguished from a genuine build error by the new
   `BuilderVmError::SupervisorExited` variant — the dispatch retries the next
   backend. On Linux that order is libkrun → qemu; on macOS it preserves the
   pre-existing auto-Vz → libkrun behaviour. A genuine `nix build` failure
   surfaces unchanged with no retry, and an explicit `--builder` /
   `MVM_BUILDER_BACKEND` opts out entirely.

One pure policy drives every builder entry point — OCI materialize, the
`dev_build` flake path (`up --flake` / `build image` / `template build`),
Stage 0 bootstrap, and the dev-image / default-microvm CLI loops —
(`builder_attempt_order` + `run_with_builder_fallback{,_anyhow}` +
`resolve_stage0_backend_for_choice`), so the CLI loops and the `mvm-build`
build paths cannot drift. Implemented in PRs #1237 + #1239 and live-proven:
`machine run --image alpine` with no `--builder` falls back libkrun → qemu and
boots.

## Alternatives considered

### Flip the Linux default to qemu — rejected (for now)

- The evidence is a **single host**. The defect is tied to a specific
  libkrun/kernel/hardware combination and is not proven universal; libkrun may
  create its VM fine on many Linux boxes. Flipping the default would penalize
  every healthy Linux host — qemu/microvm_nix boots slower and adds a heavier
  dependency (`qemu-system-*`) where libkrun needs none.
- The fallback cost on an *affected* host is bounded: libkrun fails fast at VM
  creation (~seconds, no boot), then qemu runs. That is far cheaper than
  slowing the healthy majority.
- If future data shows libkrun-on-Linux is broadly broken rather than
  host-specific, revisit — flipping is then a one-line change to
  `auto_detect_default_for` / `builder_attempt_order`.

### Wire firecracker-as-builder now — deferred

`CLAUDE.md` names Firecracker as the intended Linux builder, but it is a fourth
`BuilderVm` implementation (its own `run_build` / `run_stage0` /
`run_shell_script`) — a separate, larger project. The qemu fallback unblocks
Linux users today; firecracker-as-builder remains the longer-term direction and
is tracked as a follow-up. Until it lands, the `CLAUDE.md` "Firecracker on Linux
KVM" builder line is corrected to describe the real default (libkrun + qemu
fallback).

## Consequences

- Linux `build` / `up` / `machine run --image` / `dev up` work out of the box
  even where libkrun cannot create its VM — no `--builder` knowledge required.
- A genuine build error still surfaces immediately (the fallback fires only on a
  VMM-level failure), and explicit `--builder` is honoured.
- The qemu builder is reached only by the **local** dev/build path, not mvmd's
  `pool_build` — staying inside its "`mvm`-only dev/test" boundary
  (ADR-001 §"Per-backend tier matrix").
- On an affected host every build pays a one-time ~5s libkrun-failure before
  qemu takes over. A per-host "libkrun builder unhealthy" cache to skip the
  doomed attempt is possible but out of scope.

## Follow-ups

- Determine whether the libkrun >4 GiB `KVM_SET_USER_MEMORY_REGION` EINVAL is
  universal-on-Linux or host-specific; feed the result back into this default
  decision.
- Implement firecracker-as-builder (the long-stated Linux intent) or keep the
  doc aligned with the libkrun + qemu-fallback reality.
- Optional: persist a per-host "libkrun-builder-unavailable" marker so affected
  hosts skip the failing libkrun attempt on subsequent builds.

## Update (2026-06-22): root cause corrected — unaligned kernel, fixed in mvm

The "`KVM_SET_USER_MEMORY_REGION` EINVAL for any region above ~4 GiB" diagnosis
above was **incomplete**. `strace -f` of the failing supervisor on the same box
showed the rejected ioctl is the **kernel** region, not a RAM region above the
PCI hole:

```
ioctl(KVM_SET_USER_MEMORY_REGION, {slot=1, guest_phys_addr=0x80000000,
      memory_size=8963072, ...}) = -1 EINVAL
```

`memory_size=8963072` is exactly the builder `vmlinux` file size, and
`8963072 % 4096 = 1024` — **not page-aligned**. Linux KVM requires
`KVM_SET_USER_MEMORY_REGION` sizes to be a multiple of the host page size; mvm
passed the kernel to libkrun (`krun_set_kernel`), which maps it verbatim, so an
unaligned `vmlinux` fails VM creation regardless of guest RAM. macOS HVF imposes
no such requirement — which is why the identical (also-unaligned) aarch64 builder
kernel boots under libkrun on macOS. So this **is** an mvm-addressable bug, not
purely a libkrun/kernel defect.

On the **"2 GiB boots past it" anomaly**: the rejected region is slot 1, the
*kernel*, whose size is the `vmlinux` file size — independent of how much guest
RAM is configured. So a smaller-RAM run must hit `EINVAL` at this *same* ioctl;
guest-RAM size cannot explain the difference. The earlier "2 GiB boots" reading
was never reproduced under `strace` and is **not** explained by this root cause —
most plausibly that run used a different, already-aligned kernel build (or never
reached slot 1 for an unrelated reason). We record it as an unexplained prior
observation rather than attribute a mechanism we can't substantiate; the
strace-confirmed alignment defect above is the real, reproduced cause.

**Fix:** `mvm_build::libkrun_builder::page_aligned_kernel` zero-pads the builder
kernel up to a page boundary (a cached `vmlinux.page-aligned` sibling) before
`krun_set_kernel`. Confirmed on the box: with the unaligned kernel on disk, the
code auto-creates the aligned sibling, every `KVM_SET_USER_MEMORY_REGION`
succeeds, and `KVM_RUN` runs the vCPUs (the EINVAL is gone).

This does **not** retire the qemu fallback: it still covers other VM-creation
failures, and at least one affected host shows a *separate* later issue (the
guest userspace does not reach `cmd.sh` under libkrun — empty console, no nix
output), tracked separately. The fallback stays; this fix removes the
unaligned-kernel EINVAL as one of its triggers.


## Consolidated from ADR-094 — Fold the external-VMM bridge sidecars into one `mvm-bridge`; keep libkrun merged

**Status:** Accepted
**Amends:** [ADR-001](001-microvm-security-posture.md) — its per-backend tier matrix (the external-VMM backends share one bridge-sidecar process) and its consolidated-in ADR-083 section (the shared egress/audit funnel gains a single, shared transport process for FC + vz instead of two near-identical ones).
**Preserves:** every numbered claim — in particular claim 10 (default-deny egress), claim 12 (binding-gated host services), and claim 13 (no raw secret over the broker channel), all of which ride the gateway bridge. The `spawn_bridge_thread` enforcement core is unchanged; signed-plan admission ([ADR-014](014-signed-audited-execution-plans.md)) is untouched.
**Relates:** does **not** drop Firecracker or pick a single VMM — it is the topology cleanup that should land *before* any future libkrun-only / backend-consolidation decision, and is independently valuable if that decision is never taken.

## Context

`mvm` runs every microVM behind a per-VM host process (one per guest, by
design — the libkrun `krun_start_enter` `exit()` semantics forbid an
in-process registry). Today those host processes come in **four** binaries
that all funnel into the same enforcement core,
`mvm_hostd::supervisor::gateway_bridge::spawn_bridge_thread`, but wrap it in
**two different process models**:

- **Split model** — `mvm-firecracker-bridge` and `mvm-vz-drainer`. The VMM is
  a *separate* process (the upstream `firecracker` binary; the
  `mvm-vz-supervisor`), and the bridge is a **thin sidecar** that reads a JSON
  config on stdin → decodes the `ExecutionPlan` → builds a `BridgeConfig` + a
  `BridgeEndpoints` variant → calls `spawn_bridge_thread`. Both sidecars are
  spawned *from the backend* with an RAII teardown guard and socketpair
  fd-inheritance (`mvm-backend::microvm::spawn_fc_bridge` +
  `AttachedBridgeGuard`; `mvm-backend::vz` + `AttachedDrainerGuard`).
- **Merged model** — `mvm-libkrun-supervisor`. One process does **both** the
  VMM (`krun_start_enter`, in-process via the `libkrun-sys` FFI) **and** the
  bridge (`spawn_bridge_thread` on a concurrent thread, "reaped by `exit()` on
  guest shutdown" —
  `crates/mvm-vm-host/src/bin/mvm-libkrun-supervisor.rs::run_with_bridge`).

The cost of the divergence:

- **The two split sidecars are ~90% identical** — same stdin contract (the
  source comments already note "the bridge's stdin contract is identical to
  `mvm-vz-drainer`'s and `mvm-libkrun-supervisor`'s"), same plan decode, same
  `spawn_bridge_thread` hand-off. They differ only in the `BridgeEndpoints`
  variant (`Passt` vs `VzIngest`) and confinement. Two binaries, two stdin
  parsers, two fuzz surfaces, for one contract.
- **Confinement is wired per-binary, not per-platform.** `mvm-firecracker-bridge`
  applies `mvm-jailer-lite` confinement (`confine_self`, seccomp + Landlock) and
  verifies the pinned passt hash; `mvm-vz-drainer` applies neither. That
  asymmetry is *mostly* a platform fact, not a pure duplication bug:
  `confine_self` is **Linux-only** — on macOS it is a stub that returns
  `SeccompUnavailable` (there is no Landlock/seccomp to apply), and the vz
  drainer only ever runs on macOS. So the consolidation does **not** newly
  confine the macOS paths (it cannot). What it *does* fix is that confinement
  becomes a single cfg-gated codepath applied uniformly to every endpoint the
  OS *can* confine (the Linux `Passt` path), instead of being open-coded in one
  bin and absent from the other — removing the duplication and the risk that a
  future Linux endpoint silently ships unconfined.
- **The libkrun supervisor carries a `BridgeFds → BridgeEndpoints` factory
  closure + a concurrent-thread-reaped-by-VMM-`exit()` dance** — which exists
  because libkrun's in-process VMM requires it (see "Why libkrun stays merged"
  under the decision). The two external-VMM sidecars carry neither.

The forcing observation: **the two external-VMM sidecars are interchangeable and
the libkrun supervisor is not.** Firecracker's VMM is an external binary and
vz's is the `mvm-vz-supervisor` process — both already use the split model
(external VMM + a thin bridge sidecar spawned by the backend), and their
sidecars differ only in endpoint variant + confinement. They fold into one
`mvm-bridge`. libkrun's VMM is an in-process library that creates the bridge fds
itself and `_exit()`s on guest shutdown, so it cannot be fed by the backend the
way an external VMM can; its merged supervisor stays. (The original proposal to
split libkrun too was abandoned on this constraint — see the decision.)

## Decision

Converge the **external-VMM backends (Firecracker, vz) on one shared
`mvm-bridge` sidecar binary**, and **keep libkrun's merged supervisor as-is**.

1. **Fold `mvm-firecracker-bridge` + `mvm-vz-drainer` into a single
   `mvm-bridge` binary.** It takes a unified `BridgeConfigJson` carrying an
   **endpoint-kind discriminant**, applies `mvm-jailer-lite` confinement
   through **one cfg-gated codepath** wherever the OS supports it (the Linux
   `Passt` endpoint; macOS `VzIngest` runs unconfined because macOS has no
   Landlock/seccomp — unchanged from today), verifies the passt hash on the
   passt endpoint only, builds the matching `BridgeEndpoints` variant, and calls
   the unchanged `spawn_bridge_thread`. The stdin contract — already identical
   in practice — is written and fuzzed once. The Firecracker backend
   (`mvm-backend::microvm::spawn_fc_bridge`) and the vz backend
   (`mvm-backend::vz`, `AttachedDrainerGuard`) spawn `mvm-bridge` with the RAII
   teardown guard + fd/path passing they already use.

2. **`mvm-libkrun-supervisor` keeps its merged in-process bridge.** The
   supervisor's `run_with_bridge` is unchanged: it calls
   `run_supervisor_with_bridge`, whose factory closure builds the bridge in the
   same process and `spawn_bridge_thread`s it.

### Why libkrun stays merged (constraint discovered during implementation)

The original proposal was to strip the bridge out of libkrun too and have the
backend spawn the sidecar, mirroring Firecracker. Implementation showed that is
not achievable without restructuring the C library, for two intrinsic reasons:

- **libkrun creates the bridge fds itself, inside the supervisor.**
  `run_supervisor_with_bridge` runs `configure_with_gateway_for_bridge` (which
  spawns passt/gvproxy and builds the socketpair *in the supervisor process*),
  then hands the `BridgeFds` to a factory closure, then `start_enter`s. Unlike
  Firecracker — where the *backend* creates the socketpair and passes fds to an
  external VMM — the fds do not exist until libkrun makes them, and only the
  supervisor holds them. The backend cannot create or pass them.
- **`krun_start_enter` calls `_exit()` on guest shutdown, skipping all Rust
  destructors.** That is the very reason the merged model exists (exit() reaps
  the bridge *thread* for free). Moving the bridge to a *process* means an
  `AttachedBridgeGuard` in the supervisor never runs, so the sidecar would leak;
  reaping would need per-platform `PR_SET_PDEATHSIG` (Linux) / `kqueue
  NOTE_EXIT` (macOS) self-termination glue.

Both are properties of **libkrun the VMM**, not our binding — confirmed against
an alternate binding (`msb_krun`), which documents the same `_exit()` behavior.
Running libkrun out-of-process to absorb the `exit()` is *exactly what the
per-VM supervisor already is*; the merged model is the architecture libkrun's
design implies, not a workaround. Forcing a split would add spawn + fd-passing +
per-platform reaping glue for no benefit libkrun doesn't already have.

The resulting per-VM topology:

```text
external-VMM backends            in-process VMM backend
[ firecracker | vz-supervisor ]  [ mvm-libkrun-supervisor ]
        +                              (merged: VMM + bridge
[ shared mvm-bridge sidecar ]           thread in one process)
```

Binaries still go from four (`mvm-libkrun-supervisor`, `mvm-vz-supervisor`,
`mvm-vz-drainer`, `mvm-firecracker-bridge`) to three (`mvm-libkrun-supervisor`,
`mvm-vz-supervisor`, `mvm-bridge`) — the reduction comes entirely from folding
the two external-VMM sidecars; the libkrun supervisor is untouched.

## Consequences

- **One bridge sidecar for the external-VMM backends.** FC + vz share a single
  binary with a single stdin parser; the `firecracker-bridge-fuzz` and
  supervisor-config fuzz surfaces converge. The libkrun in-process bridge keeps
  calling the same shared `spawn_bridge_thread` core, so the enforcement logic
  (claim 10/12/13) is still one implementation — `mvm-bridge` and the libkrun
  factory are two thin callers of it.
- **Confinement is one cfg-gated codepath in the sidecar, not per-bin
  open-coding.** Wherever the OS supports it (the Linux `Passt` endpoint) the
  sidecar applies `confine_self` uniformly. This does **not** newly confine the
  macOS `VzIngest` path — macOS has no Landlock/seccomp, so it runs unconfined
  exactly as the vz drainer did; the win is removing the duplication.
- **The merged-model concurrency stays only in libkrun, where it is the natural
  fit.** The FC/vz sidecars never had the factory-closure / thread-reaped-by-
  `exit()` shape; libkrun keeps it because its in-process VMM requires it.
- **No new process for libkrun.** libkrun keeps one process per VM (the merged
  supervisor); only FC + vz run the separate sidecar (which they already did).
- **Distribution simplifies for the external-VMM backends.** One shared
  `mvm-bridge` travels instead of two backend-specific sidecars; libkrun ships
  its supervisor as before.
- **`LibkrunGvproxy` endpoint reserved but unused.** The unified
  `BridgeConfigJson` carries a `LibkrunGvproxy` variant for completeness; no
  producer emits it while libkrun stays merged. Kept (and tested) so the
  contract is whole if libkrun is ever split upstream.

## Alternatives considered

- **Split libkrun too (the original proposal): thin krun launcher + a
  backend-spawned sidecar, mirroring Firecracker.** Rejected on an intrinsic
  libkrun constraint discovered in implementation (detailed under "Why libkrun
  stays merged"): libkrun creates the bridge fds *inside* the supervisor and
  `_exit()`s on guest shutdown, so the backend cannot feed it fds and a
  destructor-based sidecar reaper never runs. Achieving it would need a C-library
  restructure + per-platform `PDEATHSIG`/`kqueue` reaping glue for no benefit
  the merged model doesn't already provide. An alternate binding (`msb_krun`)
  was checked and documents the same `_exit()` behavior — it is a property of the
  VMM, not the binding.
- **Make Firecracker/vz adopt libkrun's merged model instead.** Rejected:
  impossible. FC's VMM is an external process; vz's is the objc2 supervisor.
  Neither can be linked in-process.
- **Leave the topology as-is; share only a library, not the binary.** A
  half-measure: it keeps two near-identical sidecar bins and two stdin parsers
  to fuzz. The duplication this ADR targets is precisely that per-binary
  plumbing, not the already-shared `spawn_bridge_thread` core.

Implementation is sequenced in Plan 211
(`specs/plans/211-vm-host-process-model-convergence.md`).


## Consolidated from ADR-095 — One slim microVM kernel, two backends, published and CVE-versioned

**Status:** Proposed
**Date:** 2026-06-21
**Relates to:** [ADR-001](001-microvm-security-posture.md),
ADR-007 §"Consolidated from ADR-046",
[ADR-003](003-hypervisor-egress-policy.md)

## Context

mvm boots two different kernels today, in very different states.

**Linux / Firecracker + the builder VM** boot a slim, hand-rolled kernel
(`nix/images/builder-vm/kernel/`): built from `defconfig` plus aggressive
enable/disable deltas and `make olddefconfig`, with `CONFIG_MODULES=n` so
everything we need is built in and there is no `/lib/modules` tree. Audio,
USB, video, DRM/FB, wireless, BT, HID, the entire SoC platform tree,
SCSI/ATA/MMC, Xen, and (on arm64) ACPI are already compiled out. A workload
variant adds dm-verity; the builder variant adds virtio-fs, namespaces +
cgroups, and an iptables egress lockdown. On this path the "tiny custom
kernel" property is largely already true — it is simply unmeasured, unnamed,
and unmarketed.

**macOS / libkrun** boots the kernel **bundled inside Homebrew's `libkrunfw`
dylib** — upstream libkrunfw 5.5.0's own config (Linux 6.12.91). We do not
control that config. This is the genuinely un-slimmed kernel in the fleet,
and the larger untapped attack-surface win.

Three forces converge on changing this:

1. **Attack surface (primary).** Every subsystem we do *not* compile in is an
   entire class of kernel CVEs that cannot apply to us. ADR-001's posture is
   the frame; a smaller kernel is fewer things that can be exploited *and*
   fewer bumps to chase when a CVE lands.
2. **Resources (secondary).** Smaller kernels boot faster and carry a smaller
   per-VM footprint — measured before/after, kept only where it moves.
3. **Claim (tertiary).** A measured, reproducible, named kernel size lets us
   credibly state a "tiny custom microVM kernel" property.

The macOS path also means a kernel CVE could otherwise force a full `mvmctl`
release, and there is no story today for rebuilding and relaunching microVMs
when a kernel vulnerability is published.

## Decision

### 1. One slim kernel, two backends

Collapse the two kernels into a **single slim `vmlinux` we own**, consumed two
ways:

- **Firecracker** — kernel path, as today.
- **libkrun** — handed our `vmlinux` at runtime via the existing
  `krun_set_kernel()` FFI in `crates/deps/libkrun-sys`, **replacing** the
  bundled libkrunfw kernel. Homebrew `libkrun`/`libkrunfw` stay installed
  (libkrun is the VMM; the bundled kernel is just a fallback we stop using).
  The historical TSI-patch requirement is moot — networking moved to
  passt/gvproxy over virtio-net (ADR-055), so a stock slim kernel has no TSI
  dependency.

The kernel module is promoted out of `nix/images/builder-vm/kernel/` to a
shared **`nix/images/kernel/`**: it is no longer builder-VM-specific, it is
*the* kernel. The existing base / builder-delta / workload-delta structure
carries over unchanged.

### 2. Gate 0 — libkrun boot-feasibility spike (hard go/no-go)

Nothing else ships until a stock slim kernel is proven to boot under libkrun.
The spike boots the *current* slim workload kernel via `krun_set_kernel()` and
must reach the guest agent over vsock, exercising: PVH/entry-point + load-
address expectations (`libkrun-sys` already computes these for `set_kernel`),
virtio-mmio/PCI discovery parity, `hvc0` console, and gvproxy/virtio-net
networking without the bundled kernel.

- **Boots →** proceed with Decision 1 as written.
- **Does not boot →** documented fallback: slim libkrunfw's *own* bundled
  config (`nix/packages/libkrunfw.nix`) for the macOS path only; Linux still
  gets the unified slim kernel. We are betting on the unified path; the spike
  is the honest off-ramp.

The spike is a throwaway branch plus a findings note appended to the
implementation plan — not production code.

### 3. Shrink methodology — disciplined subtraction

The kernel is already aggressive, so this is audit-driven subtraction, not a
rewrite:

- **Measure first.** Build the resolved `.config` and the `vmlinux`; record
  compressed + uncompressed size, `=y` symbol count, and built-object count.
  No claim without a number.
- **Subtract by audit, not by guess.** For each remaining subsystem, trace
  whether any boot path or the guest agent actually uses it (the audit
  discipline already documented in `base.nix`/`default.nix`). Each removal
  cites *why nothing uses it* in the config comment, framed in attack-surface
  terms.
- **CI size gate.** A test asserts the `=y` set stays within a named budget
  and the disabled-subsystem list does not silently regrow on a kernel bump.
  This keeps the "tiny" property true over time, not just at landing.
- **Stop rule.** Stop when the next removal breaks boot / agent-reachability
  or saves trivially. We do not chase bytes past the point of risk.

### 4. Kernel as an independently-versioned, published artifact

The kernel becomes a first-class artifact with identity
**`(kernel_version, config_hash) → artifact_hash`**:

- `kernel_version` = the upstream Linux pin; `config_hash` = hash of the
  resolved `.config`; `artifact_hash` = content hash of the built `vmlinux`.
  Any of the three changing yields a new pin.
- **Source stays in-tree** under `nix/images/kernel/`. The local-build
  invariant holds (ADR-046): a contributor editing the kernel config sees it
  in the very next `mvmctl dev up`, no release round-trip, no external cache.
- **Publish layer.** The slim kernel joins the ADR-046 prebuilt release stream
  as a **hash-verified download** — the same pattern as the dev-image
  download (per-arch `*-checksums-sha256.txt`, stream-through SHA-256,
  reject + delete on mismatch). This extends the hash-keyed GHA prebuilt the
  current `base.nix` already references.
- **Host resolves by pin.** `mvmctl` references the kernel by `artifact_hash`;
  source checkouts build locally, end-users fetch + verify the prebuilt. A new
  kernel is a new pin the host swaps in — **no `mvmctl` recompile**.
- **Dedicated kernel CI workflow** so kernel rebuilds (slow, novel,
  un-substitutable) stay off the hot PR critical path and fire only on
  config/version change.

This is what makes a kernel CVE a **kernel-only release**.

### 5. Vulnerability lifecycle — rebuild-and-relaunch

- **Model: cattle, not pets.** No in-place patching of a sealed, dm-verity
  image; live kernel patching (kpatch/livepatch) is rejected as antithetical
  to verified boot. A kernel CVE → bump `kernel_version` → new `artifact_hash`
  → relaunch on the new pin. Every image is rebuilt reproducibly from its
  definition, so remediation *is* rebuild-from-pin.
- **In scope (mvm):** the single-VM primitive — rebuild a VM from a new kernel
  pin and relaunch it.
- **Designed-for follow-ups (named, not built here):**
  - **Detection watcher** — sibling to ADR-001 claim 7's `cargo audit`: flags
    when the `linux_6_12.y` pin trails the latest LTS point release or is hit
    by a published Linux CVE. New sibling plan.
  - **Fleet rollout** — drain-and-roll across running microVMs lives in
    **mvmd**, not mvm. mvm exposes the primitive; mvmd orchestrates the fleet.

The artifact identity in Decision 4 is shaped to serve both follow-ups from
day one.

### 6. Naming hygiene

All work uses neutral, mvm-native language ("slim microVM kernel"). No
reference to any sibling project in filenames, branches, PRs, commits, code,
or specs.

## Consequences

**Positive**

- One kernel to audit, slim, version, and patch — instead of two, one of which
  we did not control.
- macOS guests stop booting an un-slimmed third-party kernel; priority C
  (attack surface) is realized uniformly across both backends.
- A kernel CVE ships as a kernel-only artifact bump — no `mvmctl` rebuild,
  no full release — and the rebuild-and-relaunch model gives a concrete
  remediation primitive.
- The "tiny custom kernel" claim becomes measured, reproducible, and
  CI-guarded rather than aspirational.

**Negative / costs**

- libkrun boot under `krun_set_kernel()` is unproven for a stock slim kernel;
  Gate 0 may force the Option 2 fallback for macOS, leaving two kernels on
  that path.
- The kernel build is slow and un-substitutable (`cache.nixos.org` has no
  hit for a novel `.config`); mitigated by the prebuilt stream + dedicated
  CI, but the first source build still pays 3–5 min.
- A published-prebuilt kernel adds release-pipeline surface (checksums,
  per-arch artifacts) that must stay hash-verified to preserve claim-6-style
  integrity.

## Alternatives considered

- **Separate repo for kernel/images** (mirroring how some peer tools structure
  their image builds). Rejected: the kernel has exactly one consumer (mvm), so
  the main benefit of a split — decoupled downstream consumers — does not
  apply, while it would add a cross-repo pin-bump to every kernel change and
  fight the ADR-046 local-build invariant. Revisit only if the kernel gains a
  consumer outside mvm. Cadence-decoupling is obtained in-tree via a dedicated
  CI workflow + the hash-keyed prebuilt.
- **Slim libkrunfw's bundled config (Option 2)** as the primary macOS path.
  Held as the Gate 0 fallback only: lower boot risk, but it keeps two kernels
  and makes us own a libkrunfw fork + its distribution against the Homebrew
  install path.
- **Live kernel patching** for CVE response. Rejected: incompatible with a
  sealed, dm-verity-verified boot image and a large new complexity/trust
  surface.
- **Welding the kernel into the `mvmctl` binary.** Rejected: it would force a
  full `mvmctl` release on every kernel CVE — the exact coupling Decision 4
  exists to break.

## Sequencing

1. **Gate 0** — libkrun boot-feasibility spike. Go/no-go.
2. **Promote + unify** — move kernel to `nix/images/kernel/`; wire libkrun's
   `krun_set_kernel()` to our `vmlinux`; reach parity on both backends.
3. **Measure + shrink** — baseline, audit-subtract, land the CI size gate.
4. **Artifact + publish** — `(version, config_hash) → artifact_hash`, the
   hash-verified prebuilt stream, host pin-resolution, dedicated kernel CI.
5. **Single-VM remediation primitive** — rebuild-from-new-pin + relaunch.
6. **Deferred follow-ups** — detection watcher (sibling plan); mvmd fleet
   rollout (mvmd repo).

The implementation plan carries the task breakdown and the Gate 0 findings
note.
</content>
</invoke>


## Consolidated from ADR-098 — Raw hypervisor as the macOS performance backend

**Status:** Accepted (2026-07-08)
**Date:** 2026-06-27
**Relates to:** [ADR-001](001-microvm-security-posture.md),
[ADR-025](025-warm-snapshot-prior-art-adoption-boundary.md),
[ADR-017](017-oci-image-verity-posture.md),
[Plan 212](../plans/212-subsecond-machine-run.md),
[Plan 214](../plans/214-clean-replacement-architecture.md),
[Research note](../research/clean-replacement-architecture-review.md)

## Context

mvm runs Linux microVMs across several host VMM backends behind one `VmBackend`
trait. On macOS there are two paths today: a high-level system virtualization
framework (the "Vz" backend), which is the auto-selected default on the newest
Apple Silicon tier, and a third-party in-process VMM. The high-level framework is
excellent for stable VM orchestration and ships with the OS, but it deliberately
hides the machine internals: it does not expose guest-memory mapping, page-granular
control, or device-state capture, and its snapshot facility is a coarse, opaque
save/restore.

mvm's product promise now includes sub-second startup, with warm starts that feel
instant. The [research note](../research/clean-replacement-architecture-review.md)
establishes that the fastest *local* warm-restore mechanism is an eager
copy-on-write mapping of the snapshot RAM section: clean pages stay shared with the
snapshot file via the page cache, dirty pages become private only on write, and
there is no userspace fault round-trip. That mechanism requires the host to map a
file-backed region and present it to the guest as RAM, plus restore vCPU and device
state around it. The high-level macOS framework cannot do this. The raw
hypervisor interface (HVF) can.

The question this ADR answers:

> Should mvm use the raw hypervisor instead of the high-level virtualization
> framework for the macOS snapshot/warm-pool performance path?

This is a backend choice behind an existing abstraction, not a change to the
product, the CLI, the library contract, or the security model. The constraint is
that it must not become VMM lock-in: a new backend is one more implementation of
`VmBackend`, selected by capability, never a special case that leaks into callers.

## Decision

**The destination is HVF as the macOS backend; Vz is transitional.** The direction
is to move macOS off the high-level framework (Vz) and onto the raw hypervisor
(HVF). The chosen *path* there is staged (Option B as a transition into Option C):
add the raw-hypervisor (HVF) backend, make it the macOS backend for snapshot and
warm-pool work as soon as it is proven, and keep Vz only as a transitional
compatibility backend that is retired once HVF meets the acceptance criteria below.
Drive selection by backend capability and by the plan's required restore-latency
class. Stage the work behind benchmarks; the only reason Vz is not deleted on day
one is that we do not remove a working backend before its replacement is proven —
not because dual-backend is the intended end state.

### Options considered

- **Option A — keep only the high-level framework.** Lowest cost and lowest risk,
  but it caps macOS warm restore at the framework's coarse save/restore latency and
  forecloses eager-CoW and snapshot internals on macOS. Rejected: it cannot meet
  the sub-100 ms warm-restore target the product needs on macOS, and it is the
  backend we want to move away from.
- **Option B — add a raw-hypervisor backend for performance; keep the high-level
  framework for compatibility.** Higher cost (we own a device model and its
  fuzzing), but it unlocks guest-memory mapping, eager-CoW restore, and low-latency
  warm restore on macOS while preserving a stable fallback during the transition.
  **Chosen as the transition mechanism, not the end state** — Vz is kept only until
  HVF proves out.
- **Option C — HVF is the macOS backend; Vz is removed.** The intended end state.
  Reached by executing Option B and then sunsetting Vz once the acceptance criteria
  pass. Not done in one step only because removing a working backend before its
  replacement is proven would risk macOS users; the staged path reaches the same
  destination safely.

### Vz sunset criteria

Vz is removed from the macOS path once the HVF backend has, on the newest Apple
Silicon tier:

- passed the warm-run, shell-attach, and warm-restore acceptance gates in the
  [benchmark plan](../perf/sub-second-startup-benchmark-plan.md) (including eager-CoW
  restore p95 under target);
- booted the consolidated `mvm-init` over its vsock control channel and run both
  one-shot exec and interactive shell;
- carried the full security posture (no production SSH, no guest NIC by default,
  brokered egress/ingress, secret-free snapshot frames) with its device model under
  the same fuzzing discipline as the existing parsers;
- run a representative workload set with no Vz-only fallback required.

Until all four hold, Vz stays as the transitional fallback. After they hold, the Vz
backend, its supervisor, and its selection branch are deleted.

**Ratification (2026-07-08).** These criteria are scoped to macOS. The
representative-workload boot, sealed-security-posture, and `mvm-init`
vsock-control gates are met on HVF, so the Vz backend, its supervisor, its
builder, and its selection branch have been **deleted** (Plan 226 R1P1). The
warm-restore / save-restore criterion is the one exception: HVF
`SnapshotCapability::SaveRestore` is tracked separately (Plan 226 WS-E), so
`mvm machine checkpoint/fork` is temporarily unsupported on macOS and returns a
clear tracked error until that lands. The dev-shell VM temporarily falls back to
libkrun on macOS 26+ (the in-house HVF dev-VM boot rides the virtio-fs stack in
Plan 222); flipping the dev default to HVF is a follow-up. Linux backend
convergence is Release 2 (Plan 226 R2).

### What this ADR explicitly states

- The high-level macOS framework (Vz) is a useful stable backend for the
  transition, but it is not the end state: the macOS path moves to HVF, and Vz is
  retired once the sunset criteria pass.
- The high-level framework almost certainly cannot expose the guest-memory
  mapping, page-level control, and device-state capture that eager-CoW restore
  needs; its save/restore is coarse and opaque.
- The raw hypervisor is the likely correct substrate for low-latency warm restore
  and snapshot internals on macOS.
- Adopting the raw hypervisor does not violate "no VMM lock-in" because it is one
  backend behind the same `VmBackend` abstraction.
- The raw hypervisor is a larger implementation, fuzzing, device-model, and
  security commitment than wrapping a high-level framework, and the migration is
  staged and benchmark-driven.
- No existing CLI workflow changes because of this backend split. `mvm machine run
  --image <ref> -- /bin/sh` and interactive shell attach behave identically
  regardless of which macOS backend is selected.

## Backend selection rules

Selection is capability-aware and fail-closed, layered on the existing
platform-first auto-selection:

- Default macOS backend: the raw hypervisor (HVF) as soon as it is proven. Vz
  remains the auto-default only during the transition window, and only on hosts or
  for plans where HVF is not yet available; that window closes when the sunset
  criteria pass.
- Performance macOS backend: the raw hypervisor (HVF), always preferred.
- The scheduler (mvmd at the fleet level; the `Machine` library locally) chooses
  based on plan requirements, host capability, and the requested snapshot mode.
- If the requested snapshot mode requires eager CoW, prefer the raw hypervisor and
  do not silently fall back to the high-level framework unless the plan explicitly
  permits a fallback.
- If compatibility matters more than performance for a given plan, the high-level
  framework is allowed.
- If no raw-hypervisor backend exists yet on the host, fail clearly, or fall back
  only when the plan permits it.
- No macOS backend advertises a production-SSH capability; a plan that requires
  production SSH is rejected by either backend (consistent with the standing SSH
  ban).

The capability dimensions that gate this choice are added in
[Plan 214](../plans/214-clean-replacement-architecture.md) Phase 2:
`supports_guest_memory_mapping`, `supports_fixed_address_remap`,
`supports_device_state_snapshot`, `supports_vcpu_state_snapshot`,
`supports_eager_cow_restore`, alongside the existing pause/resume/snapshot/vsock
facts.

## Staged plan

1. Define the backend capability model (Plan 214 Phase 2) so this choice is
   expressed as capability, not as a special case in callers.
2. Keep Vz working as the transitional fallback (do not delete it yet).
3. Build a minimal raw-hypervisor spike: boot a Linux guest, no NIC, vsock control
   channel.
4. Prove guest-RAM mapping from a host file-backed region and fixed-address remap.
5. Prove the vsock/control channel and the consolidated `mvm-init` boot path on it.
6. Prove snapshot and eager-CoW restore of a minimal guest.
7. Compare restore latency (p50/p95/p99) and resident-memory profile against Vz,
   using the [benchmark plan](../perf/sub-second-startup-benchmark-plan.md).
8. Promote HVF to the macOS backend (default, not just performance) once it passes
   the gates.
9. Execute the Vz sunset once all four sunset criteria hold: delete the Vz backend,
   its supervisor, and its selection branch. If a criterion is not yet met, record
   which one and keep Vz only for that gap until it is closed.

## Consequences

**Positive.** Unlocks eager-CoW local restore and snapshot internals on macOS;
makes the sub-100 ms warm-restore target reachable on Apple Silicon; converges
macOS on a single owned backend (HVF), reducing the long-term surface to maintain;
stays within the no-lock-in principle because HVF is one `VmBackend` impl.

**Negative / costs.** mvm owns a macOS device model and its fuzzing surface; the
attack surface and maintenance grow during the transition; the spike must prove
feasibility before any promotion. Vz is a maintained second path only until the
sunset criteria pass, after which it is removed — the dual-backend cost is
transitional, not permanent.

**Security.** The raw-hypervisor backend inherits every standing requirement: no
production SSH, no guest NIC by default, no egress/ingress path that bypasses host
policy/audit, and snapshot frames that exclude secrets by construction
(see the [security/audit/trace/secret note](../notes/clean-replacement-security-audit-trace-secret-architecture.md)).
The device model is new untrusted-input surface and is fuzzed under the same
discipline as the existing vsock and supervisor-config parsers.


## Consolidated from ADR-099 — Multi-backend hypervisor abstraction (the `HypervisorVm`/`HypervisorVcpu` seam)

**Status:** Accepted (2026-06-29)
**Relates to:** [Plan 214](../plans/214-clean-replacement-architecture.md) ("no VMM lock-in"),
ADR-007 §"Consolidated from ADR-098" (raw HVF macOS backend),
the no-VMM-lock-in principle in [ADR-022](022-target-architecture.md).

## Context

The clean-replacement work built a **portable, hypervisor-agnostic device model**
(`mvm_backend::vmm`: guest memory, device tree, arm64 kernel-image loading, the
PL011 console, and virtio-mmio block + vsock) with zero hypervisor FFI, plus a
**raw HVF backend** (`mvm_backend::hvf`) that boots real arm64 Linux to userspace
on macOS / Apple silicon, live-proven (PL011 console, in-kernel GICv3 + arch
timer, PSCI, virtio-blk, virtio-vsock).

To honour the no-VMM-lock-in principle we need the *same* device model and run
loop to run under other hypervisors — **KVM on Linux**, **WHP on Windows** — not
just HVF. The question this ADR answers: **what is the seam between the portable
VMM and a concrete hypervisor, so backends plug in without rewriting the run loop
or the device model?**

The source review (the reviewed reference implementation studied for this work —
not named here, per the architecture brief) solves exactly this with a single
high trait pair and static, compile-time backend selection. We adopt that shape.

## Decision

Introduce a portable hypervisor seam in `mvm_backend::vmm::hv`:

- **`HypervisorVm`** — owns guest physical memory + the interrupt controller and
  creates vCPUs: `create()`, `map_ram()`, `create_vcpu()`, `set_irq(intid, level)`.
- **`HypervisorVcpu`** — drives one vCPU: `step() -> VcpuExit`, `get/set_core`,
  `get/set_sys`, plus an `exit_token()` returning a `VcpuHandle` that another
  thread can use to force the vCPU out of `step()` (run watchdog / snapshot
  rendezvous).
- **`VcpuExit`** — a small `Copy` enum that **unifies the two ways a guest MMIO
  access surfaces**: the raw arm64 `Exception { syndrome, phys_addr }` (HVF — the
  run loop decodes the ESR) *and* the already-decoded `Mmio { … }` / `Io { … }`
  (KVM `KVM_EXIT_MMIO` / `KVM_EXIT_IO`). Both route to the same device handler,
  so **one run loop serves every backend and architecture**.
- **`CoreReg` / `SysReg`** — portable register names (`X(n)`, `Pc`, `Cpsr`,
  `MpidrEl1`); each backend maps them to its native id (HVF `hv_reg_t`; KVM
  `KVM_REG_ARM_CORE`).

The seam is drawn **high**: memory, registers, IRQ-raise, and run/exit live in
the contract; everything below (how a backend services doorbells or injects
interrupts) is the backend's own business, so each platform uses its fastest
native mechanism (userspace on HVF; irqfd / ioeventfd / in-kernel irqchip on
KVM) without the portable layer forcing a slower pattern.

Dispatch is **static**: the active backend is bound as a concrete type alias
`vmm::hv::ActiveVm` behind `#[cfg]`, so trait calls monomorphize to direct calls
— **no `dyn` on the vCPU hot path**.

```
macOS / aarch64   →  ActiveVm = hvf::HvfVm     (HVF)
linux / aarch64   →  ActiveVm = kvm::KvmVm     (KVM — to land)
linux / x86_64    →  ActiveVm = kvm::KvmVm     (KVM, x86 boot/16550/IOAPIC)
windows           →  ActiveVm = whp::WhpVm     (WHP — later)
```

`mvm_backend::vmm` (device model + the forthcoming generic run loop) is the layer
**below** the product `VmBackend` trait and **above** this seam:

```
VmBackend (product/CLI/mvmd) ─ AnyBackend dispatch
        └── vmm: device model + generic run loop  ── drives ──▶  HypervisorVm/Vcpu seam
                                                                   ├─ hvf  (macOS)
                                                                   ├─ kvm  (Linux)
                                                                   └─ whp  (Windows)
```

## Why this shape

- **One run loop, many backends.** The MMIO/virtqueue/console dispatch is written
  once against `VcpuExit`; adding a hypervisor is "implement two traits."
- **Cross-architecture for free in the exit enum.** Because `VcpuExit` carries
  both the raw-`Exception` and decoded-`Mmio`/`Io` forms, the same loop handles
  arm64 (HVF raw ESR; KVM decoded) and x86 (KVM decoded `Io`/`Mmio`).
- **Zero hot-path overhead.** Static `cfg` dispatch, no `dyn`, no vtable on
  `step()`.
- **No lock-in.** A backend is one module behind the seam; none leaks into the
  device model or the product `VmBackend`.

## Status of implementation

- ✅ `vmm::hv` — the trait contract (`HypervisorVm`, `HypervisorVcpu`,
  `VcpuExit`, `CoreReg`, `SysReg`, `VcpuHandle`, `prot`). Portable; compiles on
  macOS + cross-compiles to Linux.
- ✅ `hvf::{HvfVm, HvfVcpu, HvfHandle}` implement the seam (thin wrappers over the
  existing HVF FFI), validating the contract against a real, live-proven backend;
  `ActiveVm` binds on macOS.
- ✅ **Unified run loop** (`vmm::run`) — one body, generic over `HypervisorVcpu`:
  `step()` → dispatch decoded `Mmio`/`Io` to a `RunDevice` list (matched by guest
  address / port) → `complete_read` on a read → `set_irq` on a write that raises
  a line; `Halt`/`Canceled` end it; non-MMIO exceptions (arm64 PSCI/HVC) go to a
  caller hook. `RunDevice` is implemented for `Pl011`/`VirtioBlk`/`VirtioVsock`.
  Mock-tested with a scripted vCPU (7 tests: read-completion, write+offset, IRQ
  raise, PIO-by-port + RAZ, cancel, exception hook, vtimer); compiles on macOS +
  both Linux targets.
- ✅ **HVF `VmBackend` + selection.** `mvm-hvf-supervisor` (the detached per-VM
  host process, `mvm-vm-host`) self-signs the hypervisor entitlement, reads an
  `HvfSupervisorConfig` (in `mvm-build`, shared with the backend) on stdin, boots
  via `boot_kernel`→`vmm::run`, and captures `console.log` + a PID file.
  `HvfBackend` (always-compiled `crate::hvf_backend`) implements the lifecycle
  over it — `start` spawns + waits for the PID file, `stop`/`status`/`list`/`logs`
  track it — and is registered in the catalog + `AnyBackend` so
  `--hypervisor hvf` / `MVM_BACKEND=hvf` select it. Live-verified end to end on
  Apple silicon (start → status Running → guest to PID 1 + virtio-blk → logs →
  stop). `as_workload_backend` returns `None` until egress parity lands.
- ✅ **HVF boots a live arm64 Linux guest through the unified loop.**
  `hvf::kernel_boot` now wraps its raw vCPU in `HvfVcpu` and drives it via
  `vmm::run`: the inline `sys` decode/dispatch loop is gone; PL011/virtio-blk/
  virtio-vsock dispatch through `RunDevice` + `complete_read`, PSCI/HVC via the
  exception hook, and the watchdog via the seam's `force_exit`. Live-verified on
  Apple silicon: boots to **PID 1**, reads a virtio-blk disk, and round-trips a
  virtio-vsock message — same result as the pre-migration path. The KVM boot path
  gets the same loop once driven on the box (the spike already proves the guest).
- ✅ **x86_64 KVM boot live-proven to userspace** — a `kvm-ioctls` driver
  (`spikes/kvm-x86-boot/`) boots a stock distro `bzImage` on `/dev/kvm` straight
  to **PID 1** (`Run /init as init process` → the init's own marker → clean
  shutdown). KVM is *simpler* than HVF on the run loop: the kernel decodes MMIO
  (`VcpuExit::Mmio`/`Io`, no ESR to parse). The x86 host device path the spike
  pins down for the backend: 64-bit long-mode entry (page tables + GDT +
  `efer.LME`, kernel at 1 MiB, entry `+0x200`), **`KVM_SET_CPUID2`** with the
  host-supported CPUID (without it the kernel's early page-table math faults), a
  **two-entry e820** map (0–640 KiB, then 1 MiB–end; a single entry falls back to
  legacy e801 → no RAM → `alloc_low_pages` panic), the **in-kernel irqchip +
  `KVM_CREATE_PIT2`** (no PIT → the kernel hangs after APIC setup waiting for
  timer ticks), and a 16550 serial for the console.
- ✅ `kvm::KvmVm` / `KvmVcpu` (x86_64) — implement the seam over `kvm-ioctls`
  (`create`/`map_ram`/`create_vcpu`+CPUID/`set_irq`/`step`→`Io`/`Mmio`/`Halt`,
  `boot_x86` applying the entry regs, a `tgkill`-based `force_exit`). `ActiveVm`
  binds to `KvmVm` on linux/x86_64. The boot setup is the pure, **unit-tested**
  `kvm::x86_boot` (7 tests; compiles on every host); the ioctl glue compiles on
  linux/x86_64.
- ✅ **Read-completion closed in the seam.** `step()` now always yields a *decoded*
  `Mmio`/`Io` (HVF decodes its data-abort ESR into the same form KVM gets from the
  kernel), and `HypervisorVcpu::complete_read(value)` delivers a load result
  natively: KVM fills the `kvm_run` data buffer (kernel finishes on re-entry); HVF
  writes the destination register + advances PC. So the (forthcoming) unified run
  loop is one body — `step` → dispatch `Mmio`/`Io` to the `vmm` devices →
  `complete_read` on a read — across both backends. (HVF decode unit-tested;
  stores self-complete in `step`.) Remaining: write that unified run loop against
  the `vmm` devices + drive a live boot through the backend (vs. the spike).
- ⏳ `kvm::KvmVm` (arm64) — on an aarch64 KVM host the *whole* `vmm` device model
  reuses unchanged behind the seam.
- ⏳ `whp::WhpVm` — Windows, later.

### Cross-architecture note (KVM reuse)

KVM runs **same-architecture** guests only. The `vmm` device model is arm64
(arm64 `Image`, FDT, PL011, GICv3), so it reuses **unchanged** under KVM only on
an **aarch64 KVM host** — there the KVM backend is just the seam's ioctl glue
(create VM/vgic-v3/vcpu, `KVM_RUN` → `VcpuExit::Mmio` → the same devices,
`KVM_IRQ_LINE` for virtio). On x86_64 KVM the *virtqueue logic* still reuses, but
the boot (boot_params/long-mode), console (16550 PIO), and interrupt controller
(IOAPIC + PIT) are a separate x86 device path — now **live-proven to userspace**
on an x86_64 host (`spikes/kvm-x86-boot/` boots a stock `bzImage` to PID 1 on
`/dev/kvm`). The clean whole-`vmm` reuse (the arm64 device model unchanged behind
the seam) wants an aarch64 KVM box, but the x86 backend stands on its own proof.

## Alternatives considered

- **`dyn VmBackend` everywhere.** Rejected for the hot path (vtable on `step()`),
  and the existing product `VmBackend` trait is too high-level (it speaks VM
  lifecycle, not vCPU registers/exits). The seam is deliberately separate and
  lower.
- **A backend per (arch × hypervisor) with no shared device model.** Rejected —
  that is the lock-in the design exists to avoid; it duplicates virtio/console.

## Consequences

- New code to add a hypervisor = implement `HypervisorVm` + `HypervisorVcpu`
  (+ a `VcpuHandle`); the run loop and device model are untouched.
- The product `VmBackend` impls (`AnyBackend`) for HVF/KVM become thin shells
  over `vmm` + the seam.
- A single cross-backend snapshot pipeline is a natural extension (add
  capture/restore to the vCPU/VM traits) — deferred until the run loop migration.


## Consolidated from ADR-102 — One VMM driver seam; backends collapse to two role runners

**Status:** Accepted (2026-06-30)
**Relates to:** [ADR-003](003-hypervisor-egress-policy.md) (vsock is the sole
guest↔world channel — this ADR makes its "single host gateway" the only egress
mechanism for *every* backend), [ADR-003](003-hypervisor-egress-policy.md)
(the hvf VMM's unified vsock gateway — the reference shape this ADR generalizes
outward), [ADR-001](001-microvm-security-posture.md) (`WorkloadBackend` permission, consolidated from ADR-083 —
preserved unchanged), ADR-007 §"Consolidated from ADR-093" (builder auto-fallback —
preserved), [ADR-001](001-microvm-security-posture.md) (claims 10/12/13 + per-backend
tier matrix), [ADR-003](003-hypervisor-egress-policy.md) (the gvproxy/passt gateway this
ADR removes), [Plan 214](../plans/214-clean-replacement-architecture.md) (implementation).

## Context

The backend layer carries two parallel hierarchies, and most VMMs are implemented
twice. A *runtime* backend (`mvm-backend`: `VmBackend`/`WorkloadBackend`) and a
*builder* backend (`mvm-build`: `BuilderVm`) each embed their own copy of the
VMM-driving code:

| VMM | runtime (`mvm-backend`) | builder (`mvm-build`) |
|---|---|---|
| libkrun | `libkrun.rs` | `libkrun_builder.rs` (3.8k) |
| vz | `vz.rs` (4.3k) | `vz_builder.rs` (3.5k) |
| qemu | `qemu.rs` | `qemu_builder.rs` |
| firecracker | `firecracker.rs` + `microvm.rs` (4.3k) | *(builder is never FC)* |
| HVF/KVM | `hvf_backend.rs` + `vmm/` | *(none — the gap)* |

The word "backend" conflates two separable things: **VMM mechanics** (create a VM,
load a kernel, attach disks, wire vsock, boot, wait, kill) and **role policy** (a
sealed workload's claim-8 admission / claim-10 egress / claims-12/13 substitution /
write-only console, versus a builder's job staging, broad-egress nix build, and
artifact collection). Because the two are tangled in every file, each VMM is written
twice, and the cross-cutting concerns are re-implemented per backend — egress and
substitution are scattered across `substitution_spawn.rs`, `egress_redirect.rs`,
`egress_shared.rs`, the vz endpoint, and `vmm/{egress_gate,egress_proxy,substitution_bridge}.rs`.
That scatter is a defect source in its own right: a launch path that forgets to wire
the policy is the exact shape of past egress-enforcement gaps.

Two prior decisions converge to make a clean cut possible now. ADR-100 fixed that a
guest's only channel off the box is vsock, through one host gateway — there is no
guest NIC. ADR-101 realized that concretely for the hvf VMM: `vmm/` is the
mechanics, `hvf_backend.rs` is a thin (~456-line) role adapter over a single
host-side vsock egress gateway that carries claims 10/12/13 in one endpoint. The
hvf VMM already has the shape every backend should have. This ADR generalizes
it.

A vsock-only production reference design (linked in the originating discussion)
corroborates the end state: no userspace network gateway, no host packet filter — a
single vsock chokepoint is the entire egress surface.

## Decision

**1. Introduce a `VmmDriver` high seam — pure mechanics, written once per VMM.**
`VmmDriver::boot(&VmmSpec) -> Box<dyn RunningVm>`, where `RunningVm` exposes
`wait`/`kill`/`pause`/`resume`/`status`/`vsock_connect`/`balloon`/`snapshot`. The
existing `vmm/hv.rs` `HypervisorVm`/`HypervisorVcpu` traits are a *lower* seam (vCPU
registers, the run loop, HVF-vs-KVM-vs-WHP) that stays *inside* `InHouseDriver`. The
two seams do not merge: the hvf VMM is one `VmmDriver` impl that uses the low
seam internally.

**2. `VmmSpec` has no NIC.** A guest VM has exactly three I/O channel kinds:
`blocks` (storage), `vsock` (everything else), `console` (write-only — the claim-15
property). There is no virtio-net device in any backend. "Networking" is a reserved
vsock egress port; the spec carries plumbing, never a `NetworkPolicy`. The driver
therefore physically cannot enforce — or bypass — egress; it only wires the wire.
Admission state (`plan_json`, `tenant_id`) never reaches the spec, so the driver
cannot launch an unadmitted plan.

**3. Composition, not a merged trait.** The two roles become two types, each holding
a `dyn VmmDriver`:

- **`WorkloadRunner`** — the sole `impl WorkloadBackend`. Maps `VmStartConfig →
  VmmSpec`, admits the plan, spawns the one vsock egress bridge, emits audit, waits.
  `LibkrunBackend`/`VzBackend`/`HvfBackend`/`FirecrackerBackend` dissolve into it —
  they were five copies of one role policy around five VMMs. With egress uniform, the
  `EgressSubstitutionTransport` enum collapses to a single `VsockChannel` and is
  deleted.
- **`BuilderRunner`** — the sole `impl BuilderVm`. Stage job → `VmmSpec` → boot →
  build session over vsock → collect artifacts → finalize → stage0.
  `libkrun_builder`/`vz_builder`/`qemu_builder` dissolve into it; the hvf
  builder falls out for free.

The per-VMM quirks must live in the driver, not the runner — they do: snapshot
fidelity is `driver.snapshot_capability()`; console-port exposure (per-port-UDS vs
multiplexed) is how the driver presents vsock. If a quirk can't be pushed into the
driver, the seam is wrong; snapshot and console were the hard cases and both fit.

**4. One host-side `vsock_egress_bridge` for claims 10/12/13, every backend.** The
backend-agnostic `vmm/{egress_gate,egress_proxy,substitution_bridge}` are promoted
out of `vmm/` into this shared module; `substitution_spawn`/`egress_shared` fold in.
`egress_redirect.rs` (FC nftables REDIRECT), the gvproxy/passt gateway, and
`broker_services_spawn.rs` are deleted. Egress is no longer "wired once per backend"
— it is one implementation, and the only thing a backend physically provides is
vsock.

**5. vsock-only everywhere, builder NIC deleted last.** The seam ships with no `net`
field from the start. Workloads migrate to the vsock bridge first. The builder keeps
its current NIC during migration via a clearly-deprecated `BuilderNet` side-channel
that lives *outside* `VmmDriver` (so the clean seam is never polluted), then cuts over
to a localhost-forward-proxy→vsock mechanism in the guest (nix honors `http_proxy`;
binary-cache fetches are HTTP(S), so no libc/kernel interception is needed). The final
slice deletes `BuilderNet` and every slirp/passt/tap line. End state: zero NICs in the
tree, one egress chokepoint.

## Consequences

**Security posture — preserved by construction, with one hardening.** The admitted-
launch funnel (claim 8) and the `WorkloadBackend` permission (ADR-001, consolidated from ADR-083) are unchanged
and implemented by the workload role type only; neither the driver nor the builder
role can reach the funnel. The tier matrix gets *crisper*: "qemu is Tier-2, never a
workload" becomes "there is a `QemuDriver` but no `QemuBackend: WorkloadBackend`" —
the absence of a workload-role type is the enforcement, at the type level. The
hardening: egress/substitution become one host-side codepath instead of three, so
"boot a workload" and "wire the egress gate" are the same code and cannot desync;
removing virtio-net deletes the host-side frame-parser attack surface (the gvproxy-Go
/ passt-C parsers in ADR-055's untrusted-input list) and all host nftables state — a
smaller TCB. The one witness that *moves*: Firecracker's claim-10 witness migrates
from the nftables `install_default_deny` test to the shared vsock-bridge gate test (a
catalog edit in the FC slice).

**UX — zero change.** `--hypervisor`, `--builder`, `machine run`, the doctor lines,
and `VmStartConfig` are identical. The parity gate's job is to prove no observable
behavior changed. The only second-order benefit is that a new VMM (and the HVF-
everywhere direction) ships faster and with fewer backend-specific quirks.

**DX — the primary win.** A VMM is written once (driver) instead of twice; role
policy lives in one place; cross-cutting concerns are wired once. ~20k lines of
runtime backends + ~8.5k lines of builders become N thin drivers + two runner types +
one bridge. The security-bearing role logic becomes unit-testable without a
hypervisor (see Testing).

**Migration — witness-gated slices, no flag day** (Plan 214). Old and new coexist
behind `AnyBackend`; each slice swaps one VMM's constructor to the new path, proves
parity, then deletes the old type. Order: **S0** define the seam + promote the bridge
(no behavior change) · **S1** `InHouseDriver` + `WorkloadRunner` (HVF reference proof)
· **S2** libkrun · **S3** vz · **S4** Firecracker (the careful one — egress
nftables→vsock, old path retained until proven on live KVM) · **S5** delete the five
old workload types + the transport enum · **S6** `BuilderRunner` + migrate the three
builders (hvf builder falls out) · **S7** builder vsock-egress cutover; delete
`BuilderNet` + all NICs. The risky migrations are sequenced last within each phase;
rollback is per-slice (don't swap the constructor until parity passes). This subsumes
the HVF-workload and hvf-builder goals — they arrive as products of the
seam rather than a bespoke spike.

**Testing.** A `MockDriver` (sibling to `mock.rs`/`mock_guest_agent.rs`) records the
`VmmSpec` and returns a scripted `RunningVm` with a loopback vsock, so
`WorkloadRunner`/`BuilderRunner` are fully unit-tested with no hypervisor — asserting
the sealed rootfs + verity disks, the egress vsock port, the write-only console, the
audit-chain entries — on every `cargo nextest`, every platform. The single
`vsock_egress_bridge` gets one canonical suite (the existing claims-10/12/13 tests +
the vsock-framing/supervisor-config fuzz targets), backend-independent. A per-slice
parity harness drives the same input through old and new and asserts equivalence:
byte-identical `BuilderArtifacts` (the existing equality-proof gate) for builders;
same egress allow/deny verdict, audit entries (modulo timestamp/nonce), and exit
status for workloads. Live boots stay environment-gated (HVF/Vz/libkrun on macOS,
FC/libkrun on KVM, the claim-10 probe per backend, the S7 cold vsock nixpkgs fetch),
captured as runbook proofs; `xtask check-claim-catalog` keeps the witness→test mapping
honest across every slice.

## Alternatives considered

**One merged backend trait (runtime + builder behind a single interface).** Rejected:
the two roles sit on opposite sides of the security model — the workload role *must*
enforce claims 8/10/12/13, the builder role *must not* (it is Tier-2). A unified trait
means either an interface bloated with role-only methods, or a dangerous symmetry
where a future edit wires claim-10 into the builder or drops it from the workload "to
match." The concerns must not be reachable from the same abstraction. Unifying on the
*VMM* (the driver), not the *backend* (the role), gives "write a VMM once" without
that coupling.

**Keep a real builder NIC permanently (vsock-only for workloads only).** Rejected: it
keeps a `net` attachment seam on `VmmDriver`, so every VMM still implements slirp/
passt/tap — exactly the per-backend divergence this ADR removes, merely relabeled
"builder-only." A permanent exception calcifies and the net code never dies. The
staged approach (decision 5) keeps the builder working throughout yet reaches a tree
with zero NICs.

**Do nothing / share more helpers ad hoc.** Rejected: the partial sharing
(`substitution_spawn`, `egress_shared`, `audit_substrate`) already exists yet is
called separately from four backend `start()` sites; without the seam the duplication
and per-backend egress divergence persist, and the hvf VMM remains a one-off
rather than the general shape.

## Out of scope

A malicious host (the host holds the hypervisor and build keys — unchanged from
ADR-001). The hvf VMM's *lower* `hv.rs` seam and its HVF/KVM/WHP coverage —
that is ADR-101's territory and is consumed unchanged here. Multi-tenant guests (one
guest = one workload, unchanged). The auto-detect default flips toward the hvf
VMM remain gated on live verification and are not decided by this ADR.
