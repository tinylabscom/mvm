---
title: "ADR-046: Move the builder VM off libkrun onto libkrun + firecracker"
status: Proposed
date: 2026-05-13
related: ADR-013 (libkrun + libkrun pivot); ADR-002 (security posture); plan 57 (libkrun spike); plan 60 (libkrun migration); plan 72 (this ADR's implementation)
---

> **Consolidation (2026-05-31 — see [ADR-066](066-target-architecture.md) §"ADR consolidation"):** ADR-046 is the **canonical** builder-VM architecture ADR. It **consolidates** ADR-013 (libkrun microVM Nix pivot), ADR-057 (symmetric builder VM), and ADR-065 (single builder/dev image + embedded host binaries); those are **superseded** and physically archived to `archive/adrs/` in Stage E. Current state reflects ADR-065's single `builder-vm` flake with `default`/`dev` attrs.

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
   │    matching mvmctl's version. Hash-verified per ADR-002 §W5.1
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
| User-facing build-trust boundary | libkrun + nixos/nix OCI image | Our own builder VM image (hash-verified per ADR-002 §W5.1) |

### Trust-zone shift

ADR-013 §"Linux builder via libkrun" placed the user-facing builder behind a pinned third-party OCI image (`docker.io/nixos/nix:2.24.10`). Plan 72 replaces that **on the user-facing path** with an mvm-published builder VM image — kernel + rootfs.ext4 built on a Linux CI runner via `nix/images/builder-vm/flake.nix` (a slimmed split of the current `nix/images/builder/`), signed by the project's release key, and verified by the same SHA-256 manifest path used today for `download_dev_image` (`mvm_cli::commands::env::apple_container::download_dev_image`, ADR-002 §W5.1).

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
- ADR-002 §W5.1 (image hash verification) applies to the builder image with no change — same manifest + streaming SHA-256 path as the dev image.
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

The builder VM is the dev tier per `feedback_dev_vm_vs_prod_security_tiers.md`, *but* its Install arm (ADR-047, Claim 9) is the prod-grade path that produces the sealed deps volumes the runtime supervisor verifies. So the ADR-002 security claims that apply to the builder VM hold across **both** backends, with the same evidence:

- **Claim 1** (no host-fs access beyond explicit shares). Both backends construct `VirtioFsShare`s for `/work` `/out` `/job` `/nix-store` only. §2.S8 ships a hermetic test asserting set-equality of `(host_path, guest_path, read_only)` triples between the two drivers for the same input.
- **Claim 5** (vsock framing + supervisor-config JSON fuzzed). libkrun's `crates/mvm-libkrun/fuzz/fuzz_supervisor_config.rs` covers the libkrun supervisor's parser. Vz's `crates/mvm-vz/fuzz/` adds a parallel target against `mvm_vz::SupervisorConfig` — Slice 2C §2.S6. The host-side Vz control-socket parser (Phase E pause/resume/balloon/snapshot) is host-process-local with `0700` parent dir; ADR-002's host-trust assumption covers the residual surface (justified in the Slice 2C ADR-002 sub-note).
- **Claim 7** (cargo deps audited). `crates/mvm-vz` participates in `deny` + `audit` like every other workspace member; Slice 2C §2.S5 confirms `deny.toml` scope.
- **Claim 8** (signed/audited `ExecutionPlan`). `mvmctl up --prod` admission emits `plan.admitted` / `plan.launched` / `plan.failed` from the same `AuditEmitter` regardless of which builder backend resolved the Install. Slice 2C §2.S3 runs `mvmctl audit verify` after a Vz-driven `mvmctl up --prod` to assert chain cleanliness.
- **Claim 9** (sealed deps volumes hash-locked + attestation-checked + CVE-scanned + SBOM-enumerated + audit-bound). Cross-backend byte-equivalence of the sealed volume contents (`content/` tree, `sbom.cdx.json`, `fetch.log`, `cve.json`) is asserted by Slice 2C §2.S2. Builder VM kernel + rootfs parity (the Install-arm prod-grade path) is §2.S9 — if divergence is unavoidable, the volume-byte-level equivalence still holds because both backends produce the same Nix store closure. `meta.json` backend-neutrality (§2.S10) is asserted by decoding a libkrun-sealed and a Vz-sealed Install on the same input and comparing byte-for-byte.

The other ADR-002 claims (2, 3, 4, 6, 10) are guest-side or end-user-runtime concerns — they don't depend on which host VMM booted the builder, so the existing libkrun-side evidence applies unchanged.

Per `feedback_adr_out_of_scope_discipline.md` this Security-claim-parity subsection lists ONLY items in the same threat model as the parent ADR-002 claim. Adjacent surfaces (Sprint 56 Claim 10 in-guest volume encryption, Plan 101 gateway audit) belong in their own ADRs and are not in scope here.

### Cross-reference summary

- **Plan 97** — Vz runtime backend (Phase A/B/D/E shipped, C parked → continued by Plan 98).
- **Plan 98** — this extension's implementation plan.
- **Plan 99 PR-1** — Stage 0 cache contract the prefix-agnostic reaper depends on.
- **ADR-002** — security posture; per-claim sub-notes in Claims 1, 5, 7, 8, 9 point back here.
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

### Why this does not violate "the contributor path doesn't download"

The §"Why the contributor path doesn't download" and §"Source-checkout
builds never depend on mvm-published artifacts" invariants are
preserved exactly:

- **Source checkouts always compile.** `--source compile` requires
  `find_builder_vm_flake()` to resolve; a contributor who edits
  `nix/lib/kernel/base.nix` or the builder delta sees that change in the
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
