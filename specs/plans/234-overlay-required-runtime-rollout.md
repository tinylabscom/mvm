# Plan 234 — Overlay-required guest runtime rollout

**Status:** complete
**Owner:** Ari
**Related:** ADR-051 (runtime overlay disk), ADR-066 (target architecture),
Plan 124 (lean guest agent + overlay), Plan 223 (virtiofs-root dev-tier posture),
ADR-002 (claims 3, 4, 10), `crates/mvm-build/src/runtime_overlay.rs`,
`crates/mvm-build/src/oci_runtime_inject.rs`,
`crates/mvm-build/src/bin/mvm-host-vm-init.rs`,
`crates/mvm-cli/src/commands/vm/up.rs`,
`crates/mvm-core/src/protocol/vm_backend.rs`

**Additional 2026-07-10 — Plan 234 is now complete.** The rollout no longer has an unproven production seam on a backend that remains admitted. The workload-side required-overlay contract is proven on every block-backed backend that actually consumes `RequiredOverlay` today: Firecracker on the real KVM host, qemu on the real KVM host, libkrun on the real KVM host, and HVF locally on macOS. The builder side is likewise in a production-safe state: the qemu builder read-only witness is green, the HVF builder read-only witness is green, Linux-native builder auto-detect routes to qemu, and explicit steady-state Linux rootfs-backed libkrun builder attempts fail closed with `BuilderVmError::LibkrunUnavailable(...)` instead of silently booting a broken path. The final Linux/KVM confirmation was rerun on `88.99.197.234` against the current code: `builder_backend_select::tests::auto_detect_default_for_linux_native_picks_qemu` passed there, and `libkrun_builder::tests::linux_native_rootfs_builder_support_guard_matches_platforms` passed there, proving the enforced production contract on the host tier that had been carrying the stale “remaining gap” narrative. Combined with the green workspace gates (`cargo check --workspace --offline`, `cargo clippy --workspace --all-targets --offline -- -D warnings`, and `cargo test --workspace --offline` on the host execution boundary that allows the local socket/listener tests to bind normally), that closes the rollout as production-ready: every admitted backend/tier either consumes the shared read-only runtime artifact with real proof or refuses the unsupported path explicitly.

The notes below are retained as the execution log for the rollout. If an older
entry describes an earlier open gap, the completed contract above is the
authoritative final state.

The design/problem statements below also capture the rollout's starting point
before the contract was enforced everywhere it is now admitted. They are kept
for historical context, not as a statement of the current production contract.

**Additional 2026-07-10 — Plan 234 now keeps source-checkout required-overlay OCI boots pinned to the current verity-initrd contract instead of a stale sibling file.** The remaining closeout bug in the persistent/transient OCI block-root path was not backend attach logic; it was initrd selection drift when the runtime overlay was being acquired from the current source checkout. `persistent_oci_effective_initrd(...)` now prefers `ensure_workload_verity_initrd()` before any sibling `rootfs.initrd` when the required-overlay contract is active, the acquire mode is `build`, and the checkout itself is the active source root. That keeps source-checkout boots aligned with the current `mvm-verity-init` build and its fingerprinted cache entry instead of silently reusing an older adjacent initrd. Focused regressions now pin all three cases: sibling-initrd preference for non-source-checkout paths, cached-verity fallback for required-overlay boots, and source-checkout boots ignoring a stale sibling initrd in favor of the current fingerprint-matched cached initrd. The same slice fixes test isolation that had been obscuring the closeout: the transient OCI initrd tests now force `MVM_RUNTIME_OVERLAY_ACQUIRE_MODE=download` when they are asserting sibling/cached behavior, and the untrusted transient admit regression now isolates `MVM_DATA_DIR` so it does not collide with host-global VM state during workspace test runs. Validation in the worktree: `env CARGO_TARGET_DIR=/tmp/mvm-overlay-gates-target cargo check --workspace --offline`, `env CARGO_TARGET_DIR=/tmp/mvm-overlay-clippy-target cargo clippy --workspace --all-targets --offline -- -D warnings`, `env CARGO_TARGET_DIR=/tmp/mvm-overlay-gates-target cargo test -p mvm-cli exec::tests::transient_oci_required_overlay_prefers_sibling_initrd --lib --offline -- --exact --nocapture`, `env CARGO_TARGET_DIR=/tmp/mvm-overlay-gates-target cargo test -p mvm-cli exec::tests::transient_oci_required_overlay_falls_back_to_cached_verity_initrd --lib --offline -- --exact --nocapture`, and `env CARGO_TARGET_DIR=/tmp/mvm-overlay-gates-target cargo test --workspace --offline` on the host execution boundary that allows the local socket/listener tests to bind normally.

**Additional 2026-07-09 — Plan 234 now fail-safes the Linux builder default while the remaining libkrun rootfs-backed builder proof is still open.** The current production gap is no longer the read-only runtime-overlay contract on workload backends; it is the Linux/KVM libkrun builder lane, where the rootfs-backed builder image still does not reach a usable userspace witness on the real host. `crates/mvm-build/src/builder_backend_select.rs` therefore no longer auto-detects libkrun as the native Linux builder default. The selector now resolves `LinuxNative -> qemu`, keeps `macOS 26+ Apple Silicon -> hvf`, and leaves other hosts on libkrun. Explicit `--builder libkrun` / `MVM_BUILDER_BACKEND=libkrun` still work for continued diagnosis, but ordinary source-checkout and builder-driven flows now default to the backend with the live production proof instead of the backend whose rootfs-backed proof is still open. The same slice updates the surrounding operator surface so the contract is explicit: CLI help, doctor text, `rootfs.rs`, and the contributor development guide all now say Linux-native builder auto-detect picks qemu. Validation in the worktree: `env MVM_DATA_DIR=/tmp/mvm-overlay-data CARGO_TARGET_DIR=/tmp/mvm-overlay-target cargo test -p mvm-build --features builder-vm builder_backend_select::tests::auto_detect_default_for_linux_native_picks_qemu --lib --locked --offline -- --exact --nocapture`, `env MVM_DATA_DIR=/tmp/mvm-overlay-data CARGO_TARGET_DIR=/tmp/mvm-overlay-target cargo test -p mvm-build --features builder-vm builder_backend_select::tests::auto_detect_default_for_non_linux_non_hvf_hosts_picks_libkrun --lib --locked --offline -- --exact --nocapture`, `env MVM_DATA_DIR=/tmp/mvm-overlay-data CARGO_TARGET_DIR=/tmp/mvm-overlay-target cargo check -p mvm-cli --locked --offline`, and `env MVM_DATA_DIR=/tmp/mvm-overlay-data CARGO_TARGET_DIR=/tmp/mvm-overlay-target cargo clippy -p mvm-build --features builder-vm --lib --tests --locked --offline -- -D warnings`.

**Additional 2026-07-10 — Plan 234 now fail-closes explicit Linux rootfs-backed libkrun builder attempts too, based on a minimal real-host repro.** The earlier default flip avoided the unsupported path for ordinary Linux builder use, but explicit `--builder libkrun` still walked into the same dead rootfs-backed boot shape and could hang until timeout. The new guard in `crates/mvm-build/src/libkrun_builder.rs` closes that seam at cache-load time: on `LinuxNative`, loading the steady-state `rootfs.ext4` libkrun builder image now returns `BuilderVmError::LibkrunUnavailable("the rootfs-backed libkrun builder is not supported on Linux/KVM yet; use the qemu builder ...")` instead of attempting the silent boot. The root-dir/bootstrap shape remains allowed. This is backed by a narrower real-host experiment on `88.99.197.234`, not only the full builder VM failure: a deliberately tiny ext4 image with a hand-written `/init` and `/dev/console` stayed completely silent under the same rootfs-mode libkrun launch (`console.log` stayed zero bytes), while the matching root-dir launch on the same host reached guest console immediately and emitted `Couldn't execute '/init' inside the vm: No such file or directory`, which is enough to prove the kernel and root-dir userspace path are alive and the remaining broken seam is specifically Linux libkrun `rootfs_path` mode. Validation in the worktree: `env MVM_DATA_DIR=/tmp/mvm-overlay-data CARGO_TARGET_DIR=/tmp/mvm-overlay-target cargo test -p mvm-build --features builder-vm libkrun_builder::tests::linux_native_rootfs_builder_support_guard_matches_platforms --lib --locked --offline -- --exact --nocapture`, `env MVM_DATA_DIR=/tmp/mvm-overlay-data CARGO_TARGET_DIR=/tmp/mvm-overlay-target cargo test -p mvm-build --features builder-vm libkrun_builder::tests::ensure_builder_vm_image_accepts_current_manifest_capabilities --lib --locked --offline -- --exact --nocapture`, `env MVM_DATA_DIR=/tmp/mvm-overlay-data CARGO_TARGET_DIR=/tmp/mvm-overlay-target cargo check -p mvm-build --features builder-vm --all-targets --locked --offline`, and `env MVM_DATA_DIR=/tmp/mvm-overlay-data CARGO_TARGET_DIR=/tmp/mvm-overlay-target cargo clippy -p mvm-build --features builder-vm --lib --tests --locked --offline -- -D warnings`.

**Additional 2026-07-10 — Plan 234 now removes the last active SSH fallback from the legacy Firecracker builder orchestrator too.** The runtime-overlay rollout had already moved the supported builder/runtime contract onto direct vsock, but `crates/mvm-build/src/pipeline/orchestrator.rs` still kept a reachable SSH builder backend and an `auto -> vsock then SSH fallback` branch. That is now collapsed onto the surviving transport: `MVM_BUILDER_MODE=vsock` remains the explicit FC builder path, `auto` is only a legacy alias for that same direct-vsock path, and the old SSH backend plus `MVM_BUILDER_AUTHORIZED_KEY` injection surface are removed from the active builder-artifact preparation path and public docs. This keeps the overlay rollout aligned with the fully-vsock contract instead of carrying a silent builder-side exception. Validation in the worktree: `env MVM_DATA_DIR=/tmp/mvm-overlay-verify-data MVM_CACHE_DIR=/tmp/mvm-overlay-verify-cache CARGO_TARGET_DIR=/tmp/mvm-overlay-verify-target cargo check -p mvm-build --offline`, `env MVM_DATA_DIR=/tmp/mvm-overlay-verify-data MVM_CACHE_DIR=/tmp/mvm-overlay-verify-cache CARGO_TARGET_DIR=/tmp/mvm-overlay-verify-target cargo test -p mvm-build --offline test_ensure_builder_artifacts_skips_when_present test_ensure_builder_artifacts_downloads_when_missing -- --nocapture`, and `env MVM_DATA_DIR=/tmp/mvm-overlay-verify-data MVM_CACHE_DIR=/tmp/mvm-overlay-verify-cache CARGO_TARGET_DIR=/tmp/mvm-overlay-verify-target cargo clippy -p mvm-build --all-targets --offline -- -D warnings`.

**Additional 2026-07-09 — Plan 234 HVF workload read-only proof is now green locally on the production OCI block-root seam.** The remaining workload-side backend-proof gap is no longer HVF. The exact required-overlay OCI witness now passes on macOS/HVF with isolated state: `MVM_EMBED_ZIG=/Users/auser/.local/share/mise/installs/python/3.12.10/lib/python3.12/site-packages/ziglang/zig MVM_OCI_REQUIRED_OVERLAY_SMOKE=1 MVM_OCI_IMAGE_RUNNER_HYPERVISOR=hvf MVM_DATA_DIR=/private/tmp/mvm-oci-hvf-data-fixed2 MVM_CACHE_DIR=/private/tmp/mvm-oci-hvf-cache-fixed2 CARGO_TARGET_DIR=/private/tmp/mvm-oci-hvf-target-fixed2 cargo test --test oci_image_runner_smoke run_image_block_root_required_overlay_is_read_only_on_selected_backend -- --exact --nocapture`. Two guest-path fixes were required to close it: `mvm-verity-init` now accepts both verity sidecar layouts by geometry (`hash_start_block=1` when the sidecar carries a superblock, `0` when it does not), and the injected OCI `/init` now skips the raw runtime-overlay mount when `/mvm/runtime` is already mounted by `mvm-verity-init`. `OCI_RUNTIME_EPOCH` also moved to `5` so stale injected OCI rootfs cache entries rematerialize with the corrected `/init` contract. Validation in the worktree: `cargo test -p mvm-guest --bin mvm-verity-init -- --nocapture`, `cargo test -p mvm-build init_script_ --lib -- --nocapture`, `cargo check -p mvm-cli --all-targets`, `cargo clippy -p mvm-build -p mvm-cli -p mvm-guest --all-targets -- -D warnings`, and the live HVF witness above.

**Additional 2026-07-09 — Plan 234 now removes the zero-byte embedded host-binary trap from source-checkout proof lanes.** The builder/bootstrap paths no longer assume a non-release `mvmctl` must carry real embedded `stage0-init` and companion host binaries. `mvm-cli::host_binaries::extract` now has a shared `ensure_boot_host_binaries(...)` path: real embedded builds still extract the baked payloads, while source checkouts that intentionally bake zero-byte stubs rebuild the host-side `mvm-build` binaries once with `cargo zigbuild`, cache them under the host-bins cache, and feed both Stage 0 `/init` bytes plus `/mvm-bins` from that source-built cache. The Stage 0 root-dir bootstrap, workload-kernel compile path, builder-image cache loader, default-microVM local build path, and HVF builder-rootfs injector now all use that shared resolver instead of failing immediately on `embedded stage0-init is a zero-byte stub`. Validation in the worktree: `cargo test -p mvm-cli --test host_binaries_extract -- --nocapture`, `cargo test -p mvm-cli host_binaries::extract::tests::runtime_host_target_dir_honors_cargo_target_dir --lib -- --exact --nocapture`, `cargo test -p mvm-cli host_binaries::extract::tests::source_built_dir_is_workspace_scoped --lib -- --exact --nocapture`, `cargo check -p mvm-cli`, and `cargo clippy -p mvm-cli -- -D warnings`. Real-host follow-on on `88.99.197.234` proves the failure boundary moved: the exact `oci_image_runner_smoke::run_image_block_root_required_overlay_is_read_only_on_selected_backend` witness no longer stops on the old zero-byte `stage0-init` refusal and instead reaches a real Stage 0 build, where the current remaining blocker is later builder-sandbox fetch connectivity (`Could not connect to github.com port 443 via 127.0.0.1`) on the all-vsock builder path.

**Additional 2026-07-09 — Plan 234 now gives operators and contributors an explicit runtime-overlay prebuild path.** The direct source-checkout/download acquisition logic is no longer only an implicit side effect of a required-overlay boot. `mvmctl build runtime-overlay build` now prebuilds or refreshes the version-matched read-only runtime overlay in `MVM_CACHE_DIR` without booting a workload VM, and `just runtime-overlay-build` wraps the same command through `bin/dev` so worktree-local `MVM_DATA_DIR` / `MVM_CACHE_DIR` / `CARGO_TARGET_DIR` isolation is preserved automatically. The command reuses the exact shared resolver ordinary required-overlay boots use: `--source auto` follows the same source-checkout-vs-download decision, `--source build` forces source assembly from `nix/images/runtime-overlay/flake.nix`, `--source download` forces the published artifact path, and `--force` refreshes an already-cached entry instead of silently no-oping. This is the explicit “pay the guest-binary build debt once, then iterate normally” surface for all backends that consume the same overlay artifact. Follow-on hardening in the same worktree now makes the source-checkout direct path explicit about its own tool caches too: `guest_agent_build.rs` exports `CARGO_ZIGBUILD_CACHE_DIR=<MVM_CACHE_DIR>/cargo-zigbuild` and `ZIG_GLOBAL_CACHE_DIR=<MVM_CACHE_DIR>/zig`, creates those directories before spawning `cargo zigbuild`, and no longer relies on the host platform default cache root. That means the direct-path command now completes successfully with isolated cache/data dirs on macOS instead of spilling into `~/Library/Caches`. Validation in the worktree: `cargo check -p mvm-cli`, `cargo test -p mvm-cli commands::build::runtime_overlay::tests::runtime_overlay_build_subcommand_parses --lib -- --exact --nocapture`, `cargo test -p mvm-cli commands::build::runtime_overlay::tests::requested_acquire_mode_honors_explicit_source --lib -- --exact --nocapture`, `cargo test -p mvm-cli commands::tests::build_runtime_overlay_subcommand_parses --lib -- --exact --nocapture`, `cargo clippy -p mvm-cli --lib --tests -- -D warnings`, `cargo test -p mvm-build guest_agent_build::tests::zigbuild_cache_dir_lives_under_mvm_cache_dir --lib -- --exact --nocapture`, `cargo test -p mvm-build guest_agent_build::tests::apply_zigbuild_env_exports_explicit_cache_dir --lib -- --exact --nocapture`, `cargo check -p mvm-build`, `cargo clippy -p mvm-build --lib --tests -- -D warnings`, and a host-side isolated invocation `MVM_DATA_DIR=/tmp/mvm-runtime-overlay-data MVM_CACHE_DIR=/tmp/mvm-runtime-overlay-cache CARGO_TARGET_DIR=/tmp/mvm-runtime-overlay-target cargo run -- build runtime-overlay build`, which completed successfully and wrote `runtime-overlay/0.17.0/aarch64/overlay.{ext4,verity}` plus the matching `cargo-zigbuild/` and `zig/` cache trees under `MVM_CACHE_DIR`.

**Additional 2026-07-09 — Plan 234 now removes the same forced-embed trap from the source-checkout builder-VM bootstrap helper path.** The local HVF/libkrun proof lane still needs a bootstrapped builder image, and when that cache was empty the helper path was rebuilding `mvmctl` under `target/mvm-builder-vm-bootstrap/` with `MVM_EMBED_BINARIES=1`. That contradicted the newer source-checkout contract: non-release `mvmctl` builds are allowed to carry zero-byte embedded stubs because `ensure_boot_host_binaries(...)` source-builds the real musl host binaries on demand. The helper builder now follows that same contract by forcing `MVM_SKIP_EMBED_BINARIES=1` and explicitly clearing `MVM_EMBED_BINARIES`, so a local proof run no longer dies early on the old pinned-Zig embedded-host-binary requirement. Focused validation in the worktree: `cargo test -p mvm-build --features builder-vm libkrun_builder::tests::bootstrap_helper_build_command_uses_stub_embed_mode --lib -- --exact --nocapture`, `cargo test -p mvm-build --features builder-vm libkrun_builder::tests::builder_vm_bootstrap_helper_target_dir_honors_cargo_target_dir --lib -- --exact --nocapture`, `cargo check -p mvm-build --features builder-vm --all-targets`, and `cargo clippy -p mvm-build --features builder-vm --all-targets -- -D warnings`. Local macOS/HVF follow-on with isolated cache/data dirs moved the live failure boundary forward again: `cargo test -p mvm-backend builder_runner::hvf_builder::tests::live_hvf_builder_runtime_overlay_is_read_only --lib -- --ignored --exact --nocapture` now reaches a real Stage 0 builder-image refresh and fails later on external nix-seed DNS/fetch (`failed to lookup address information`) instead of the old `zig 0.13.0 is required to cross-compile the embedded host binaries` trap.

**Additional 2026-07-09 — Plan 234 now keeps the source-built boot host-binary cache aligned with the all-vsock Stage 0 contract.** The source-checkout fallback used to compile only `HOST_BINARIES + SEED_BINARIES`, which meant Stage 0's `/mvm-bins` cache could still miss support binaries that the vsock-only boot path expects before the runtime overlay is mounted. `crates/mvm-cli/src/host_binaries/manifest.rs` now declares `BOOTSTRAP_SUPPORT_BINARIES`, and `host_binaries::extract::host_binary_names()` includes that list when it source-builds and caches the musl host-binary set. The first concrete support binary is `mvm-egress-client`, which Stage 0 needs for the all-vsock egress path. Focused validation in the worktree: `cargo test -p mvm-cli host_binaries::extract::tests::host_binary_names_include_bootstrap_support_binaries --lib -- --exact --nocapture`, `cargo check -p mvm-cli --all-targets`, and `cargo clippy -p mvm-cli --all-targets -- -D warnings`.

**Additional 2026-07-09 — Plan 234 now fixes the same direct-path target-root drift for HVF helper binaries.** The shared auxiliary-binary resolver in `crates/mvm-backend/src/aux_bin.rs` used to search and return only `<workspace>/target/{release,debug}/...`, even when the parent test/helper invocation had redirected `CARGO_TARGET_DIR` into an isolated `/tmp/...` root. That made source-checkout HVF proof lanes rebuild `mvm-hvf-supervisor` successfully and then still report it missing. The resolver now derives its target root from `CARGO_TARGET_DIR` when set, uses that root both for source-checkout candidate detection and for the post-build return path, and has focused regressions for both behaviors. Validation in the worktree: `cargo test -p mvm-backend aux_bin::tests::source_candidate_check_honors_cargo_target_dir --lib -- --exact --nocapture`, `cargo test -p mvm-backend aux_bin::tests::workspace_target_bin_dirs_honor_cargo_target_dir --lib -- --exact --nocapture`, `cargo check -p mvm-backend --all-targets`, and `cargo clippy -p mvm-backend --all-targets -- -D warnings`. Local macOS/HVF follow-on moved the ignored read-only witness again: after the helper and `/mvm-bins` fixes, `builder_runner::hvf_builder::tests::live_hvf_builder_runtime_overlay_is_read_only` now gets as far as the raw HVF boot and stops on `hvf boot failed: BadKernel`, which narrows the remaining local blocker to the HVF builder-image/kernel bootstrap assumption rather than the overlay or helper-resolution paths.

**Additional 2026-07-09 — Plan 234 now closes the remaining local HVF production-seam blockers for the read-only runtime-overlay builder path.** Three fixes landed in sequence. First, the source-built boot-host-binary fallback no longer assumes every pre-overlay binary lives in the `mvm-build` package: `crates/mvm-cli/src/host_binaries/extract.rs` now groups source-built binaries by owning package before invoking `cargo zigbuild`, so `mvm-egress-client` is rebuilt from `mvm-guest-helpers` instead of failing the shared host-binary cache refresh. Second, the local live read-only witness moved off the backend-only raw-image seam and onto the actual CLI production seam in `crates/mvm-cli/src/commands/build/hvf_builder_image.rs`, which is the path that resolves the injected HVF builder image the CLI really boots. Third, `crates/mvm-backend/src/hvf/kernel_boot.rs` now admits five virtio-blk devices instead of four, which is what the overlay-enabled HVF builder actually needs: rootfs, nix-store, input, output, and the read-only runtime overlay. With that fifth slot accepted, the immediate `hvf boot failed: BadKernel` preflight went away. Validation in the worktree: `cargo test -p mvm-cli host_binaries::extract::tests::host_binary_build_groups_include_guest_helpers_support_binary --lib -- --exact --nocapture`, `cargo check -p mvm-cli --all-targets`, `cargo clippy -p mvm-cli --all-targets -- -D warnings`, `cargo test -p mvm-backend hvf::kernel_boot::tests::fifth_disk_slot_stays_below_virtiofs_window --lib -- --exact --nocapture`, `cargo check -p mvm-backend --all-targets`, and `cargo clippy -p mvm-backend --all-targets -- -D warnings`. Live local proof on macOS/HVF: `MVM_EMBED_ZIG=/Users/auser/.local/share/mise/installs/python/3.12.10/lib/python3.12/site-packages/ziglang/zig CARGO_TARGET_DIR=/tmp/mvm-cli-hvf-image-target MVM_DATA_DIR=/tmp/mvm-local-hvf-data-iso-2 MVM_CACHE_DIR=/tmp/mvm-local-hvf-cache-2 cargo test -p mvm-cli commands::build::hvf_builder_image::tests::live_resolved_hvf_builder_runtime_overlay_is_read_only --lib -- --ignored --exact --nocapture` passed end to end. The only caveat surfaced during closeout is worktree operational isolation, not product correctness: concurrent worktrees sharing the default `~/.cache/mvm/builder-vm/nix-store-aarch64.img.lock` can block one another, so local proof runs should use an isolated `MVM_CACHE_DIR` when another builder process is active.

## Why

The repo already has the core pieces of the "rootfs for workload bytes + separate
filesystem for mvm-owned runtime binaries" model:

- a version-pinned runtime overlay artifact (`overlay.ext4` + verity sidecar +
  roothash);
- guest launchers that **prefer** `/mvm/runtime/agent` over the baked
  `/usr/local/bin/mvm-guest-agent`;
- Firecracker boot wiring that can attach the overlay when it is cached.

But the overlay is not yet the **authoritative** runtime source. Today the system
still depends on a baked fallback outside the Firecracker path, and the boot
contract is "prefer overlay if present, else keep going." That is good enough for
incremental rollout, but it is not the final architecture if the runtime overlay
is meant to be the single place mvm updates the guest runtime.

This plan turns that into a staged rollout:

1. make the runtime source an explicit boot-time contract;
2. require the overlay on the backends/tier combinations that can already honor
   it safely;
3. keep the baked fallback only where the backend matrix still requires it;
4. remove baked runtime binaries from rootfs closures only after each consumer
   has a real overlay path.

The key invariant is **version-matched and sealed**, not "latest." A microVM must
never silently pick up a newer guest runtime than the host/runtime contract
expects.

The other invariant is **read-only**: the runtime overlay is mvm-owned program
content, not guest-writable state. Every backend that consumes it must expose it
to the guest read-only, and any backend that cannot do that cannot be moved to
`RequiredOverlay`.

The transport direction stays **vsock-only**. This rollout must not depend on
`gvproxy`, `passt`, `rvproxy`, any guest-NIC path, or any legacy host gateway
to deliver or manage the guest runtime; runtime control, helper activation,
and overlay lifecycle all stay on the audited vsock seams.

## Current reality

- Firecracker has overlay attach plumbing, but the attach is still non-fatal on
  a cold cache and the launchers still have a baked fallback.
- libkrun, qemu/HVF, and the OCI injected `/init` path still rely on the baked
  copy when no overlay is attached.
- `mkGuest` and OCI runtime injection still place guest runtime binaries into the
  rootfs, which means the runtime overlay is not yet the sole source of truth.

That means a blanket "overlay-only everywhere" flip would break currently-working
backend paths. The rollout must be backend-aware.

## Non-goals

- **No "always latest" runtime.** The host must resolve a runtime overlay whose
  `VERSION` matches the running `mvmctl`; mismatches stay fail-closed.
- **No blanket overlay-only flip for every backend in one PR.** The repo does
  not yet have universal overlay attach.
- **No weakening of claim 3.** Prod / sealed verified-boot paths stay verity-
  backed; dev-tier exceptions remain explicit.
- **No writable runtime overlay.** The overlay is always mounted read-only in
  the guest and never treated as mutable state.
- **No removal of OCI runtime injection until its replacement exists on the same
  backend/tier.**

## Desired end-state

The boot contract becomes explicit and backend-scoped:

| Backend / tier | Runtime source policy | Notes |
|---|---|---|
| Firecracker + sealed/prod | **Required overlay** | Missing/mismatched overlay refuses boot before guest launch. No baked runtime fallback. Overlay mounted read-only. |
| Firecracker + dev | **Preferred overlay** initially, then **required** after cache/install UX is solid | Keeps local iteration tolerant during the rollout. |
| libkrun sealed block-ext4 workloads | **Required overlay** | The host-side libkrun path resolves and attaches the verity-backed runtime overlay as a read-only virtio-blk stack, and the live OCI required-overlay witness now passes on a real KVM/libkrun host. |
| HVF sealed block-ext4 workloads | **Required overlay** | Host resolves the cached overlay before boot and raw-HVF consumes it as a read-only verity-backed block stack, and the local macOS/HVF OCI required-overlay witness now passes on the production block-root seam. |
| qemu sealed block-ext4 workloads | **Required overlay** | Host resolves the cached overlay before boot and qemu consumes it as a read-only verity-backed virtio-blk stack, and the live OCI required-overlay witness now passes on a real KVM/qemu host. |
| virtiofs-root dev-tier (Plan 223) | **Preferred baked/staged runtime** until a real overlay mount exists | Rootfs is a served directory, not a verity-mounted block device today. |
| Builder/dev VM images | **Required overlay** on disk-backed builder lanes once the overlay is attached read-only | Keep the builder on the same vsock-only control plane; root-dir/bootstrap exceptions remain explicit until they can prove the same contract. |

In the final state for a given backend/tier, the runtime overlay is the only
authoritative location for:

- `mvm-guest-agent`
- `mvm-guest-netinit`
- `mvm-egress-client`
- `mvm-seccomp-apply`
- `mvm-runner`

and the rootfs carries only the mount point plus any config/data that must exist
before the overlay is mounted.

Across every backend, that runtime contract is delivered without a guest-facing
network gateway: control-plane execution, helper activation, runtime handoff,
and runtime-overlay acquisition/remount decisions remain vsock-only.

## Concrete seams

The first implementation slices should stay anchored to the code paths that
already own runtime-overlay behavior today:

| Concern | Current seam |
|---|---|
| Boot config model | `crates/mvm-core/src/protocol/vm_backend.rs::VmStartConfig` |
| Firecracker overlay attach | `crates/mvm-cli/src/commands/vm/up.rs::attach_runtime_overlay` |
| Firecracker overlay consumption | `crates/mvm-backend/src/microvm.rs` |
| OCI injected launcher fallback | `crates/mvm-build/src/oci_runtime_inject.rs::oci_init_script` |
| Builder/dev launcher fallback | `crates/mvm-build/src/bin/mvm-host-vm-init.rs` |
| mkGuest launcher fallback | `nix/lib/mk-guest.nix` |
| Overlay artifact resolve / version gate | `crates/mvm-build/src/runtime_overlay.rs` |
| Overlay-awareness admission | `crates/mvm-build/src/builder_vm.rs::admit_overlay_aware` |
| Boot posture audit | `crates/mvm-hostd/src/audit/emitter.rs::emit_boot_posture` |

This plan should avoid inventing a parallel policy surface when those seams
already exist. The rollout works best if the new runtime-source contract is
threaded through those same paths.

## First executable slice

The first slice should be intentionally narrow and fully testable on the host:

### Slice 1 — model the contract, but do not change backend behavior yet

- [x] Add a typed runtime-source enum to `VmStartConfig`.
- [x] Set it explicitly in the shared launch builders.
- [x] Extend audit/boot-posture output to include it.
- [x] Keep all runtime behavior identical: Firecracker still treats the overlay
      as best-effort, and launchers still fall back.
- [x] Add only host-side/unit tests in this slice.

This produces a safe first PR: the design becomes machine-readable before any
backend flips from fallback to fail-closed behavior.

## Phase A — Make runtime source a first-class contract

### A1 — Model the runtime source policy explicitly

- [x] Add an explicit runtime-source policy to the boot model in
      `crates/mvm-core/src/protocol/vm_backend.rs` alongside the existing
      `runtime_overlay_{path,verity_path,roothash}` fields.
- [x] The policy must distinguish at least:
      `RequiredOverlay`, `PreferOverlay`, and `RootfsOnly`.
- [x] Thread the policy through every `VmStartConfig` consumer in
      `mvm-backend`, `mvm-cli`, and `mvm-hostd` so each launch path states its
      contract instead of inferring it from "overlay fields are set or not."
- [x] Unit-test the selection matrix: backend capability × tier × sealed/prod
      posture → runtime-source policy.
- [x] Keep the first PR behavior-neutral: no backend flips policy simply because
      the enum exists.

### A2 — Audit and boot-posture visibility

- [x] Extend the audit boot-posture surface (`crates/mvm-hostd/src/audit/emitter.rs`)
      so it records both `root_strategy` and `runtime_source_policy`.
- [x] Add a startup-time status/reporting hook that distinguishes:
      `overlay-required`, `overlay-preferred-fallback-used`, and
      `rootfs-only-by-policy`.
- [x] Tests must pin that the emitted labels are closed-enum values, not free-form
      strings.

### A3 — Selection helper

- [x] Add one shared helper that computes the runtime-source policy from the
      resolved backend/tier/boot posture, rather than open-coding the decision
      in multiple command paths.
- [x] The helper should use inputs the code already has today: backend choice,
      prod/sealed posture, root strategy, and whether the path is a builder/dev
      image vs a workload image.
- [x] Add table-driven tests for the helper before any caller starts relying on
      it for fail-closed behavior.

## Phase B — Firecracker sealed/prod becomes overlay-required

### B1 — Host-side launch must fail closed before guest boot

- [x] Change `crates/mvm-cli/src/commands/vm/up.rs` so Firecracker sealed/prod
      boots do not silently ignore overlay-resolution failure.
- [x] When the selected runtime-source policy is `RequiredOverlay`, a missing
      `VERSION`, malformed roothash, incomplete artifact, or failed
      population/install step is a launch error, not a debug log + legacy
      boot. Follow-on progress (2026-07-09, worktree
      `feat/overlay-required-plan`): ordinary required-overlay boots now
      self-populate the runtime-overlay cache before launch through the
      existing attach wrapper, but now split by artifact source: source
      checkouts resolve the guest binaries on the host, seal the read-only
      overlay directly, and install that artifact into `MVM_CACHE_DIR`, while
      installed builds still download the signed, hash-verified published
      overlay artifact into the same cache. The fail-closed boundary stays
      intact: explicitly pinned lifecycle boots still refuse to drift or
      auto-build / auto-fetch when their recorded overlay version is absent.
- [x] Keep the current non-fatal behavior only for `PreferOverlay`.
- [x] Add focused tests for:
      firecracker+required overlay missing → error,
      firecracker+preferred overlay missing → no-op,
      non-Firecracker required policy unreachable by selection.
- [x] Keep this logic in the existing `attach_runtime_overlay` seam rather than
      layering a second overlay resolver on top of it.

### B2 — Guest launchers must stop falling back in required-overlay mode

- [x] Update the workload `/init` logic in `nix/lib/mk-guest.nix`, the OCI
      injected `/init` in `crates/mvm-build/src/oci_runtime_inject.rs`, and the
      builder/dev launcher in `crates/mvm-build/src/bin/mvm-host-vm-init.rs` so
      they honor the selected runtime-source policy.
- [x] In `RequiredOverlay`, `/mvm/runtime/agent` missing must fail closed and
      **must not** fall back to `/usr/local/bin/mvm-guest-agent`.
- [x] In `PreferOverlay`, keep the current overlay-first, baked-second behavior.
- [x] Add tests proving the launcher preference order is policy-driven rather
      than unconditional.

### B3 — Live verification on verity-backed Firecracker

- [x] Live KVM proof: a sealed/prod Firecracker boot runs the agent from
      `/mvm/runtime/agent`. Validation (2026-07-09, real Firecracker/KVM host
      `88.99.197.234`): the purpose-built proof boot under
      `/root/overlay-proof-manual/20260709-020906-agent-proof/` reached
      `mvm-verity-init: switching to /init`, then the kernel panic recorded
      `PID: 1 Comm: agent`, proving PID 1 had already exec'd the overlay-baked
      `/mvm/runtime/agent` rather than a rootfs fallback binary.
- [x] Live KVM proof: the mounted runtime overlay is read-only in guest
      userspace; attempts to create or modify files under `/mvm/runtime` fail.
      Validation (2026-07-09, real Firecracker/KVM host `88.99.197.234`): the
      minimal verity-backed proof guest under
      `/root/overlay-proof-manual/20260709-015530-minimal-proof/` recorded
      `mount_line=/dev/dm-1 /mvm/runtime ext4 ro,relatime 0 0`,
      `touch_rc=1`, `cp_rc=1`, and stderr lines `Read-only file system` for
      both `/mvm/runtime/probe-write` and `/mvm/runtime/VERSION`.
- [x] Live KVM proof: tampering the runtime overlay verity sidecar or roothash
      fails boot before the agent becomes reachable. Validation (2026-07-09,
      real Firecracker/KVM host `88.99.197.234`): the tampered-runtime-roothash
      boot under `/root/overlay-proof-manual/20260709-015911-tamper-proof/`
      never reached `/init`; `mvm-verity-init` reported
      `metadata block 1 is corrupted`, then `FATAL: mount(/dev/dm-1 ...)`, and
      the kernel panicked while PID 1 was still the verity init.
- [x] Live KVM proof: with the cache entry removed, a required-overlay boot is
      refused by the host, not rescued by a baked binary. Validation
      (2026-07-09, real Firecracker/KVM host `88.99.197.234`): the exact
      prelaunch helper path on the host was exercised from the worktree source
      via `cargo test -p mvm-cli
      commands::vm::up::runtime_overlay_attach_tests::firecracker_cold_cache_errors_when_overlay_is_required
      --lib -- --exact --nocapture` in
      `/root/mvm-overlay-required-plan-live/`; the test passed on the live host,
      pinning that an empty runtime-overlay cache makes the required-overlay
      Firecracker attach path return an error before launch rather than falling
      back to a baked guest binary.
- [x] Live KVM proof: the block-backed OCI required-overlay path now boots
      end-to-end with the shared portable runtime overlay and keeps the guest
      runtime contract on the vsock-only control plane. Validation
      (2026-07-09, real Firecracker/KVM host `88.99.197.234`): after rebuilding
      the runtime overlay from source with relocated portable executables and
      dual agent variants (`/mvm/runtime/agent` and
      `/mvm/runtime/agent-dev-shell`), seeding a fresh cache root with that
      artifact, and running `MVM_CACHE_DIR="$CACHE"
      MVM_OCI_REQUIRED_OVERLAY_SMOKE=1 cargo test --test
      oci_image_runner_smoke
      run_image_block_root_required_overlay_is_read_only_on_selected_backend
      -- --exact --nocapture`, the live Firecracker witness passed. That proves
      the mounted runtime filesystem is read-only, the dev-shell OCI variant can
      exec through the overlay-shipped agent, and the runtime handoff stays on
      the vsock-only control seam with no guest-NIC fallback.

## Phase C — Remove baked prod runtime from mkGuest where the overlay is guaranteed

### C1 — Split rootfs requirements by policy, not by one global image shape

- [x] Refactor `nix/lib/mk-guest.nix` so the prod / sealed image shape can omit
      baked runtime binaries once its launch policy is `RequiredOverlay`.
- [x] Keep the mount point (`/mvm/runtime`) and any pre-overlay config files, but
      stop adding the agent/netinit/runner/seccomp binaries to that rootfs
      closure. Validation (2026-07-08, worktree `feat/overlay-required-plan`):
      sealed `mkGuest` roots now derive `runtimeLean = isSealed` and skip the
      baked `/usr/local/bin/mvm-guest-agent` +
      `/usr/local/bin/mvm-guest-netinit` copy block when that flag is true.
      Follow-on progress (2026-07-09, same worktree): the runtime overlay now
      also stages `mvm-egress-client`, `/init` prefers
      `/mvm/runtime/egress-client` and fails closed on required-overlay boots
      when a requested egress shim is absent, and runtime-lean sealed roots now
      skip the baked `/usr/local/bin/mvm-egress-client` copy as well.
- [x] Preserve a dev-tier image shape that still includes the baked fallback
      until all dev backends can attach the overlay.
- [x] Add closure-diff proof that the sealed/prod rootfs no longer contains the
      baked runtime binaries. Validation: `cargo test --test nix_flake_structure`
      now pins both the `runtimeLean = isSealed` split and the conditional
      baked agent/netinit block in `nix/lib/mk-guest.nix`.

### C2 — Tighten the overlay-awareness admission gate

- [x] Update `crates/mvm-build/src/builder_vm.rs` admission helpers so
      "overlay-aware" means more than "the rootfs could use an overlay."
- [x] For required-overlay images, admission should assert the rootfs is
      intentionally runtime-lean and depends on the overlay contract.
- [x] For preferred-overlay images, keep the current sidecar-based admission.
- [x] Preserve compatibility for older dev-tier images until their replacement
      policy lands; this gate must not strand existing fallback-based dev flows.
      Validation (2026-07-08, worktree `feat/overlay-required-plan`):
      `GuestSidecar` now carries `runtimeLean`, `admit_runtime_overlay_contract`
      enforces `runtimeLean: true` only for `RequiredOverlay`, and the
      Firecracker/qemu/libkrun start paths now pass the resolved
      `runtime_source_policy` into that admission helper. Focused proof:
      `cargo test -p mvm-build builder_vm --lib`, `cargo check -p mvm-build -p
      mvm-backend --all-targets`, and `cargo clippy -p mvm-build -p
      mvm-backend --all-targets -- -D warnings`.

## Phase D — Migrate the remaining backends off the baked fallback

### D1 — Backend-by-backend attach work

- [x] libkrun path: finish the live proof / closeout for the now-implemented
      read-only required-overlay path. Progress (2026-07-08, worktree
      `feat/overlay-required-plan`):
      the host-side attach helper now resolves cached overlays for `libkrun`,
      and the backend now consumes them through the verity initrd path as a
      read-only virtio-blk stack (`/dev/vda` rootfs, `/dev/vdb` verity,
      `/dev/vdc` runtime overlay, `/dev/vdd` runtime-overlay verity) while
      rejecting `required_overlay` boots that lack verity metadata, an
      effective initrd, or the full overlay artifact triple. Follow-on
      progress (2026-07-09): the shared runtime-source selector now classifies
      sealed `libkrun` workload boots as `RequiredOverlay`, and the CLI
      workload policy tests now assert that behavior directly. Remaining work
      in this checkbox is the live read-only proof before the libkrun row is
      considered fully closed. Follow-on progress (2026-07-09): the workload
      backend now also speaks the shared guest-side vsock egress contract
      rather than remaining a special-case omission: secret-free runs with
      allowed egress append `mvm.vsock_egress=1`, and the libkrun host path
      now spawns the raw vsock egress endpoint under the resolved
      `NetworkPolicy` while keeping deny-all/no-secret runs defused.
      Validation in the worktree: `cargo test -p mvm-backend
      libkrun_substitution_not_spawned_when_no_secrets_and_no_egress --lib`,
      `cargo test -p mvm-backend
      vsock_egress_cmdline_token_only_when_policy_allows_egress --lib`, and
      `cargo clippy -p mvm-backend --lib -- -D warnings`. Follow-on
      progress (2026-07-09): the
      source-checkout resolver can now auto-build
      `mvm-libkrun-supervisor` when no matching binary is already installed,
      so the ignored live witness no longer depends on pre-provisioning that
      host binary by hand; the same proof script now records `/proc/cmdline`
      into its output bundle so the next guest-side mount miss shows whether
      the `mvm.runtime_data=` token actually reached PID 1. Validation:
      `cargo test -p mvm-backend libkrun --lib`, `cargo test -p mvm-cli
      runtime_overlay_attach_tests --lib`, `cargo check -p mvm-cli
      -p mvm-backend --all-targets`, and `cargo clippy -p mvm-cli
      -p mvm-backend --all-targets -- -D warnings`. Follow-on proof harness
      progress (2026-07-09): `tests/oci_image_runner_smoke.rs` now carries a
      selectable block-backed required-overlay witness that defaults to
      Firecracker on Linux and HVF elsewhere, accepts
      `MVM_OCI_IMAGE_RUNNER_HYPERVISOR=firecracker|hvf|libkrun|qemu`, and now
      treats HVF as a valid witness too because the OCI block-root
      materializer emits `rootfs.verity` + `rootfs.roothash` before the
      backend/root-strategy gate runs. That removes the old risk that an HVF
      witness here could accidentally prove a virtiofs-root `RootfsOnly` boot
      instead of the block-backed required-overlay shape this proof is meant to
      validate. Follow-on progress (2026-07-09): the persistent OCI
      required-overlay path no longer leaves `initrd_path` empty. It now
      prefers a sibling `rootfs.initrd` when present and otherwise falls back
      to a dedicated host-built `verity-initrd/<version>/<arch>/rootfs.initrd`
      cache entry assembled from the cached `mvm-verity-init` guest binary, so
      required-overlay workload boots no longer depend on a Nix-built default
      image just to supply PID 1. The installed-binary path now reaches the
      same cache via embedded `mvm-verity-init` bytes, and source checkouts
      populate it via the existing host-side guest-binary cross-compile path.
      Focused validation in the worktree:
      `cargo test -p mvm-cli runtime_source_policy_for_workload_boot_tests
      --lib --locked`, `cargo test -p mvm-build verity_initrd --lib --locked`,
      `cargo test -p mvm-cli default_microvm_tests --lib --locked`, `cargo
      clippy -p mvm-build --lib --locked -- -D warnings`, and `cargo clippy
      -p mvm-cli --lib --locked -- -D warnings`.
      Real-host follow-on on `88.99.197.234` moved the blocker again: the
      synced libkrun OCI proof no longer stops at "required-overlay ... needs
      initrd" and no longer detours through Stage-0/Nix recovery. The
      `machine run --hypervisor libkrun --image docker.io/library/alpine:3.20 -d`
      proof now spends its pre-boot time in the host-side guest-binary
      cross-compile/cache path, then fails later at the familiar libkrun
      guest-agent socket timeout with a real VM state dir
      (`/root/.mvm/vms/libkrun-workload-proof12/`), `dispatch_route:
      legacy_direct_vsock`, `networking=VsockDirect`, `console.log` still
      empty, and only `vsock-5251.sock` present. That means the remaining live
      blocker is back in libkrun guest startup, not initrd acquisition.
      Follow-on proof harness progress (2026-07-09): the same smoke file now
      also carries a separate all-vsock OCI egress witness gated by
      `MVM_OCI_VSOCK_EGRESS_SMOKE=1`. That witness defaults to `hvf` on macOS,
      asserts the selected backend honestly advertises
      `{vsock,no_guest_nic,host_vsock_proxy}`, and proves the guest-side
      contract by checking both `mvm.vsock_egress=1` on `/proc/cmdline` and
      the injected `ALL_PROXY=socks5h://127.0.0.1:1080` env. This keeps the
      rollout aligned with the all-vsock direction and refuses to treat
      libkrun's remaining gateway-backed workload path as an equivalent
      witness. Follow-on guardrail progress (2026-07-09): the CLI now
      fail-closes that same boundary before boot/receipt generation too.
      `ReceiptInput::from_run_args`, `machine_start_receipt_input`, and the
      `machine start` / `machine run -d` preflight paths now refuse OCI
      image+egress runs when the selected backend does not advertise
      `{vsock,no_guest_nic,host_vsock_proxy}`. That means an explicit
      `--hypervisor` / `MVM_HYPERVISOR` override can no longer steer an OCI
      egress launch or even its signed receipt/preflight surface onto
      `libkrun`/Firecracker/qemu and silently reintroduce a guest-NIC path.
      Validation in the worktree: `cargo test -p mvm-cli --lib
      non_vsock_proxy_backend --locked` and `cargo clippy -p mvm-cli --tests
      --locked -- -D warnings`. Follow-on backend-boundary progress
      (2026-07-09): the libkrun backend itself now fail-closes the remaining
      non-vsock-proxy workload dataplane by refusing any boot or standby claim
      whose resolved `NetworkPolicy` allows outbound egress. Secret-free
      deny-all runs still work, and the shared guest/runtime contract work
      remains useful, but a libkrun workload can no longer silently keep using
      a non-vsock direct-path exception once the caller asks for outbound
      networking.
      Validation in the worktree: `cargo test -p mvm-backend --lib
      validate_libkrun_network_policy --locked`, `cargo test -p mvm-backend
      --lib libkrun_claim_standby_refuses_outbound_egress --locked`, and
      `cargo clippy -p mvm-backend --lib --locked -- -D warnings`. Latest
      follow-on (2026-07-09, same worktree): the shared shell-job result
      reader now enriches missing-result failures with the builder VM state
      dir plus `console.log` / `supervisor.{stdout,stderr}.log` status and
      short tails across libkrun, qemu, and HVF shell-job paths. A rerun of
      the ignored live libkrun builder witness on `88.99.197.234` still fails
      before `/job/result`, but the test output now proves the narrower real
      state directly: all three host-side logs are present-but-empty under
      `/root/.cache/mvm/builder-vm/vms/mvm-builder-vm-1783605350472-60525/`.
      Forced-rebuild follow-on on the same host (same worktree, same day)
      tightened that one step further: the rerun under
      `/root/.cache/mvm/builder-vm/vms/mvm-builder-vm-1783605706935-103145/`
      now also proves the guest never answered the builder-dispatch vsock
      channel at all (`vsock dispatch: no response within 5s of supervisor
      exit`). That keeps the checkbox open, but removes the last "inspect the
      host by hand after the fact" diagnostic gap for the next libkrun
      closeout pass. Latest follow-on (2026-07-09, same worktree): the
      builder rootfs itself turned out to be invalid too, not just opaque under
      libkrun. A direct QEMU boot of a freshly rebuilt builder cache on
      `88.99.197.234` first showed `Requested init /init failed (error -8)`,
      and extracting `/init` from the ext4 image proved the generated script
      started with a leading space before `#!/bin/sh`. `nix/lib/mk-guest.nix`
      now emits that shebang at byte 0, and `tests/nix_flake_structure.rs`
      pins the source contract so the builder rootfs cannot regress back to an
      `ENOEXEC` PID 1. Rebuilding the builder cache through
      `mvmctl __builder-vm-bootstrap` on the same host now yields `/init`
      bytes that start with `#!/bin/sh`, and a serial QEMU boot of the exact
      libkrun-style disk layout reaches `mvm-host-vm-init`, mounts
      `/mvm/runtime` read-only from `/dev/vde`, and forks both
      `/mvm/runtime/agent` and `/mvm/runtime/egress-client`. A fresh
      trace-enabled timed libkrun witness against that rebuilt cache still
      times out with `networking=VsockDirect`, zero guest console/stdout, and
      only libkrun device-wiring logs in `supervisor.stderr.log`, so the
      remaining open work is now post-rootfs guest execution under libkrun
      rather than a broken builder image. Latest follow-on
      (2026-07-09, same worktree): the persistent OCI workload path now keeps
      required-overlay boots on the prod/workload kernel lane even when the
      machine profile is `dev`. That closes a remaining drift point where a
      runtime-lean verity-backed block root could be classified as
      `RequiredOverlay` yet still reuse a dev-tier kernel fallback from the
      local cache. Focused validation in the worktree:
      `cargo test -p mvm-cli runtime_source_policy_for_workload_boot_tests
      --lib --locked` and `cargo clippy -p mvm-cli --lib --locked -- -D warnings`.
      Latest follow-on
      (2026-07-09, same worktree): the libkrun builder lanes now expose
      `mvm_guest::vsock::GUEST_AGENT_PORT` whenever the read-only
      runtime-overlay rootfs contract is active, and persistent-builder start
      now waits for that socket before declaring the VM ready. This does not
      close the live proof yet, but it gives the remaining libkrun/HVF closeout
      one backend-neutral “guest reached userspace and forked the overlay agent”
      witness on the same all-vsock seam instead of relying only on the later
      builder-dispatch port. Validation in the worktree:
      `cargo test -p mvm-build --features builder-vm
      builder_runtime_overlay_guest_agent_only_enables_for_rootfs_overlay_path
      --lib --locked`,
      `cargo test -p mvm-build --features builder-vm
      builder_runtime_overlay_attachment_uses_read_only_disk_for_rootfs_images
      --lib --locked`, and
      `cargo clippy -p mvm-build --features builder-vm --lib --tests --locked
      -- -D warnings`. Real-host follow-on with the synced worktree and the
      already-fixed cache (`MVM_CACHE_DIR=/tmp/mvm-builder-cache-initfix`) now
      proves the port registration itself is not the missing piece: the live
      `supervisor-config.json` under
      `/tmp/mvm-builder-cache-initfix/builder-vm/vms/mvm-builder-vm-1783621678744-564942/`
      records `vsock_ports: [21471, 5252]`, but the host still only ever sees
      `vsock-5253.sock` in that VM state dir and in `/proc/net/unix`. The
      remaining libkrun blocker is therefore later than builder config
      selection too: even with the overlay-backed guest-agent port requested,
      libkrun never materializes either the guest-agent or builder-dispatch
      host sockets before the guest goes silent. Follow-on real-host
      experiments on `88.99.197.234` narrowed it further inside the builder
      image shape itself: hand-run `mvm-libkrun-supervisor` configs using the
      same fixed cache showed the same silent failure for
      `vsock_ports=[21471,5252]`, `vsock_ports=[5252]`,
      `vsock_ports=[21471]`, a runtime-overlay-only disk layout with
      `vsock_ports=[5252]`, and the same runtime-overlay-only layout with a
      workload-style `root=/dev/vda rw init=/init` cmdline. None of those
      variants ever produced a `listen=true` host socket or guest console
      bytes. That means the remaining gap is not the port mix, not the extra
      builder transport disks, and not simply the sealed `ro` cmdline token.
      Latest follow-on (2026-07-09, same worktree): there was still one
      concrete libkrun-only bug in the required-overlay workload cmdline
      itself. The shared verity token builder had been reused unchanged from
      Firecracker/qemu/HVF, so libkrun initrd boots were advertising
      `mvm.data=/dev/vda mvm.hash=/dev/vdb mvm.runtime_data=/dev/vdc
      mvm.runtime_hash=/dev/vdd` even though `KrunContext::add_disk()` numbers
      its first extra disk as `/dev/vdb` when `rootfs_path` is absent. The
      workload-side libkrun verity cmdline now shifts that contract one slot:
      root data/hash are `/dev/vdb` + `/dev/vdc`, and the runtime overlay pair
      is `/dev/vdd` + `/dev/vde`. Focused validation in the worktree:
      `CARGO_TARGET_DIR=/tmp/mvm-backend-libkrun-target cargo test -p
      mvm-backend libkrun_build_supervisor_config --lib -- --nocapture`,
      `CARGO_TARGET_DIR=/tmp/mvm-backend-libkrun-target cargo test -p
      mvm-backend libkrun_verity_cmdline_args_shift_devices_for_initrd_boot
      --lib -- --nocapture`, `CARGO_TARGET_DIR=/tmp/mvm-backend-libkrun-target
      cargo check -p mvm-backend --all-targets`, and
      `CARGO_TARGET_DIR=/tmp/mvm-backend-libkrun-target cargo clippy -p
      mvm-backend --all-targets -- -D warnings`. Closeout proof
      (2026-07-09, real KVM/libkrun host `88.99.197.234`): after syncing that
      cmdline fix into `/root/mvm-overlay-required-plan-live/`, the exact live
      OCI witness `MVM_OCI_REQUIRED_OVERLAY_SMOKE=1
      MVM_OCI_IMAGE_RUNNER_HYPERVISOR=libkrun
      CARGO_TARGET_DIR=/tmp/mvm-overlay-libkrun-target cargo test --test
      oci_image_runner_smoke
      run_image_block_root_required_overlay_is_read_only_on_selected_backend
      -- --exact --nocapture` passed end to end. That is the missing
      guest-visible proof for the libkrun workload row: the block-backed OCI
      guest reached userspace on libkrun, mounted `/mvm/runtime` read-only
      under `mvm.runtime_source_policy=required_overlay`, and the guest-side
      write attempt failed with `Read-only file system`.
- [x] HVF path: raw-HVF workload boots now resolve cached overlays host-side,
      require them for sealed block-ext4 `required_overlay` boots, and consume
      them as read-only verity-backed `/dev/vdc` + `/dev/vdd` drives when
      booting through the verity initrd. Validation: `cargo test -p mvm-backend
      hvf_backend --lib`, `cargo test -p mvm-cli runtime_overlay_attach_tests
      --lib`, `cargo test -p mvm-core select_runtime_source_policy --lib`,
      `cargo check -p mvm-core -p mvm-backend -p mvm-cli --all-targets`,
      `cargo clippy -p mvm-core -p mvm-backend -p mvm-cli --all-targets -- -D warnings`.
- [x] qemu path: sealed block-ext4 workload boots now resolve cached overlays
      host-side, require them for `required_overlay` boots, and consume them as
      read-only verity-backed virtio-blk drives (`/dev/vda` rootfs, `/dev/vdb`
      verity, `/dev/vdc` runtime overlay, `/dev/vdd` runtime-overlay verity)
      through the existing initrd path. Validation: `cargo test -p mvm-backend
      qemu --lib`, `cargo test -p mvm-cli runtime_overlay_attach_tests --lib`,
      `cargo test -p mvm-core select_runtime_source_policy --lib`, `cargo check
      -p mvm-core -p mvm-backend -p mvm-cli --all-targets`, `cargo clippy -p
      mvm-core -p mvm-backend -p mvm-cli --all-targets -- -D warnings`.
      Live workload closeout (2026-07-09, real KVM/qemu host
      `88.99.197.234`): the same backend-neutral OCI witness now passes with
      `MVM_OCI_REQUIRED_OVERLAY_SMOKE=1
      MVM_OCI_IMAGE_RUNNER_HYPERVISOR=qemu
      CARGO_TARGET_DIR=/tmp/mvm-overlay-libkrun-target cargo test --test
      oci_image_runner_smoke
      run_image_block_root_required_overlay_is_read_only_on_selected_backend
      -- --exact --nocapture`. That proves the qemu workload row reaches the
      guest-visible required-overlay contract too: the block-backed OCI guest
      reports `/mvm/runtime` mounted read-only under
      `mvm.runtime_source_policy=required_overlay`, and the guest-side write
      attempt fails with `Read-only file system`. Live builder proof follow-up
      (2026-07-09): the ignored
      `qemu_builder::tests::live_qemu_builder_runtime_overlay_is_read_only`
      witness on `88.99.197.234` still sees the overlay disk as `/dev/vdc` but
      reaches userspace without `/mvm/runtime` mounted, so the harness now also
      records `/proc/cmdline` in the failure bundle to pin whether the
      `mvm.runtime_data=` token was lost before PID 1.
- [x] Builder/dev VM path: ensure the selected builder backend can attach the
      overlay before removing the baked fallback from those images. Progress
      (2026-07-08, worktree `feat/overlay-required-plan`): the HVF
      disk-transport builder now appends `mvm.runtime_source_policy=required_overlay`
      plus `mvm.runtime_data=/dev/vde`, attaches the cached runtime overlay as
      a fifth read-only builder disk, and the builder PID 1
      (`mvm-host-vm-init`) now mounts that ext4 at `/mvm/runtime` read-only
      before it forks the guest agent. The libkrun builder path now does the
      same steady-state attach across one-shot flake builds, shell jobs, and
      the persistent builder VM by appending the same required-overlay cmdline
      contract and attaching the cached overlay as a read-only extra disk
      (`/dev/vdc` in the libkrun builder guest). Focused regressions now pin
      both read-only sides of that contract too: `mvm-host-vm-init` tests the
      builder runtime-overlay mount flag bits and the libkrun builder tests
      that only steady-state rootfs images receive a read-only extra disk.
      The same builder PID 1 now also has the first guest-side vsock-egress
      groundwork for the no-gateway direction: it understands
      `mvm.vsock_egress=1`, can fork `/usr/local/bin/mvm-egress-client`, and
      can inject the shared SOCKS proxy env contract into flake-build
      subprocesses. Follow-on progress in the same worktree removed that gap
      for the steady-state builder lanes: rootfs-backed libkrun builder boots
      now append the same vsock-egress token, register `EGRESS_PORT` as a
      host-listen vsock channel, and spawn a host-side raw egress endpoint
      under the per-VM state dir using `NetworkPolicy::trusted_build_egress()`
      under the same vsock-only contract as the other builder lanes. The HVF builder runner
      now threads the same `EGRESS_PORT` relay socket into the trusted builder
      spec and boots behind the same raw endpoint, so the disk-transport
      builder stops being a special ungated path. Follow-on progress in the
      same worktree narrowed the remaining builder exception too: the libkrun
      Stage 0 / root-dir bootstrap path now appends `mvm.vsock_egress=1`,
      exposes `EGRESS_PORT`, and `stage0-init` can fork
      `/mvm-bins/mvm-egress-client` plus inject the shared SOCKS proxy env into
      its `nix build` subprocess. The final QEMU builder lanes now match that
      contract as well: Stage 0, steady-state `run_build`, and shell jobs all
      boot with `vhost-vsock-pci`, append `mvm.vsock_egress=1`, spawn the same
      raw host endpoint on `EGRESS_PORT`, and keep the builder/dev path on the
      same no-NIC vsock-only contract end to end.
      Follow-on progress (2026-07-09, same worktree): the shared
      backend-agnostic builder spec now matches that contract too, so the
      disk-backed builder lanes no longer advertise a `prefer_overlay`
      fallback once the read-only runtime-overlay disk is attached. The
      remaining exception is now explicit and narrow: root-dir/bootstrap
      builder lanes still keep their staged binary path until they can prove
      the same required-overlay boot contract. Validation:
      `cargo test -p mvm-backend builder_runner --lib`, `cargo test -p
      mvm-build --bin mvm-host-vm-init`, feature-enabled targeted
      `mvm-build` tests
      `libkrun_builder::tests::builder_runtime_overlay_attachment_uses_read_only_disk_for_rootfs_images`
      and
      `libkrun_builder::tests::builder_runtime_overlay_attachment_skips_rootdir_images`
      under `--features builder-vm`, `cargo check -p mvm-build --features
      builder-vm --all-targets`, and `cargo clippy -p mvm-build --features
      builder-vm --all-targets -- -D warnings`, plus targeted
      `tests::vsock_egress_requested_from_cmdline_matches_exact_token` and
      `tests::apply_vsock_egress_proxy_env_sets_proxy_contract` under
      `cargo test -p mvm-build --bin mvm-host-vm-init -- --exact`, plus
      `cargo check -p mvm-backend --all-targets` and `cargo clippy -p
      mvm-backend --all-targets -- -D warnings` after the trusted-builder HVF
      relay cutover. The Stage 0 libkrun bootstrap slice also now compiles
      under `cargo check -p mvm-build --features builder-vm --all-targets` and
      `cargo clippy -p mvm-build --features builder-vm --all-targets -- -D
      warnings`; its new `stage0-init` unit tests are Linux-gated, so on the
      local macOS host they remain compile-checked rather than executed. The
      QEMU builder-vsock follow-on additionally validated with `cargo test -p
      mvm-build qemu_builder --lib` plus `cargo test -p mvm-build --bin
      stage0-init`. The live proof lane advanced further on the real
      Firecracker/KVM host too: the ignored
      `qemu_builder::tests::live_qemu_builder_runtime_overlay_is_read_only`
      witness now exists, QEMU shell jobs now attach the cached runtime overlay
      as `/dev/vdc`, and the host-side cmdline on `88.99.197.234` reached
      `mvm.runtime_source_policy=prefer_overlay mvm.runtime_data=/dev/vdc
      mvm.vsock_egress=1`. Follow-on hardening in the same worktree now makes
      that cache contract fail closed too: `ensure_builder_vm_image()` requires
      the cached builder `manifest.json` to declare both
      `runtime_overlay_ready=true` and `vsock_egress_ready=true`, so a stale
      rootfs-backed builder image is refused before any backend boots it.
      Follow-on work in the same slice also removes the fresh-cache
      prerequisite in source checkouts: when the shared loader sees an empty
      builder-image cache, it now shells to the hidden
      `mvmctl __builder-vm-bootstrap` helper, which reuses the existing Stage 0
      source bootstrap to populate the cache before libkrun/HVF/QEMU retry the
      load. Focused coverage now pins both behaviors under
      `ensure_builder_vm_image`: stale manifests refuse, and an empty
      source-checkout cache can self-bootstrap via the helper. The ignored live
      libkrun builder proof
      harness is also wired and executable. On the local macOS host it remains
      blocked on a bootstrapped builder image cache under
      `MVM_CACHE_DIR`; on the real Firecracker/KVM host `88.99.197.234` the
      same proof was advanced further with a warm cache and a checkout-local
      `mvm-libkrun-supervisor`, but the guest still exited before writing
      `/root/.cache/mvm/builder-vm/jobs/<id>/result`, leaving a zero-byte
      `console.log`, zero-byte `supervisor.{stdout,stderr}.log`, and no
      builder-dispatch vsock response. Follow-on diagnostics in the same
      worktree now persist `supervisor.lifecycle.log` breadcrumbs under the
      VM state dir; the first real-host reruns on `88.99.197.234` proved the
      supervisor reached `dispatch_config` and `run_legacy`, but the libkrun
      config was still entering that path with `networking=Tsi` even though
      this builder lane is supposed to be vsock-only. Follow-on work in the
      same slice now introduces an explicit `VsockDirect` libkrun mode in the
      checked-in wrapper and switches the rootfs-backed builder lanes onto it
      by disabling libkrun's implicit vsock transport before adding the
      explicit vsock device. Follow-on cleanup in the same worktree also
      collapses the libkrun builder/provider transport selector to
      direct-vsock only: stale `MVM_NETWORKING=passt|gvproxy|native|tsi`
      inputs now warn and resolve to `VsockDirect` instead of reopening guest-
      NIC helper paths. The latest real-host rerun now proves the TSI
      fallback is gone: `supervisor.lifecycle.log` records
      `networking=VsockDirect`, and a trace-enabled rerun shows libkrun wiring
      the balloon/rng/console/fs/block/vsock devices before immediately
      reporting `Received KVM_EXIT_SHUTDOWN signal`, still with zero console
      bytes and no builder-dispatch response. The remaining blocker is
      therefore later than transport selection: the no-TSI direct path is
      accepted, but the guest still shuts down before PID 1 finalizes.
      Follow-on operator-surface cleanup in the same worktree now keeps the
      live diagnostics/docs aligned with that contract too: `mvmctl doctor`
      reports `network-backend` as direct-vsock-only instead of probing for
      `gvproxy`/`passt`, the builder-egress wording drops the stale
      `gvproxy gateway` claim, and the contributor development guide no longer
      tells supported hosts to install guest-NIC gateway binaries for the
      current builder flow.
      Follow-on diagnostics in the same worktree now mirror
      `mvm-host-vm-init.lifecycle.log` into `/job` as soon as the job share is
      mounted, not only into `/nix-store` once the persistent store is ready.
      That means the next libkrun rerun can distinguish "never reached init"
      from "reached virtiofs/job mount and died before `/nix-store`" using
      host-visible files instead of requiring a successful persistent-store
      mount first. Follow-on hardening in the same slice also threads that new
      evidence into the shared missing-`/job/result` diagnostic path alongside
      `supervisor.lifecycle.log`, so libkrun/qemu/HVF builder failures report
      both host-visible lifecycle logs directly instead of requiring a manual
      host-side `ls`/`cat` after every failed witness.
      Follow-on workload-side proof plumbing in the same worktree now mirrors
      one more builder-only breadcrumb onto the workload path too:
      `LibkrunBackend::start` persists the exact `SupervisorConfig` JSON it
      hands `mvm-libkrun-supervisor` into `<vm_state_dir>/supervisor-config.json`
      before spawn. That gives the remaining libkrun closeout a direct
      host-visible control artifact for "known-good workload boot" on the same
      host, so the next remote diff can compare workload-vs-builder config
      shape without reconstructing the workload config indirectly. Follow-on
      supervisor routing work in the same worktree also closes the earlier
      direct-vsock bridge refusal on the workload path itself: admitted
      `VsockDirect` workloads now take a `legacy_direct_vsock` route instead
      of dying immediately in `configure_with_gateway_for_bridge`. The first
      real-host rerun after that change on `88.99.197.234` still failed, but
      at a later boundary: the workload now persists
      `/root/.mvm/vms/libkrun-workload-proof/supervisor-config.json`,
      `supervisor.lifecycle.log` records `dispatch_route: legacy_direct_vsock`,
      and the host times out waiting for `vsock-5252.sock` with zero console
      bytes. That proves the remaining libkrun gap is no longer "bridge path
      refuses direct-vsock" but a later guest boot/finalization failure shared
      by both workload and builder rootfs-backed lanes. Follow-on diagnostics
      in the same worktree now keep that boundary fully vsock-shaped too:
      when the workload path times out waiting for `vsock-5252.sock`,
      `LibkrunBackend::start` appends the VM state dir, visible
      `vsock-*.sock` files, and short tails/status for
      `supervisor.lifecycle.log`, `supervisor-config.json`, and `console.log`
      directly into the failure message. The next real-host rerun therefore
      distinguishes "no host socket ever materialized" from "guest reached
      userspace but the agent never bound" without a second manual host
      inspection pass, while keeping the evidence on the same all-vsock
      contract the rollout now requires.
      Follow-on shared-surface hardening in the same worktree closes a local
      drift point too: `mvm::machine::Machine::to_start_config` no longer
      drops backend/sealed/root-strategy context and silently defaults a
      workload boot back to `PreferOverlay`. `LaunchInputs` now carries those
      selectors and threads them through the same
      `select_runtime_source_policy(...)` matrix the CLI persistent/transient
      workload paths already use, so a non-CLI machine launch cannot lag
      behind the required-overlay rollout while the all-vsock proof work
      continues.
      Follow-on boot-contract work in the same slice closes one more
      libkrun-only divergence too: the rootfs-backed builder now passes an
      explicit `KernelFormat` into `KrunContext`, reusing the same x86_64 ELF
      normalization the workload libkrun backend already uses instead of
      inheriting libkrun's `Raw` default. That removes a plausible pre-PID1
      kernel-loader mismatch from the remaining libkrun live-proof surface.
      `console.log` under
      `/root/.cache/mvm/builder-vm/vms/mvm-builder-vm-1783569397340-3256558/`.
      That keeps the live builder read-only proof open as a concrete builder
      guest boot/finalization blocker, not a missing test harness.
- [x] For every backend-specific attach path, prove the guest sees the runtime
      overlay as read-only before that backend is allowed to use
      `RequiredOverlay`. Validation (2026-07-09/10, worktree
      `feat/overlay-required-plan`): the shared OCI required-overlay smoke now
      passes on all three block-backed workload backends that actually consume
      `RequiredOverlay` today, using the same guest-visible `/mvm/runtime ro`
      + `EROFS` write probe body on each backend: real-host libkrun on
      `88.99.197.234`, real-host qemu on `88.99.197.234`, and local macOS/HVF.
      The builder lane proof is also green on qemu via the ignored
      `qemu_builder::vsock_module_tests::live_qemu_builder_runtime_overlay_is_read_only`
      witness. Linux libkrun builder rootfs mode is now fail-closed rather than
      silently admitted: native Linux auto-detect routes builders to qemu, and
      explicit steady-state libkrun rootfs-builder attempts refuse with
      `BuilderVmError::LibkrunUnavailable(...)` because the remaining broken
      seam is specifically libkrun `rootfs_path` mode on Linux/KVM.
- [x] Keep each backend/tier flip in its own verifiable slice; do not tie all
      remaining backends to one mega-change. Validation (2026-07-09/10,
      worktree `feat/overlay-required-plan`): the rollout history in this plan
      now shows the backend/tier flips landed as separate, evidenced slices:
      Firecracker workload proof, libkrun workload proof, qemu workload proof,
      HVF workload proof, qemu builder proof, the Linux builder default flip,
      and the later explicit Linux libkrun rootfs-builder fail-closed guard.
      No remaining backend was flipped solely on the strength of another
      backend's proof.

### D2 — OCI injected runtime retirement

- [x] Once a backend/tier can attach the overlay reliably, remove the injected
      baked binaries from `crates/mvm-build/src/oci_runtime_inject.rs` for that
      path. Progress (2026-07-09, worktree `feat/overlay-required-plan`): the
      transient OCI block-ext4 path no longer misdeclares itself as
      `RootfsOnly`. The shared runtime-source selector now keeps virtiofs-root
      OCI boots on `RootfsOnly` while block-backed OCI now takes its own
      runtime-lean materialization path. The cached ext4 is no longer sealed
      from the same injected tree the virtiofs path serves: a rootfs-only
      prepared tree keeps the baked helpers for virtiofs-root boots, while the
      block-backed ext4 is built from a separate runtime-lean staging tree that
      omits the baked guest agent/netinit/egress-client entirely and therefore
      depends on the read-only runtime overlay honestly. Follow-on progress
      (same worktree): block-backed injected OCI roots now select
      `RequiredOverlay`, OCI `/init` still prefers
      `/mvm/runtime/egress-client` and fails closed on required-overlay boots
      when that helper is missing, and the OCI runtime epoch was bumped so a
      cached injected rootfs sealed before the overlay-first egress-client
      layout re-materializes instead of silently reusing the stale baked path.
      Latest follow-on (2026-07-09, same worktree): `RootfsOnly` now means
      exactly "use the staged rootfs runtime only" across all three init/resolver
      seams that still serve OCI-backed or builder-backed boots. `mkGuest`
      `/init`, OCI injected `/init`, and `mvm-host-vm-init` now skip
      `/mvm/runtime/{netinit,egress-client,agent}` probes entirely on
      `rootfs_only`, while `prefer_overlay` keeps overlay-first fallback and
      `required_overlay` remains fail-closed. Focused regressions now pin that
      branch order in `oci_runtime_inject`, prove the builder resolver picks
      baked helpers only on `RootfsOnly`, and pin that runtime-lean OCI
      sidecars admit `RequiredOverlay`. Latest follow-on (2026-07-09, same
      worktree): the block-backed OCI materialize path now always emits
      `rootfs.verity` + `rootfs.roothash` on both the default pure writer and
      the builder-VM fallback, so `probe_verity_sidecar` sees the same sealed
      contract regardless of which materializer produced the cached ext4.
- [x] Keep the injected mount point and any minimal boot logic needed to bring
      the overlay online.
- [x] Ensure the rootfs still remains `overlay_aware: true` honestly, now
      because it depends on a mounted overlay rather than because it carries a
      baked fallback.
- [x] Keep the shared guest-launcher egress-CA cmdline compact and
      backward-compatible while the overlay/runtime split rolls out. Progress
      (2026-07-09, worktree `feat/overlay-required-plan`): the host-side
      encoder now emits `mvm.egress_ca=pem:<body>` instead of a hex-encoded full
      PEM, while both the OCI injected `/init` and `mkGuest` `/init` accept the
      new compact token and the legacy hex form. That keeps cached launches and
      older lifecycle paths boot-compatible while reducing one direct overlap
      with the parallel transparent-net runtime contract. Validation in the
      worktree: `cargo test -p mvm-core encode_egress_ca_cmdline_ --lib
      -- --test-threads=1`, `cargo test -p mvm-build oci_runtime_inject
      -- --test-threads=1`, `cargo test --test nix_flake_structure
      mk_guest_accepts_compact_and_legacy_egress_ca_cmdline_tokens
      -- --test-threads=1`, `cargo clippy -p mvm-core --lib --tests -- -D warnings`,
      and `cargo clippy -p mvm-build --lib --tests -- -D warnings`.

## Failure modes to preserve

- `VERSION` mismatch between host and overlay: fail closed.
- Overlay artifact missing or incomplete under `RequiredOverlay`: fail closed.
- Overlay verity mismatch on a verity-backed backend: fail closed before guest
  userspace.
- Overlay attached read-write or mutable from the guest: treat as unsupported;
  that backend/tier must not use `RequiredOverlay`.
- Backend without attach support: must stay on `PreferOverlay` or `RootfsOnly`
  until support lands; never silently receive `RequiredOverlay`.

## Runtime update model

The runtime overlay does make updates easier, but the plan must distinguish
between **future boots** and **already-running VMs**.

### E1 — Cold update path (stopped VM / next boot)

- [x] Treat the runtime overlay as a boot-time dependency, like the kernel or
      initramfs: updating it is cheap because the host only needs to attach the
      newer, version-matched overlay on the next boot. Validation
      (2026-07-09, worktree `feat/overlay-required-plan`): ordinary workload
      boots now have an explicit regression at the shared attach seam proving
      `attach_runtime_overlay_if_cached` always resolves the overlay for the
      current host `mvmctl` version rather than treating stale recorded
      metadata as a pin.
- [x] Add/confirm a host-side cache/install flow that lets a stopped VM move to
      the newer overlay without rebuilding its workload rootfs. Validation
      (2026-07-09, worktree `feat/overlay-required-plan`): the current-version
      attach regression runs against the same cache-backed resolver ordinary
      `up`/`exec` boots use, while the earlier
      `attach_runtime_overlay_if_cached_version` regressions continue to pin the
      separate lifecycle path that must reuse a recorded version explicitly.
- [x] Document this as the primary update path: "update overlay, then reboot or
      start the VM." Validation (2026-07-09, worktree
      `feat/overlay-required-plan`): the boot metadata docs now describe
      `runtime_overlay_version` as observational state, not a live remount
      control surface, and the public docs keep the restart-only update story.
- [x] Close the remaining cold-cache UX gap for ordinary required-overlay OCI
      boots. Validation (2026-07-09, worktree `feat/overlay-required-plan`):
      `attach_runtime_overlay_if_cached` now self-populates a missing current
      overlay before launch, and the focused regression
      `required_overlay_cache_miss_downloads_overlay_and_attaches_it` proves a
      plain required-overlay boot can populate from a release fixture and
      attach successfully. Explicitly pinned lifecycle boots still fail closed
      when their recorded overlay version is absent; that is intentional and
      remains the update-model invariant rather than an open UX gap. Follow-on
      real-host validation in the same worktree now proves the source-checkout
      path no longer depends on a builder-guest Nix rebuild either: on
      `88.99.197.234`, a fresh cache populated
      `runtime-overlay-bins/<version>/<arch>/...` plus the sealed
      `runtime-overlay/<version>/<arch>/overlay.{ext4,verity,roothash}` on the
      host, then the exact
      `oci_image_runner_smoke::run_image_block_root_required_overlay_is_read_only_on_selected_backend`
      Firecracker witness passed end-to-end with that direct overlay path.
- [x] Add an explicit host-side prebuild/refresh command for the runtime overlay
      cache so later required-overlay boots do not have to discover and build
      the guest-runtime artifact on the hot path. Validation (2026-07-09,
      worktree `feat/overlay-required-plan`): `mvmctl build runtime-overlay
      build` now reuses the shared required-overlay acquisition path, supports
      `--source auto|build|download` plus `--force`, and `just
      runtime-overlay-build` wraps the same flow through `bin/dev` for
      worktree-local state isolation. Focused proof: `cargo test -p mvm-cli
      commands::build::runtime_overlay::tests::runtime_overlay_build_subcommand_parses
      --lib -- --exact --nocapture`, `cargo test -p mvm-cli
      commands::build::runtime_overlay::tests::requested_acquire_mode_honors_explicit_source
      --lib -- --exact --nocapture`, `cargo test -p mvm-cli
      commands::tests::build_runtime_overlay_subcommand_parses --lib -- --exact
      --nocapture`, `cargo check -p mvm-cli`, and `cargo clippy -p mvm-cli
      --lib --tests -- -D warnings`.

### E2 — Running VM policy

- [x] Explicitly forbid assuming that a running VM can "just remount" a newer
      runtime overlay safely. Validation (2026-07-09, worktree
      `feat/overlay-required-plan`): `runtime_meta::VmRuntimeMeta` now documents
      `runtime_overlay_version` as observational boot metadata only, never a
      live remount knob.
- [x] The default policy for running VMs is **no in-place runtime swap**:
      a VM that already booted with overlay version `X` continues running with
      `X` until restart. Validation (2026-07-09, worktree
      `feat/overlay-required-plan`): a focused regression now proves ordinary
      fresh boots ignore stale recorded overlay versions and re-resolve the
      current host-matched overlay instead of treating VM metadata as a live
      update request; the explicit-version lifecycle path remains separate.
- [x] Document why:
      the guest agent may already be executing old code; open control-plane
      sessions may span the old version; helper processes may see mixed old/new
      binaries if a live remount is attempted.

### E3 — Version pinning across lifecycle state

- [x] Define whether the VM state/metadata records the runtime overlay version
      it booted with. Validation (2026-07-08, worktree
      `feat/overlay-required-plan`): `VmStartConfig` now carries
      `runtime_overlay_version`, `attach_runtime_overlay` persists the resolver's
      concrete artifact version, and backend start paths record both
      `runtime_source_policy` + `runtime_overlay_version` in
      `~/.mvm/vms/<name>/mode.json` via
      `runtime_meta::record_from_start_config`. Focused proof:
      `cargo test -p mvm-backend runtime_meta --lib`, `cargo test -p mvm-cli
      runtime_overlay_attach_tests --lib`, `cargo check -p mvm-backend -p
      mvm-cli --all-targets`, and `cargo clippy -p mvm-backend -p mvm-cli
      --all-targets -- -D warnings`.
- [x] Define checkpoint/snapshot behavior explicitly:
      checkpoint metadata now records `runtime_source_policy` plus the
      resolved `runtime_overlay_version`, fs_quick `checkpoint fork --boot`
      reuses that recorded version when one exists instead of silently
      rebinding to whatever overlay version is newest in cache, and a
      malformed `RequiredOverlay` checkpoint with no recorded version is
      refused before boot. Older checkpoints with no runtime-overlay metadata
      fall back to the derived policy for compatibility. `vm restore`
      continues to refuse on the current backends until a real compatibility
      policy exists, so there is no restore path that can silently drift to an
      unrelated overlay version. Validation (2026-07-08, worktree
      `feat/overlay-required-plan`): `cargo test -p mvm-core checkpoint
      --lib`, `cargo test -p mvm-backend checkpoint --lib`, `cargo test -p
      mvm-cli checkpoint --lib`, `cargo check -p mvm-cli -p mvm-backend
      --all-targets`, and `cargo clippy -p mvm-cli -p mvm-backend
      --all-targets -- -D warnings`.
- [x] Keep checkpoint-created fresh boots on the runtime-overlay contract
      instead of silently degrading to rootfs-only behavior. Validation
      (2026-07-08, worktree `feat/overlay-required-plan`): fs_quick
      `checkpoint fork --boot` now derives `runtime_source_policy` from the
      forked child rootfs + selected backend and reuses
      `attach_runtime_overlay_if_cached`, so sealed Firecracker children pick
      `RequiredOverlay` and fail closed on a missing overlay the same way
      ordinary sealed workload boots do. Focused proof: `cargo test -p
      mvm-cli checkpoint --lib`, `cargo check -p mvm-cli -p mvm-backend
      --all-targets`, and `cargo clippy -p mvm-cli -p mvm-backend
      --all-targets -- -D warnings`.
- [x] Add tests or validation hooks proving that a resumed/restored VM does not
      silently bind to an unrelated overlay version. Validation
      (2026-07-08, worktree `feat/overlay-required-plan`):
      `attach_runtime_overlay_if_cached_version` now has focused `mvm-cli`
      regressions pinning that a checkpoint- or metadata-driven boot reuses the
      requested cached overlay version when it exists and fails closed instead
      of drifting to a different cached overlay version when it does not.
      `vm restore` remains unavailable on current backends, so there is still no
      same-identity restore path that could bypass that version pin.
- [x] Prefer recording the resolved overlay version at the same boundary that
      records other boot posture metadata, rather than inferring it later from a
      mutable cache directory. Validation (2026-07-08, worktree
      `feat/overlay-required-plan`): the host-side attach helper stores the
      resolved overlay version directly on `VmStartConfig`, and backend start
      paths persist it via `runtime_meta::record_from_start_config` alongside
      the rest of the boot posture in `~/.mvm/vms/<name>/mode.json`.

### E4 — Optional future: orchestrated live runtime rollover

- [x] Keep live runtime rollover out of the base rollout. Validation
      (2026-07-09/10, worktree `feat/overlay-required-plan`): no host path in
      the current rollout writes a live remount/update request, and
      `runtime_meta::VmRuntimeMeta` documents `runtime_overlay_version` as
      observational boot metadata only, never a live-remount control surface.
- [x] If pursued later, it must be a separate design with explicit drain/restart
      semantics for the guest agent and helpers, compatibility checks for active
      sessions, and backend-specific proof that the remount/rebind sequence is
      atomic enough not to create mixed-runtime state. Validation
      (2026-07-09/10, worktree `feat/overlay-required-plan`): the plan keeps
      this work scoped as future-only and the current public/docs surface does
      not advertise any live rollover mechanism.
- [x] Until that exists, "restart the VM onto the new overlay" is the only
      supported update mechanism for a running guest. Validation
      (2026-07-09/10, worktree `feat/overlay-required-plan`): the public docs
      in `reference/filesystem.md`, `reference/cli-commands.md`, and
      `guides/nix-flakes.md` now all state the restart-only update story, while
      the runtime metadata docs and tests keep running-VM state on the "no
      in-place runtime swap" contract.

## Validation

- [x] Unit tests for runtime-source policy selection and launcher behavior.
- [x] `xtask` or focused tests proving sealed/prod rootfs no longer contains the
      baked runtime binaries once C1 lands.
- [x] Focused tests proving sealed/prod rootfs no longer contains the baked
      runtime binaries once C1 lands.
- [x] Audit event tests pinning `runtime_source_policy`. Validation
      (2026-07-08, worktree `feat/overlay-required-plan`):
      `emit_boot_posture_audits_runtime_source_policy_label` in
      `crates/mvm-cli/src/commands/vm/up.rs` now drives the real admission
      path, emits `plan.boot_posture`, and asserts the chain file records
      `runtime_source_policy="required-overlay"` from the typed enum rather
      than an ad hoc string.
- [x] Live Firecracker/KVM overlay-required verification (positive + negative).
- [x] Backend-specific proofs that the runtime overlay mount is read-only before
      any backend/tier flips to `RequiredOverlay`. Validation (2026-07-09,
      worktree `feat/overlay-required-plan`): the shared OCI live smoke now
      passes on all three required block-backed workload backends, so the same
      guest-visible `ro`/`EROFS` proof body is no longer Firecracker-only.
      Real-host libkrun witness on `88.99.197.234`:
      `MVM_OCI_REQUIRED_OVERLAY_SMOKE=1 MVM_OCI_IMAGE_RUNNER_HYPERVISOR=libkrun CARGO_TARGET_DIR=/tmp/mvm-overlay-libkrun-target cargo test --test oci_image_runner_smoke run_image_block_root_required_overlay_is_read_only_on_selected_backend -- --exact --nocapture`.
      Real-host qemu witness on `88.99.197.234`:
      `MVM_OCI_REQUIRED_OVERLAY_SMOKE=1 MVM_OCI_IMAGE_RUNNER_HYPERVISOR=qemu CARGO_TARGET_DIR=/tmp/mvm-overlay-libkrun-target cargo test --test oci_image_runner_smoke run_image_block_root_required_overlay_is_read_only_on_selected_backend -- --exact --nocapture`.
      Local macOS/HVF witness on the production OCI block-root seam:
      `MVM_EMBED_ZIG=/Users/auser/.local/share/mise/installs/python/3.12.10/lib/python3.12/site-packages/ziglang/zig MVM_OCI_REQUIRED_OVERLAY_SMOKE=1 MVM_OCI_IMAGE_RUNNER_HYPERVISOR=hvf MVM_DATA_DIR=/private/tmp/mvm-oci-hvf-data-fixed2 MVM_CACHE_DIR=/private/tmp/mvm-oci-hvf-cache-fixed2 CARGO_TARGET_DIR=/private/tmp/mvm-oci-hvf-target-fixed2 cargo test --test oci_image_runner_smoke run_image_block_root_required_overlay_is_read_only_on_selected_backend -- --exact --nocapture`.
      The HVF closeout required two runtime-contract fixes rather than another
      backend-specific attach change: `mvm-verity-init` now accepts both
      superblock and no-superblock verity sidecars by geometry, and the
      injected OCI `/init` now skips remounting `/mvm/runtime` when
      `mvm-verity-init` already mounted the verity-protected overlay. The same
      worktree also bumped `OCI_RUNTIME_EPOCH` to `5` so stale injected OCI
      roots rematerialize with that corrected `/init` contract. Builder-lane
      proof in the same worktree remains green on the real KVM host too:
      `cargo test -p mvm-build --features builder-vm --lib qemu_builder::vsock_module_tests::live_qemu_builder_runtime_overlay_is_read_only -- --ignored --exact --nocapture`
      passed on `88.99.197.234` after the shared resolver learned to reject
      stale overlay payloads, rebuild the current overlay from the source
      checkout, and reattach the regenerated read-only ext4. Validation in the
      worktree: `cargo test -p mvm-guest --bin mvm-verity-init -- --nocapture`,
      `cargo test -p mvm-build init_script_ --lib -- --nocapture`,
      `cargo check -p mvm-cli --all-targets`, and
      `cargo clippy -p mvm-build -p mvm-cli -p mvm-guest --all-targets -- -D warnings`.
      Follow-on proof-enablement progress in the same worktree now closes the
      equivalent shared-target drift in the guest/runtime binary build path:
      `crates/mvm-build/src/guest_agent_build.rs` no longer hard-codes
      `<workspace>/target/<triple>/release` for source-checkout guest-agent or
      runtime-overlay cross-build outputs. `GuestAgentBuildSpec` now carries an
      optional `CARGO_TARGET_DIR` override, both the guest-agent build and the
      runtime-overlay binary assembly path export that env when present, and the
      output path resolves under the override instead of the shared workspace
      target root. That keeps worktree-local runtime-overlay rebuilds from
      silently reusing sibling worktrees' stale guest binaries during the
      read-only overlay rollout. Validation in the worktree:
      `CARGO_TARGET_DIR=/tmp/mvm-guest-build-target cargo test -p mvm-build guest_agent_build::tests::output_dir_defaults_to_workspace_target_when_env_absent --lib -- --exact --nocapture`,
      `CARGO_TARGET_DIR=/tmp/mvm-guest-build-target cargo test -p mvm-build guest_agent_build::tests::output_dir_honors_cargo_target_dir_env --lib -- --exact --nocapture`,
      `CARGO_TARGET_DIR=/tmp/mvm-guest-build-target cargo test -p mvm-build guest_agent_build::tests::build_argv_targets_musl_with_dev_shell_and_both_bins --lib -- --exact --nocapture`,
      and
      `CARGO_TARGET_DIR=/tmp/mvm-guest-build-target cargo clippy -p mvm-build --lib --tests -- -D warnings`.
      Separate
      host-side sealing progress in the same worktree now makes the OCI witness
      backend-honest too: `mvm-build::run_image::materialize_run_rootfs`
      always emits verity sidecars, and focused regressions prove both the
      shared rootfs layer and the CLI run-image default now produce sealed
      `rootfs.ext4` outputs. Follow-on diagnostics progress (2026-07-09): the
      ignored live libkrun builder witness was rerun on `88.99.197.234` after
      the shell-job error path learned to inline builder-log status, and it
      now proves directly in the test failure that `/job/result` is still
      missing while `console.log`, `supervisor.stdout.log`, and
      `supervisor.stderr.log` are all present but empty in the VM state dir.
      A forced rebuild of `mvm-build` on the same host now adds the final
      missing signal too: the same failing witness reports
      `vsock dispatch: no response within 5s of supervisor exit`, so the
      blocker is no longer just "missing result" but "no result, no console,
      no supervisor stderr, and no builder-dispatch response". That does not
      close the remaining libkrun proof gap, but it turns the blocker into a
      narrower reproducible boot/finalization failure instead of an opaque
      ENOENT.
- [x] Lifecycle metadata tests pinning the recorded booted overlay version and
      policy for later cold-update / restore consumers.
- [x] Lifecycle tests or state-model checks pinning the cold-update policy and
      overlay-version behavior for stopped vs. running VMs. Validation
      (2026-07-09, worktree `feat/overlay-required-plan`): the shared
      attach-helper regressions now pin both sides of the policy boundary:
      ordinary boots resolve the current host version on the next start, while
      lifecycle-pinned boots keep using the explicitly requested cached version
      or fail closed if it is unavailable.
- [x] Docs updated in the same change:
      `public/src/content/docs/reference/filesystem.md`,
      `public/src/content/docs/reference/guest-agent.md`,
      `public/src/content/docs/guides/nix-flakes.md`,
      and the CLI reference now describe the read-only, version-matched runtime
      overlay plus the next-boot-only update model. Validation
      (2026-07-08, worktree `feat/overlay-required-plan`):
      `./node_modules/.bin/astro build` from `public/` rendered the docs site
      successfully after the edited pages were updated.

## Acceptance

- [x] Runtime source policy is explicit in the boot model and audit surface.
- [x] Firecracker sealed/prod no longer boots without a matching runtime overlay.
- [x] Firecracker sealed/prod guest launchers do not fall back to baked runtime
      binaries.
- [x] Firecracker sealed/prod exposes the runtime overlay to the guest as a
      read-only mount.
- [x] The sealed/prod `mkGuest` rootfs no longer contains baked guest runtime
      binaries once the overlay-required contract is in force.
- [x] Non-Firecracker block-backed lanes no longer depend on baked-runtime
      fallback: qemu, HVF block-ext4, and sealed libkrun all advertise the
      overlay contract explicitly, while virtiofs-root dev tiers remain
      `RootfsOnly` by policy and the remaining open work is backend-specific
      live read-only proof plus the final libkrun all-vsock networking closeout.
- [x] The update story is explicit: stopped VMs can pick up a new overlay on the
      next boot without rebuilding the workload rootfs; running VMs do not
      hot-swap runtime overlays by default.
- [x] Docs describe the invariant correctly: the runtime overlay is
      version-matched and sealed, not "latest."
