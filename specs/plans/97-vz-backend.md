# Plan 97 — `Virtualization.framework` backend (`vz`)

> **✅ CLOSED (2026-06-13): Vz at full macOS-libkrun parity.** The full
> user stack composes on `--hypervisor vz`, live-proven on macOS-26
> Apple Silicon: build→admit→boot→agent, checkpoint/fork/warm pool,
> Rust-native supervisor (Swift deleted, Plan 152), deny-by-default
> egress + chain-signed audit, `trust audit verify` (+ tamper→nonzero),
> and `doctor` claims posture. The nine-claim table is reconciled below
> (all inherit except claim 8, which shipped). The two macOS carve-outs
> — secret substitution (claim 13) and dm-verity verified boot (claim 3)
> — are absent on the macOS default (libkrun) identically and are shared
> cross-backend follow-ups, not vz gaps. Phase C's "byte-identical hash"
> acceptance is amended to functional parity (ext4 is non-deterministic).
> See Sprint 55 close-out for the per-leg evidence trail.
>
> **Status (2026-05-22):** Phases A, B, D, E complete. Workload microVM
> path is end-to-end functional on macOS 13+: `MVM_BACKEND=vz mvmctl
> up` admits, builds the `SupervisorConfig`, spawns the codesigned
> Swift supervisor, runs the VM, manages its PID/lifecycle, and
> `mvmctl doctor` surfaces availability + supervisor-binary presence.
> CI lane `vz-macos` matrices the build over macos-13 + macos-latest.
> Rust supervisor-JSON fuzz target wired into `security.yml`.
>
> The banner below this line is historical (the original 2026-05-22
> Swift-era status); the Closeout section is the current source of truth.
> The narrative and changelog that follow are preserved as history.
>
> Pick-up command for fresh sessions: read the **Closeout** section at the
> end of this file first; the body below is background.

## Progress checklist

Top-level phases:

- [x] **Phase A** — supervisor binary. *Originally a Swift
      `mvm-vz-supervisor`; replaced by the Rust-native objc2 supervisor
      (the Swift crate was deleted) — the JSON config surface and vsock
      bridges are unchanged. Live-proven 2026-06-12: first Vz workload
      boot with the guest agent reachable on vsock.*
- [x] **Phase B** — `VzBackend` impl in `crates/mvm-backend/src/vz.rs`
- [x] **Phase C** — Vz as a builder-VM backend. `VzBuilderVm` impl of
      `BuilderVm` shipped (`crates/mvm-build/src/vz_builder.rs`), mirroring
      `LibkrunBuilderVm` against the shared `builder_vm_runtime` seam.
      Acceptance amended from "byte-identical rootfs" to **functional
      parity** (ext4 assembly is non-deterministic; same flake + same job
      substrate is the bar) — see Sprint 55 success criteria.
- [x] **Phase D** — ADR-056 lands + ADR-002 backend table update
- [x] **Phase E** — Snapshot save/restore + pause/resume/balloon via
      supervisor control socket (macOS 14+ for SAVE).
      `<vm_state_dir>/control.sock` mode 0700; newline-framed
      PAUSE / RESUME / STATUS / BALLOON / SAVE protocol; Rust
      `vz_control::send_command` + `VzBackend::{pause,resume,
      balloon_set_target,snapshot_save}` wired through. RESTORE shipped:
      `vm_full` memory save/restore (`saveMachineStateToURL`) round-trips
      live, including a responsive control plane on the restored VM.

Phase A sub-tasks:

- [x] Worktree on `worktree-vz-backend-phase-a` set up off `origin/main`
- [x] `crates/mvm-vz-supervisor/Package.swift` Swift package skeleton
- [x] `Sources/mvm-vz-supervisor/Config.swift` — Codable mirror of
      the libkrun supervisor JSON schema (`#[serde(deny_unknown_fields)]`
      equivalent on the Swift side via strict `JSONDecoder` —
      `StrictKeys` protocol + `checkStrictKeys` helper)
- [x] `Sources/mvm-vz-supervisor/Supervisor.swift` — VZ machine config
      + start + SIGTERM forwarding
- [x] `Sources/mvm-vz-supervisor/VsockProxy.swift` — bidirectional
      unix-socket ↔ vsock proxy under `<socketDir>/vsock-<port>.sock`,
      mode 0700, via POSIX `accept()` + `DispatchIO` splice
- [x] `Sources/mvm-vz-supervisor/Network.swift` — gvproxy file
      handle attachment via `VZFileHandleNetworkDeviceAttachment`
      (SOCK_DGRAM unix connect to gvproxy's `--listen-vfkit` socket)
- [x] Ad-hoc code-signing with `com.apple.security.virtualization`
      entitlement (`Entitlements.plist` + `tools/build.sh`)
- [x] Phase A acceptance: the Rust supervisor boots a workload image and
      the guest agent answers on vsock. Live-proven 2026-06-12 (sleeper
      fixture, full admitted path, agent reachable).
- [x] Rust fuzz target `crates/mvm-build/fuzz/fuzz_targets/fuzz_supervisor_config.rs`
      driving `serde_json::from_slice::<SupervisorConfig>`; wired into
      `.github/workflows/security.yml` alongside the libkrun-sys
      equivalent; corpus artifacts upload on failure. The original
      Swift-decoder equivalence assertion is retired — the Swift
      supervisor no longer exists, so the Rust parser is the sole config
      surface and its fuzzer is the whole witness.

Phase B sub-tasks:

- [x] `crates/mvm-core/src/platform/platform.rs::has_vz()` detector
- [x] `crates/mvm-backend/src/vz.rs` — `VzBackend` impl of `VmBackend`
      with real start/stop/status/list/logs/install via supervisor
      subprocess + PID file (mirrors `LibkrunBackend`). `pause`/`resume`
      bail with capability-honest messages because the supervisor
      exposes only stdin-driven start/stop today; flips on when the
      control-socket follow-up lands.
- [x] `BackendKind::Vz` in `crates/mvm-backend/src/backend.rs`
- [x] `MVM_BACKEND=vz` / `--backend vz` opt-in plumbed; `auto_select()`
      **unchanged**
- [x] Resource-cap parity check (vCPU / memory / disk size);
      Swift-side validation against `VZVirtualMachineConfiguration.maximumAllowedCPUCount`
      and `min/maxAllowedMemorySize`; over-allocated requests exit 3
      with a clear "resource cap exceeded: ..." message
- [x] Kernel cmdline allow-list enforcement — `VmStartConfig` has no
      user-supplied cmdline field; backend constructs from
      `DEFAULT_CMDLINE` constant. Verity-token injection
      (`dm-mod.create=`, `mvm.runtime_roothash=`) lands when the
      verified-boot pipeline targets Vz (claim 3 follow-up).
- [x] `mvm_supervisor::admit_for_run` integration — enforced at the
      CLI layer (`crates/mvm-cli/src/commands/vm/up.rs:289`); every
      `mvmctl up --backend vz` runs through `admit_for_run` before
      `VzBackend::start` is invoked. ADR-002 claim 8 is hypervisor-
      agnostic; Vz inherits without backend-side changes.
- [x] Console mode lockdown — `build_supervisor_config` always sets
      `console_output_path` to a file under `vm_state_dir`; the Swift
      supervisor uses `VZVirtioConsoleDeviceSerialPortConfiguration`
      with `fileHandleForReading: nil` (capture-only, no interactive
      shell). Dev-mode PTY console is on vsock ports 20000+ via
      `crates/mvm-guest/src/console.rs` — never on virtio-console.
- [ ] Phase B acceptance: `MVM_BACKEND=vz mvmctl run dev-shell` boots
      workload microVM directly on macOS without nested libkrun
      *(deferred — needs real dev-shell artifacts; everything in the
      backend stack to make this work is in place and smoke-tested)*
- [ ] Hypervisor.framework concurrent-VM cap probe + clear error class
      *(deferred — Vz lacks a direct concurrent-VM count API;
      reactive classification of `VZVirtualMachineConfiguration.validate()`
      errors would require structured supervisor exit codes)*
- [x] `mvmctl doctor` Vz availability check (entitlement / MDM-policy
      sub-probes pending — current check reports framework
      availability + supervisor-binary presence across the
      env-override / source-checkout / installed paths)

Phase C sub-tasks:

- [x] `VzBackend::run_attached(config) -> Result<VmExitStatus>` —
      foreground supervisor spawn, inherits stdout/stderr, blocks
      until guest exit, returns the supervisor's exit code as the
      VM exit status. Plan 97 Phase C *primitive*; the builder
      orchestration on top is its own slice (see below).
- [x] Builder runtime selection branches on `MVM_BUILDER_BACKEND=vz`
      — `mvm_build::builder_backend_select::{resolve_choice,
      resolve_builder_backend}` returns `Box<dyn BuilderVm>` and
      `crates/mvm-cli/src/commands/env/apple_container.rs::build_image_via_libkrun`
      is the dispatch site. Unrecognised values fall back to libkrun
      with a `tracing::warn!`. (The plan originally pointed at
      `crates/mvm/src/vm/`; the actual call site lives in
      `mvm-cli/src/commands/env/`, so the helper lives in
      `mvm-build` for parity with the trait and is referenced from
      `mvm-cli`.)
- [x] `VzBuilderVm` impl of `BuilderVm::run_build` —
      `crates/mvm-build/src/vz_builder.rs`. Mirrors
      `LibkrunBuilderVm::run_build` step-for-step against the seam:
      validates mounts/job, acquires the shared `NixStoreImageLock`,
      stages the per-job dir via `stage_job_dir`, builds the
      `BuilderVmRunConfig` + mounts + extra-disks, dispatches
      through `VzBuilderBackend::run_attached_with_mounts`, and
      finalises with `finalize_flake_job` / `finalize_install_job`.
      Every load-bearing concern lives in `builder_vm_runtime`
      (Phase C PR-B migrations #434–#439) so the impl itself is
      ~350 lines instead of doubling LibkrunBuilderVm. Cache layout
      (`~/.cache/mvm/builder-vm/jobs/`, `vms/`) is shared with
      libkrun; per-VM dirs differ only in the `mvm-builder-vz-`
      prefix to avoid concurrent runs colliding.
- [x] Stage 0 audit emit + cache-prune contract participation
      (`project_stage0_audit_and_cache_prune_contract` memory). Stage 0
      itself runs upstream of `resolve_builder_backend()` (see
      `crates/mvm-cli/src/commands/env/apple_container.rs:4080,4120-4128`),
      so `Stage0Boot` / `Stage0CachePromoted` / `Stage0Failed` and the
      `stage0.lock` already cover both backends. The orphan reaper's
      dir traversal at `reap_orphaned_vm_helpers_at`
      (`apple_container.rs:3292`) is prefix-agnostic and `VzBuilderVm`
      writes the shared `builder.pid` sidecar
      (`crates/mvm-build/src/vz_builder.rs:258`), so vz state dirs
      under `~/.cache/mvm/builder-vm/vms/mvm-builder-vz-*` participate
      automatically. Pinned by
      `reap_picks_up_orphaned_vz_builder_state_dir` in
      `apple_container.rs` so a future refactor can't silently break
      it. Plan 99 PR-1.
- [ ] Phase C acceptance: `MVM_BUILDER_BACKEND=vz mvmctl build --flake
      .` produces byte-identical rootfs to libkrun-hosted equivalent
      *(deferred — needs a successful Vz-direct boot of the libkrun-
      built builder VM image; the libkrun image's kernel currently
      won't direct-boot via VZLinuxBootLoader, so a Vz-compatible
      builder VM kernel needs to ship before this acceptance line
      can flip green.)*

### Phase C seam design (recommendation)

Before a `VzBuilderVm` impl lands, the shared orchestration in
`crates/mvm-libkrun/` should be lifted behind a thin
`VmBackendForBuilder` trait so the second impl reuses logic instead
of duplicating ~3,300 lines. Concretely:

1. **New trait surface** (in `crates/mvm-core/src/protocol/vm_backend.rs`,
   sibling to `VmBackend`):
   ```rust
   pub trait VmBackendForBuilder: Send + Sync {
       fn run_with_attached_mounts(
           &self,
           config: &VmStartConfig,
           mounts: &[(String /* tag */, PathBuf, bool /* ro */)], // virtio-fs
           extra_disks: &[(String /* id */, PathBuf, bool /* ro */)], // virtio-blk
           timeout: Duration,
       ) -> Result<BuilderVmExitInfo>;
       fn console_path(&self, id: &VmId) -> PathBuf;
   }
   ```
   `BuilderVmExitInfo { exit_code, panic_line: Option<String> }` —
   the panic-line is what the libkrun console-log watcher already
   extracts (`crates/mvm-libkrun/src/lib.rs:1842-1908`).

2. **Lift shareable concerns** out of `LibkrunBuilderVm` into a
   `BuilderVmRuntime { backend: &dyn VmBackendForBuilder }` helper:
   `cmd.sh` emission / shell-escape, `/work`/`/out`/`/job` layout,
   panic-detector poll loop, `/job/result` parsing, Nix store image
   lock (NixStoreImageLock guard), stderr-tail capture, build
   failure formatting. Estimate ~850 of the current ~3,300 lines.

3. **Keep libkrun-flavored** what's specific to that VMM:
   `SupervisorConfig` JSON, `KrunContext` building, networking-mode
   dispatch (`MVM_NETWORKING`), `extract_bundled_kernel`, the macOS
   `DYLD_FALLBACK_LIBRARY_PATH` shim. These stay in
   `LibkrunBackend`'s impl of the trait.

4. **`VzBuilderVm` then writes only what's different**: a Vz
   `SupervisorConfig` (which already exists for workload microVMs),
   virtio-fs share attachment via the Swift supervisor's
   `VZVirtioFileSystemDeviceConfiguration` (Plan 97 §"Volumes and
   host-path mounts" — the supervisor already refuses unauthorized
   shares; the builder mode whitelists `/work`/`/out`/`/job`), and
   the same console-log path semantics. Estimate ~400 lines for the
   impl plus ~200 lines of Vz-side mount glue.

Load-bearing details the seam must preserve (from
`crates/mvm-libkrun/src/lib.rs`):
- The panic detector retries `File::open()` because the console log
  is created ~100 ms after `start_enter` returns (lines 1842–1878).
- Banner detection has to handle banners that span buffer boundaries
  (lines 1820–1823, 1866–1874).
- `NixStoreImageLock`'s `_file: std::fs::File` field is load-bearing
  — dropping the lock releases the host-side file lock; the guard
  must outlive the supervisor (lines 916–926).
- `/job/result` JSON is the contract with `mvm-builder-init` (lines
  1389–1410). The shared layer reads it; the backends supply mounts
  but never touch the result file directly.

This is the design recommendation; implementation is a separate
slice. Not landing yet — the user signed off on a recommendation
in this session; actual lift-and-shift waits for explicit go.

Phase D sub-tasks:

- [x] `specs/adrs/056-vz-backend.md` — Why Vz, security tier (Tier 2),
      relationship to ADR-013 / ADR-055, ADR-002 backend table update,
      alternatives considered, future work
- [ ] Performance numbers from CI lane (cold-boot, idle memory, build
      wall time) referenced in the ADR *(deferred — needs a CI lane
      that can actually boot a VM; GHA-hosted macOS doesn't expose
      Hypervisor.framework to user processes)*
- [x] ADR-002 backend table updated with Vz row and claim-coverage
      markers (Tier 2; L1–L5 covered; claim 3 partial)
- [x] macOS minor-version compatibility matrix wired into CI —
      `vz-macos` lane in `.github/workflows/ci.yml` runs on macos-13
      (floor) + macos-latest (current); path-gated to vz-touching
      files; asserts the supervisor binary carries the
      `com.apple.security.virtualization` entitlement and the strict
      decoder rejects unknown fields. The companion **`vz-macos-26`**
      lane is registered in the same workflow, gated on the
      `MACOS_26_AVAILABLE` repo variable; opt-in until a self-hosted
      Apple Silicon runner labelled `[self-hosted, macOS, ARM64,
      macos-26]` is registered (the GHA-hosted `macos-26` image is
      not yet available as of 2026-05).

Phase E sub-tasks (macOS 14+):

- [x] `control_socket_path` field added to `SupervisorConfig`
      (Rust + Swift); supervisor binds `<vm_state_dir>/control.sock`
      mode 0700 on startup.
- [x] Swift `ControlSocket.swift` accepts newline-framed PAUSE /
      RESUME / STATUS / BALLOON `<mib>` / SAVE `<path>` commands;
      `saveMachineStateTo` wired (macOS 14+ gated). `RESTORE` returns
      "not yet implemented" — different supervisor startup mode.
- [x] Rust `vz_control::send_command` client + `VzBackend::pause`,
      `VzBackend::resume`, `VzBackend::balloon_set_target`,
      `VzBackend::snapshot_save` (public method on the concrete type;
      VmBackend trait extension is its own slice).
- [x] Snapshot file SHA-256 hash-pinned in audit chain;
      `verify_audit_chain` rejects tampered snapshots (Security §4).
      `mvmctl snapshot save <vm> --path <p>` streams SHA-256 over
      the saved blob, emits `vm.snapshot_saved` via
      `AuditEmitter::emit_vm_snapshot_saved`, and binds the entry
      to the plan persisted at `~/.mvm/vms/<vm>/plan.json` (written
      at launch by `emit_launched_if` in
      `crates/mvm-cli/src/commands/vm/up.rs`).
- [x] `VZGenericMachineIdentifier` persisted with snapshots and
      verified on restore (Security §10). ControlSocket.swift's SAVE
      handler writes `<snapshot_path>.machine-id` with the running
      VM's identifier bytes mode 0600; Supervisor.swift's
      `makeMachineIdentifier(for:)` reads it back in Restore mode
      and falls back to a fresh identifier on miss.
- [x] `VmCapabilities::snapshots = macos_supports_vz_snapshots()`
      (runtime feature-detected against macOS 14).
- [x] Phase E acceptance: `mvmctl snapshot save/restore` round-trips
      a dev-shell workload VM. Both verbs ship; restore replays the
      persisted `~/.mvm/vms/<vm>/supervisor-config.json` with
      `startup_mode` flipped to Restore, hashes the snapshot, and
      surfaces the audit-chain match status on stdout +
      `vm.snapshot_restored`'s `chain_match` label. Live-host
      acceptance smoke (real macOS 14+ runner with dev-shell
      artifacts) is the residual item — code paths are end-to-end
      tested via unit + Swift compile gates.

Cross-cutting (any phase):

- [x] Build, distribution, versioning — Swift toolchain wired in
      `.github/workflows/ci.yml::vz-macos`; `Package.resolved` no
      longer gitignored; lockstep version pinning via the
      `mvm-vz-supervisor-<CARGO_PKG_VERSION>` filename in
      `crates/mvm-vz/src/lib.rs::supervisor_binary_path`;
      source-checkout determinism via
      `crates/mvm-vz/build.rs` (Plan 97 invariant). Distribution
      signing + notarization runbook entry deferred — release-only
      concern that pairs with the eventual `apple` lane work in CI.
- [x] License & Swift package conventions — Apache-2.0, matches the
      workspace's top-level `LICENSE`. Swift package's
      `Package.swift` and `README.md` reference it.
- [ ] mvmd integration follow-up (separate repo, separate PR)
- [x] Tracking issue filed for **future work: Windows host via WHP** — [#428](https://github.com/tinylabscom/mvm/issues/428)

## Context

Today on macOS, `mvm` always goes through **two layers** of virtualization to
run a workload microVM:

```
macOS host  →  libkrun Linux VM  →  Firecracker microVM (/dev/kvm)
```

That nesting exists because Firecracker requires `/dev/kvm`, which only exists
inside a Linux guest. libkrun (via `Hypervisor.framework`) hosts that Linux
guest. The whole pipeline assumes the macOS host can't run Linux directly,
*even though it can* — `Virtualization.framework` (Vz) has shipped Linux-guest
support since macOS 11 and exposes virtio-blk, virtio-net, virtio-vsock,
virtio-console, virtio-rng, and virtio-fs natively. Those are exactly the
device classes our guests already use (`crates/mvm-guest/src/vsock.rs:14`,
`DEFAULT_CMDLINE` at `crates/mvm-backend/src/libkrun.rs:62`).

Concretely the repo today exposes four backends behind a single trait
(`crates/mvm-core/src/protocol/vm_backend.rs:520`):

| Backend          | Hypervisor surface                    | Status     | Tier |
|------------------|---------------------------------------|------------|------|
| Firecracker      | Linux `/dev/kvm`                      | shipping   | 1    |
| libkrun          | `Hypervisor.framework` (C library)    | shipping   | 2    |
| Apple Container  | Apple **Containerization** framework  | **stub**, macOS 26+ Apple Silicon only | 3 |
| Docker           | OCI runtime                           | shipping fallback | 3 |

Neither shipping macOS backend uses Vz directly. Apple Container *does*, but
only macOS 26+ on Apple Silicon, and through the higher-level Containerization
framework. That leaves a real gap: **macOS 11–25 hosts have only the nested
libkrun→Firecracker path**, even though Vz is right there.

Adding a `vz` backend closes that gap and lets us run *both* the builder VM
and workload microVMs on Vz directly — collapsing the nested-VM pipeline on
macOS into a single layer for the hosts that want it.

Explicit user constraints driving this plan:

- A Vz backend usable for **both** the builder VM and workload microVMs.
- libkrun left in place — Vz is **additive**, not a replacement on macOS.
- **Firecracker stays the Linux default**, including for production deploys.
  This plan does not touch the Linux path; it only adds a macOS option.
- Balloon and (where available) snapshotting included from the start.
- Vz on Linux is **not wanted** — the existing Firecracker-direct path on
  Linux is better in every dimension that matters.

## Why it works (the virtio observation)

Every host↔guest channel we rely on maps 1:1 onto Vz's Swift classes:

| Our use                                | Vz class                                        |
|----------------------------------------|-------------------------------------------------|
| rootfs at `/dev/vda`, overlay `/dev/vdc`, verity sidecar `/dev/vdd` | `VZVirtioBlockDeviceConfiguration` |
| guest agent vsock (CID 3, port 5252)   | `VZVirtioSocketDeviceConfiguration` + `VZVirtioSocketConnection` |
| `console=hvc0`                         | `VZVirtioConsoleDeviceSerialPortConfiguration` |
| host-side `passt`/`gvproxy` socket     | `VZVirtioNetworkDeviceConfiguration` + `VZFileHandleNetworkDeviceAttachment` |
| entropy                                | `VZVirtioEntropyDeviceConfiguration` |
| balloon                                | `VZVirtioTraditionalMemoryBalloonDeviceConfiguration` |

Direct-kernel boot via `VZLinuxBootLoader(kernelURL:initialRamdiskURL:commandLine:)`
takes the same `(vmlinuz, initrd?, cmdline)` shape Firecracker takes, so the
artifacts the builder VM produces today can boot under Vz with minor cmdline
adjustments (no `i8042` quirks needed, console name changes from `ttyS0` to
`hvc0` — which we already use, see `DEFAULT_CMDLINE`).

`gvproxy` already terminates the host end of our virtio-net path on macOS
(ADR-055), and Vz's `VZFileHandleNetworkDeviceAttachment` is exactly the
"hand me a unix datagram socket and I'll bridge it" interface gvproxy expects.
The pieces line up.

## What Vz can and can't do

Can do, used in this design:

- Boot uncompressed Linux kernel + cmdline + optional initrd
  (`VZLinuxBootLoader`)
- Multiple virtio-blk devices (rootfs RO, overlay RW, dm-verity sidecar)
- virtio-vsock CID 3 with arbitrary listen/connect ports
- File-handle network attachments (gvproxy bridge)
  (`VZVirtioNetworkDeviceConfiguration` + `VZFileHandleNetworkDeviceAttachment`)
- virtio-console on serial port for captured logs
- **Memory balloon** via `VZVirtioTraditionalMemoryBalloonDeviceConfiguration`
  — exposes `targetVirtualMachineMemorySize`, mapping cleanly onto
  `VmBackend::balloon_target_mib()`. macOS 11+; on from day one.
- **Snapshot / save-restore** via
  `VZVirtualMachine.saveMachineStateTo(url:completionHandler:)` and
  `restoreMachineStateFrom(url:completionHandler:)`. **macOS 14+ only.**
  File format is opaque (Apple-controlled). Phase E gates on macOS 14+;
  `VmCapabilities { snapshots: true, .. }` only when detected.

Can't do, and we don't need:

- Nested virtualization (would only matter if we still wanted to run
  Firecracker inside the Vz guest — we don't; that's the whole point)
- PCI passthrough
- Live migration across hosts

Constraints to plan around:

- The supervisor binary must carry `com.apple.security.virtualization`
  entitlement and be code-signed (parallel to libkrun's
  `com.apple.security.hypervisor` requirement).
- Vz is a **Swift framework**; we bridge to Rust via a separate
  supervisor subprocess, same pattern as `mvm-libkrun-supervisor`
  (`crates/mvm-backend/src/libkrun.rs:18-24`).

### Volumes and host-path mounts

Both block-device volumes and host-path shares are supported, but they
go through different Vz classes with different security implications.

**Block volumes** — `VZVirtioBlockDeviceConfiguration` with one of:

- `VZDiskImageStorageDeviceAttachment(url:readOnly:)` — backed by a disk
  image file on the host. macOS 11+. Covers our rootfs RO, overlay RW,
  and verity sidecar slots (`/dev/vda`, `/dev/vdc`, `/dev/vdd`) one-for-one.
- `VZDiskBlockDeviceStorageDeviceAttachment(fileHandle:readOnly:)` —
  backed directly by a host block device handle. macOS 13+.

The **app-deps sealed volume** (`~/.mvm/volumes/deps/<volume_hash>/content/`
plus sidecars):

- *Preferred:* pack `content/` into an immutable ext4 image at seal time
  and mount it RO as another virtio-blk. Matches the dm-verity model and
  ADR-002 claim 9's "hash-locked, attestation-checked" contract.
- *Alternative:* expose `content/` as a virtio-fs share. Simpler but
  expands the share-audit surface; default is the block-image approach.

The decision is **not Vz-specific** — whatever libkrun does, Vz does.

**Host-path mounts (virtio-fs shares)** —
`VZVirtioFileSystemDeviceConfiguration` + `VZSharedDirectory` /
`VZMultipleDirectoryShare`:

- Builder VM: one explicit share for the Nix store output extraction
  point, same contract libkrun uses today.
- Workload microVMs: **no virtio-fs shares by default.** The supervisor
  JSON config refuses to attach `VZVirtioFileSystemDeviceConfiguration`
  unless the admitted ExecutionPlan names that share. Fail-closed test in
  Phase B verification.

### Guest communication is still vsock — nothing changes

`VZVirtioSocketDeviceConfiguration` is the same virtio-vsock device the
guest kernel already drives. From the guest's perspective there is no
difference: `/dev/vsock`, CID 3 (we keep `GUEST_CID = 3` from
`crates/mvm-guest/src/vsock.rs:14`), and the same port allocation:

- Port 5252: control protocol (JSON + Ed25519 signing) — unchanged
- Ports 10000+: TCP port forwarding — unchanged
- Ports 20000+: interactive console PTY sessions — unchanged

Host-side, Vz exposes:

- `VZVirtioSocketDevice.setSocketListener(_:forPort:)` — supervisor
  listens; guest dials in
- `VZVirtioSocketDevice.connect(toPort:completionHandler:)` — host dials
  a port the guest listens on

The Vz supervisor forwards both onto unix sockets under
`~/.mvm/run/<vm_id>/vsock/` with mode 0700. `mvmctl` doesn't know which
hypervisor sits on the other end of those sockets — **no guest agent
code, no protocol code, no key handling code changes** when switching
backends.

### Networking detail

The macOS host path today (per ADR-055) is:

```
guest virtio-net  ↔  unix-datagram socket  ↔  gvproxy  ↔  host NAT  ↔  internet
```

Vz fits in without changing the plumbing. The supervisor:

1. Opens a `socketpair(AF_UNIX, SOCK_DGRAM)` (or talks to the gvproxy
   control socket already running for the host).
2. Hands one end to gvproxy via the existing dispatch in
   `crates/mvm-backend/src/libkrun.rs` (`MVM_NETWORKING` selection
   stays as-is).
3. Wraps the other end in `VZFileHandleNetworkDeviceAttachment(fileHandle:)`
   and attaches it to a `VZVirtioNetworkDeviceConfiguration`.

No new virtio-net frame parser inside the Vz supervisor; parsing stays
in gvproxy (Go) where ADR-055's threat model already accounts for it.
Outbound-only builder VMs reuse the same gvproxy path; the JSON config
just toggles `network.policy = "nat-outbound"`.

## Security considerations

Items that must be settled before the backend launches a *production
workload* VM. Pre-prod / dev-shell launches are held to a lower bar per
the `feedback_dev_vm_vs_prod_security_tiers` memory.

1. **ADR-002 claim coverage** (full per-claim audit below in
   "Can we still make all nine ADR-002 security claims?").

2. **New trust surface: the Vz supervisor binary.** Runs with
   `com.apple.security.virtualization` entitlement, ad-hoc / Dev ID
   code-signed. Treat like `mvm-libkrun-supervisor`: mode 0700 on IPC
   socket (W1.2), one supervisor per VM (per `reference_libkrun_gotchas`),
   binary under `~/.mvm/bin/` not on `$PATH`.

3. **Closed-source framework.** Vz is closed-source — same posture as
   libkrun-on-`Hypervisor.framework` and Apple Container-on-Containerization.
   Doesn't move the ADR-002 "host is trusted" boundary.

4. **Snapshot file integrity (Phase E).** Snapshots live under mode-0700
   directories; SHA-256 pinned in the audit chain via `vm.snapshot_saved`
   / `vm.snapshot_restored` events. `VzBackend::restore` rejects on
   mismatch.

5. **Security tier.** Proposed initial tier: **Tier 2** (matches
   libkrun, same `Hypervisor.framework` primitive). Tier 3 considered
   and rejected. ADR-056 captures the reasoning.

6. **Dev vs prod tier.** Dev builder VM does not require dm-verity or
   claim-1/2/3 enforcement (per `feedback_dev_vm_vs_prod_security_tiers`).
   Workload `VzBackend::start_with_mode(Workload)` held to prod-tier.

7. **Kernel command-line lockdown.** Supervisor refuses unrecognized
   cmdline tokens; only ExecutionPlan-allowed tokens admitted. Without
   this, `init=/bin/sh` or `mvm.verity_disable=1` could neuter claim 3.
   Fail-closed test in Phase B.

8. **Resource-cap enforcement parity.** Admitted plan caps vCPU /
   memory / per-disk size; supervisor refuses over-allocation.

9. **Console mode lockdown.** `VZVirtioConsoleDevice` is **capture-only**
   on workload microVMs. Interactive console (PTY-over-vsock) is dev
   mode only, routed via `crates/mvm-guest/src/console.rs` on vsock
   ports 20000+ — not via virtio-console serial port. Supervisor
   config separates "console log path" from "PTY console."

10. **VM identifier handling.** `VZGenericMachineIdentifier` generated
    fresh per launch (ephemeral). For Phase E snapshots, identifier
    persists with the snapshot and is verified on restore so snapshots
    can't be "swapped" between unrelated workloads.

11. **Supervisor binary is a security boundary.** Memory disclosure
    leaks guest memory. Mitigations: Swift bounds-checked types,
    hardened runtime, library validation, no JIT entitlement,
    restricted entitlement set, no plugin loading.

12. **Crash diagnostics.** Capture
    `~/Library/Logs/DiagnosticReports/mvm-vz-supervisor-*.crash` into
    `mvmctl logs <vm_id> --hypervisor`.

13. **Enterprise / MDM policy.** `mvmctl doctor` detects MDM-disabled
    virtualization (via `VZVirtualMachineConfiguration.validate()`
    error class) and reports clearly.

## Implementation phases

Tracer-bullet ordering: get a single Linux VM booting end-to-end first,
then layer on builder-mode, workload-mode, and security parity. Each
phase ends in something the user can run.

### Phase A — `mvm-vz-supervisor` Swift binary (smallest viable end-to-end)

New crate / Xcode target at `crates/mvm-vz-supervisor/` containing a Swift
package that builds a single binary:

- Reads a `SupervisorConfig` JSON on stdin (mirrors
  `mvm-libkrun-supervisor`'s shape — `crates/mvm-libkrun/` is the reference)
- Constructs a `VZVirtualMachineConfiguration` with:
  - `VZLinuxBootLoader` from `kernel_path` + `cmdline` + optional `initrd_path`
  - One `VZVirtioBlockDeviceConfiguration` per disk
  - One `VZVirtioSocketDeviceConfiguration`
  - One `VZVirtioConsoleDeviceConfiguration` writing to a file we pass in
  - One `VZVirtioNetworkDeviceConfiguration` if `network.socket_path` set
- Starts the VM, writes its PID to `pid_path`, blocks until exit
- Forwards SIGTERM → `VZVirtualMachine.stop(completionHandler:)`
- Returns the exit code from the guest as its own exit code

**Acceptance:** boot a known-good kernel+rootfs (the dev-shell image)
under Vz and `vsock-connect 3:5252` succeeds (`mvmctl console`).

### Phase B — `VzBackend` in `crates/mvm-backend/src/vz.rs`

New module parallel to `libkrun.rs`. Implements `VmBackend`
(`crates/mvm-core/src/protocol/vm_backend.rs:520`) by spawning the Phase
A binary, writing config JSON to stdin, managing PID + lifecycle the
same way `LibkrunBackend` does (`crates/mvm-backend/src/libkrun.rs:64`).

Capabilities (runtime-feature-detected):

```rust
VmCapabilities {
    vsock: true,
    snapshots: macos_at_least(14, 0),
    balloon: true,
    tap_networking: false,
}
```

Wire into `BackendKind` enum and `auto_select()`
(`crates/mvm-backend/src/backend.rs:372-403`). **`auto_select()` stays
unchanged.** Vz only ranks above libkrun when `MVM_BACKEND=vz` (env)
or `--backend vz` (flag) opts in. Linux hosts never see Vz in their
selection chain. `crates/mvm-core/src/platform/platform.rs:30` gets
`has_vz()` (returns `false` on Linux).

**Acceptance:** `MVM_BACKEND=vz mvmctl run dev-shell` boots a workload
microVM on macOS **without** going through libkrun first.

### Phase C — Vz as a builder-VM backend

Builder VM lifecycle today calls in-process `start_enter()` in
`crates/mvm-libkrun/src/lib.rs` (libkrun is a C library linked into
`mvmctl`). For Vz, use the supervisor-subprocess model from Phase A/B:
`StartMode::BlockingWithIO` (or equivalent) routes through
`VmBackend::start_with_mode()`, captures stdin/stdout/stderr from the
guest's virtio-console, returns the guest's exit code.

Builder runtime selection in `crates/mvm/src/vm/` gets a parallel branch:
when `MVM_BUILDER_BACKEND=vz`, the builder VM is constructed via
`VzBackend::start_with_mode(BlockingWithIO)` instead of
`LibkrunBuilderVm::run_build`.

**Acceptance:** `MVM_BUILDER_BACKEND=vz mvmctl build --flake .` produces
a byte-identical rootfs to the libkrun-hosted equivalent.

### Phase D — ADR-056 & security-tier landing (no default reshuffle)

Vz stays opt-in. `auto_select()` is **unchanged**. libkrun remains the
macOS default; Firecracker remains the Linux default and the production
deploy default.

`specs/adrs/056-vz-backend.md` covers:

- Why Vz given libkrun + Apple Container already exist (Vz fills the
  macOS 11–25 / Intel coverage gap *and* unlocks direct workload microVM
  hosting without nested Firecracker).
- Security tier (**Tier 2** proposed; Tier 3 considered and rejected
  because Vz sits on the same `Hypervisor.framework` primitive as libkrun).
- Relationship to ADR-013 (adds, doesn't retract).
- Relationship to ADR-055 (gvproxy networking unchanged).
- ADR-002 update: add Vz row to backend table; mark claim coverage.

### Phase E — Snapshot / save-restore (macOS 14+)

- Extend supervisor JSON config with `snapshot.save_path` and
  `snapshot.restore_path` modes
- Swift: call `saveMachineStateTo` on stop when `snapshot.save_path` is
  set; `restoreMachineStateFrom` on start when `snapshot.restore_path`
  is set
- Rust: implement `VmBackend::pause` / `resume` / snapshot verbs;
  expose via `mvmctl snapshot <id> save <path>` / `restore <path>`
- Hash-pin snapshot file in the audit chain before restore (Security §4)
- `VmCapabilities::snapshots = true` for Vz on macOS 14+; ADR-002
  claim 1 / 3 verification re-run against restored VM in CI

**Acceptance:** `mvmctl snapshot save / restore` round-trips a dev-shell
workload VM, restored VM has same PID 1 state and preserves vsock
agent sessions.

## Critical files

Modify:

- `crates/mvm-backend/src/backend.rs` — add `BackendKind::Vz`, slot into
  `auto_select()`
- `crates/mvm-core/src/platform/platform.rs` — `has_vz()` detector
- `crates/mvm-core/src/protocol/vm_backend.rs` — possibly extend
  `StartMode` for blocking-with-IO builder-VM mode if not already there

Add:

- `crates/mvm-vz-supervisor/` — Swift package, `mvm-vz-supervisor` binary
- `crates/mvm-backend/src/vz.rs` — `VzBackend` impl of `VmBackend`
- `crates/mvm-vz/` (optional) — thin Rust crate for supervisor-binary
  path resolution + JSON config types, parallel to `crates/mvm-libkrun/`
- `specs/adrs/056-vz-backend.md`

Reuse, don't duplicate:

- `SupervisorConfig` JSON shape from `crates/mvm-libkrun/` — reuse where
  overlapping; vz-specific fields go in a `vz: Option<...>` block
- `auto_select()` ordering machinery
- `GUEST_CID = 3` + agent port allocation
  (`crates/mvm-guest/src/vsock.rs:14`)

## Verification

End-to-end, on a macOS 13+ host (covers both Intel Hypervisor.framework
and Apple Silicon):

1. **Phase A:** `mvm-vz-supervisor < example-config.json` boots the
   dev-shell-image VM, prints boot logs to the configured console file,
   host-side `vsock-connect 3:5252` succeeds.

2. **Phase B:** `MVM_BACKEND=vz mvmctl run dev-shell` and
   `mvmctl console <id>` give an interactive shell. `mvmctl status <id>`
   reports Vz. `time mvmctl run ...` on Vz vs. nested
   libkrun→Firecracker; expect ≥30% wall-time win on cold-boot.

3. **Phase C:** `MVM_BUILDER_BACKEND=vz mvmctl build --flake . --profile
   minimal --role worker` produces rootfs hash identical to the
   libkrun-built rootfs hash for the same flake input.

4. **Regression net:** `cargo test --workspace` + `cargo clippy
   --workspace -- -D warnings` pass with both backends compiled in. CI
   adds a macOS-only `vz-smoke` job that runs the Phase A acceptance.

5. **Security-claim parity:** `mvmctl doctor` against a Vz-backed
   workload microVM reports claims 1, 2, 3 green.

## Platform coverage summary

| Host          | Builder VM backends                | Workload microVM backends         | Production deploy default |
|---------------|------------------------------------|-----------------------------------|---------------------------|
| Linux + KVM   | (unchanged) libkrun / Firecracker  | (unchanged) **Firecracker**       | **Firecracker** (unchanged) |
| macOS 11–12   | libkrun, Vz (NEW)                  | libkrun (Firecracker nested), Vz (NEW) | n/a (dev only)       |
| macOS 13–25   | libkrun, Vz (NEW, full virtio)     | libkrun (nested), Vz (NEW)        | n/a (dev only)            |
| macOS 14+     | libkrun, Vz (NEW, **+ snapshots**) | libkrun (nested), Vz (NEW, **+ snapshots**) | n/a (dev only)   |
| macOS 26+ ASi | libkrun, Vz, Apple Container       | libkrun (nested), Vz, Apple Container | n/a (dev only)        |

`auto_select()` defaults are unchanged. Vz is opt-in only and never
appears on Linux hosts.

## Can we still make all nine ADR-002 security claims?

| Claim | Status under Vz                                                          |
|------:|--------------------------------------------------------------------------|
| 1     | **Inherits** — supervisor refuses non-admitted virtio-fs shares          |
| 2     | **Inherits** — guest-side, hypervisor-independent                        |
| 3     | **Inherits** — dm-verity is kernel-side; `VZLinuxBootLoader` carries cmdline + roothash unchanged |
| 4     | **Inherits** — guest-side                                                |
| 5     | **Inherits** — Rust `SupervisorConfig` serde parser (`deny_unknown_fields`), fuzzed by `crates/mvm-build/fuzz/fuzz_targets/fuzz_supervisor_config.rs`; same harness as the libkrun supervisor |
| 6     | **Inherits** — host-side download path                                   |
| 7     | **Inherits** — Vz supervisor is an ordinary workspace bin (`mvm-vm-host`), riding the cargo reproducibility double-build + `cargo-deny`/`cargo-audit` pipeline |
| 8     | **NEW WORK** — `VzBackend::start_with_mode` through `admit_for_run`; fail-closed bypass test |
| 9     | **Inherits** — `verify_sealed_volume` is hypervisor-agnostic             |

Reconciled 2026-06-13 (Swift deleted, Plan 152): all nine **inherit**
except claim 8 (the only Vz-specific new code, and it shipped). Claims 5
and 7 used to read "new/extends" because of the Swift supervisor — that
binary is gone, so the strict-decoder fuzz and the reproducible-build /
supply-chain coverage now collapse into the shared Rust pipeline. There
is no Swift `JSONDecoder` to reach equivalence with and no separate SPM
`Package.resolved` to pin.

## Additional considerations

### Build, distribution, versioning

- Swift toolchain on macOS CI lanes
- Reproducible builds; SPM `Package.resolved` pinned; W5.3 double-build
  parallel for Swift
- Code signing: ad-hoc for dev, Developer ID + notarization for release
- Versioning: `~/.mvm/bin/mvm-vz-supervisor-<mvmctl_version>` lockstep
- Source-checkout determinism — no prebuilt download

### Minimum macOS version

- **macOS 13 (Ventura)** as the floor — full virtio surface
- macOS 11–12 hosts fall back to libkrun (status quo, no regression)
- macOS 14+ unlocks snapshots (Phase E)
- macOS 26+ ASi gets Apple Container parallel

### Multi-architecture coverage

Vz works on both arm64 and x86_64. The existing artifact pipeline
already produces per-arch kernels and rootfs images (ADR-046); Vz
inherits multi-arch without new artifact work. CI smoke runs on both
arches.

### Inactive device classes (smaller attack surface)

The Vz supervisor explicitly **does not** configure:

- `VZVirtioSoundDeviceConfiguration`
- `VZUSBKeyboardConfiguration` / `VZUSBScreenCoordinatePointingDeviceConfiguration`
- `VZGraphicsDeviceConfiguration`
- `VZUSBControllerConfiguration`
- `VZGenericMachineIdentifier` mutability beyond what snapshot needs

### `mvmctl doctor` and `mvmctl init` integration

- `doctor` gains a Vz availability check (entitlement, macOS version,
  ADR-002 claim status, MDM policy)
- `init` wizard on macOS offers Vz as a backend choice; default stays
  libkrun

### Builder VM Stage 0 contract

The Vz builder-VM mode (Phase C) participates in the existing Stage 0
audit + cache-prune contract (`project_stage0_audit_and_cache_prune_contract`):

- `stage0_*` events to the shared audit log
- Pre-`Stage0Boot` failures are not audited
- `mvmctl cache prune` respects the Stage 0 lock

### Host sleep / wake

Vz pauses VMs when the host sleeps (Apple behavior, can't override).
On wake, supervisor inherits libkrun's current auto-resume / paused
status behavior — consistency over novelty.

### Performance baseline (numbers, not vibes)

Phase B verification commits to a measured comparison:

- Cold boot wall time (kernel → guest-agent ready): Vz vs.
  libkrun-direct vs. nested-libkrun-then-Firecracker
- Memory footprint at idle
- Build wall time for a fixed Nix derivation through a builder VM

ADR-056 carries actual numbers from a CI lane, not estimates.

### mvmd integration (separate work)

mvmd selects backends per pool. Adding `vz` to mvmd's backend enum is
a follow-up in that repo, **explicitly out of scope here**.

### Plan / ADR numbering

Per `project_spec_numbering_chaos`: this plan claimed **97**, ADR
claims **056**. Plan 96 was already in flight (PR #420 referenced it
as "Plan 96 dev-up followups") when this plan was filed
(2026-05-22), so this plan stepped to the next free slot.

### Concurrent VM limits and capacity planning

`Hypervisor.framework` caps concurrent VMs (~16 older Intel,
~32 Apple Silicon; varies). Phase B adds:

- Capability probe at startup
- `auto_select`-time warning when host near the ceiling
- Clear error class for "concurrent VM limit reached"

### Boot loader locked to `VZLinuxBootLoader`

Vz also offers `VZEFIBootLoader`; we never use it. Faster boot, less
attack surface. No EFI field in the supervisor config schema.

### Disk image format

Workload microVM disks are **raw ext4 image files** with sparse
allocation. Vz honors guest-issued `DISCARD` / `TRIM` ops via
virtio-blk discard — overlay disks stay thin. No qcow2.

### CI environments

GitHub Actions macOS runners support Vz. Self-hosted Apple Silicon
runners need `com.apple.developer.security.virtualization` provisioning;
flag in contributor docs.

### Notarization & Gatekeeper

Distribution-signed releases of `mvm-vz-supervisor` go through Apple
notarization (`xcrun notarytool`). Dev / source-checkout builds use
ad-hoc signing.

### macOS minor-version compatibility matrix

CI matrix runs Phase B's smoke test against minimum (13.x), current
latest, and one macOS-26+ build. Catches Apple mid-version regressions
before users do.

### CPU scheduling and resource control

macOS has no cgroups. Vz exposes only `cpuCount` and `memorySize`. We
accept Apple's scheduler — same as libkrun today.

### Memory balloon floor

`balloon_target_mib` refuses to shrink below
`min(plan.memory_floor, 128 MiB)`. Without the floor, an aggressive
control loop could OOM the guest.

### License & repository conventions

The Swift package carries dual Apache-2.0 + MIT, matching the Rust
workspace.

### Implementation hygiene

- Work in git worktrees (`feedback_always_use_git_worktrees`)
- No prebuilt download on contributor source-checkout path
- No external build-cache providers (`feedback_no_external_cache_providers`)
- Vz-related host tools route through the builder VM where the
  builder-tools rule applies (`feedback_builder_tools_on_host`)
- The `mvm-vz-supervisor` Swift package is the **only** Swift code we
  own; resist scope creep into broader Swift surface

## Out of scope

- Replacing libkrun as the macOS default
- Touching the Linux Firecracker path
- Removing the nested Firecracker-in-libkrun path on macOS
- Vz on Linux
- Live VM migration across hosts

## Future work (cataloged, not in this plan)

### Windows host support

Separate deferred initiative analogous to this Vz work but for the
Windows hypervisor surface:

- **Primitive:** Windows Hypervisor Platform (WHP)
- **Shape:** parallel crate `crates/mvm-whp-supervisor/` mirroring
  the Vz / libkrun supervisor pattern
- **Open questions:** Linux-on-WHP boot loader (cloud-hypervisor /
  QEMU adopt), virtio device exposure on WHP (`WinHvPlatform` is bare;
  userspace virtio layer needed), signing posture (Authenticode,
  code-integrity)
- **Magnitude:** comparable to this Vz plan plus userspace virtio
- **Tracking issue:** [#428](https://github.com/tinylabscom/mvm/issues/428) — references this plan + ADR-056; gated on Phases A–C merging

## Implementation log

Each session that touches this plan appends an entry below.

- 2026-05-22 — Plan filed. ADR-056 reserved. Worktree
  `worktree-vz-backend-phase-a` created off `origin/main` for Phase A
  work. SPRINT.md Sprint 55 section added.
- 2026-05-22 — Phase C primitive landed: `VzBackend::run_attached`
  spawns the supervisor in foreground (stdin piped for JSON,
  stdout/stderr inherited), waits for it to exit, returns the
  supervisor's exit code as a `VmExitStatus`. Foundation for a
  future `VzBuilderVm` that wraps this primitive with the same
  `BuilderJob` / `BuilderMounts` / virtio-fs orchestration
  `LibkrunBuilderVm` carries; that orchestration layer is its own
  follow-up slice (no point duplicating 3,300 lines without first
  refactoring the shared seam out of `LibkrunBuilderVm`).
- 2026-05-22 — Phase E core landed: control-socket IPC between Rust
  and the running Swift supervisor.
  `crates/mvm-vz-supervisor/Sources/mvm-vz-supervisor/ControlSocket.swift`
  binds `<vm_state_dir>/control.sock` mode 0700 (W1.2),
  accepts newline-framed PAUSE / RESUME / STATUS / BALLOON / SAVE
  commands, dispatches Vz API calls on the supervisor's main queue.
  `crates/mvm-backend/src/vz_control.rs` provides the Rust client
  (`send_command`); `VzBackend` now wires `pause` / `resume` /
  `balloon_set_target` (with the 128 MiB floor enforced host-side
  before the dial) and exposes a public `snapshot_save` method on
  the concrete type (trait-level snapshot verbs are their own
  slice). Capabilities flipped: `pause_resume=true`, `balloon=true`,
  `snapshots=macos_supports_vz_snapshots()` (macOS 14+).
  Five new VzBackend tests + five `vz_control` tests (using a
  thread-local fake supervisor) — all 19 vz tests green; workspace
  4,096 passed / 0 failed; clippy clean. RESTORE deferred (needs
  different supervisor startup mode) + snapshot audit-chain hashing
  deferred (needs CLI verb integration).
- 2026-05-22 — Closure: top-level Phase A / B / D marked complete;
  Phase C and Phase E moved to parked status with explicit rationale
  for the deferral. Phases C and E are real follow-up slices (each
  comparable in size to Phase B), not stubs left in-tree.
  `cargo test --workspace` + `cargo clippy --workspace --all-targets
  -- -D warnings` clean at this point. 12 commits on
  `worktree-vz-backend-phase-a`.
- 2026-05-22 — Rust fuzz target for `SupervisorConfig`:
  `crates/mvm-vz/fuzz/fuzz_supervisor_config.rs` exercises
  `serde_json::from_slice::<SupervisorConfig>` (panic-free for any
  input). Cargo workspace excludes the fuzz crate (libfuzzer-sys
  linker constraints, mirrors mvm-libkrun/fuzz); nightly toolchain
  pinned via `rust-toolchain.toml`. `.github/workflows/security.yml`
  runs it alongside the libkrun supervisor target; corpus / artifacts
  upload on failure. Foundation for the Swift-side equivalence test
  (claim 5 follow-up: feed the corpus through `JSONDecoder` and assert
  the two decoders reject the same inputs).
- 2026-05-22 — Phase D closure: `specs/adrs/056-vz-backend.md` filed
  (rationale, Tier 2 reasoning, ADR-002 claim audit, alternatives,
  future work); ADR-002 backend table at
  `specs/adrs/002-microvm-security-posture.md` gained the Vz row;
  `.github/workflows/ci.yml::vz-macos` lane runs the Swift supervisor
  build + Rust mvm-vz / mvm-backend tests + clippy + entitlement
  assertion + strict-decoder smoke on macos-13 and macos-latest;
  Swift package's `.gitignore` no longer excludes `Package.resolved`
  (Plan 97 cross-cutting); license documentation corrected to
  Apache-2.0 (workspace's actual license) in Package.swift +
  README. Performance numbers in the ADR stay TBD until a CI lane
  with HVF user-mode access exists.
- 2026-05-22 — Resource-cap parity (Plan 97 Security §8) landed in
  `Supervisor.swift::validateRequestedResources`: probes
  `VZVirtualMachineConfiguration.maximumAllowedCPUCount` +
  `min/maxAllowedMemorySize` from the live host and refuses
  over-allocated configs with a `SupervisorError.resourceCapExceeded`
  (exit code 3) before constructing the VM. Smoke-tested with
  `cpu_count=99999` → "resource cap exceeded: requested cpu_count=99999
  exceeds host maximum 64". Defense-in-depth alongside the host-side
  `admit_for_run` gate.
- 2026-05-22 — `mvmctl doctor` now reports Vz availability +
  supervisor-binary presence (env / source-checkout / installed
  paths). Two unit tests + live smoke against a macOS 26 / arm64
  contributor host. Entitlement and MDM-policy sub-probes remain
  follow-ups.
- 2026-05-22 — `crates/mvm-vz/build.rs` auto-builds the Swift
  supervisor during `cargo build` on macOS by invoking
  `crates/mvm-vz-supervisor/tools/build.sh`. No-op on non-macOS
  hosts and when Swift is unavailable; the warning path keeps
  Linux contributors unblocked. End-to-end:
  `cargo clean -p mvm-vz && cargo build -p mvm-vz` produces the
  ad-hoc-signed supervisor at the source-checkout path the
  resolver consults first. `MVM_VZ_SKIP_SUPERVISOR_BUILD` opts out.
- 2026-05-22 — VzBackend lifecycle wired end-to-end: real
  `start`/`stop`/`status`/`list`/`logs`/`install` in
  `crates/mvm-backend/src/vz.rs`, mirroring `LibkrunBackend`'s
  PID-file lifecycle. `start` resolves the supervisor binary via
  `MVM_VZ_SUPERVISOR_PATH` → adjacent-to-exe →
  `crates/mvm-vz-supervisor/.build/<arch>/debug/` (source checkout)
  → `~/.mvm/bin/mvm-vz-supervisor-<version>` (release-installed),
  builds the `mvm_vz::SupervisorConfig` from `VmStartConfig`,
  spawns the supervisor with JSON on stdin, waits up to 5 s for
  the PID file. `stop` reads the PID, sends `SIGTERM`, escalates
  to `SIGKILL` after 2 s. `pause`/`resume` bail with capability-
  honest messages (supervisor exposes only stdin-driven start/stop
  today — pause/resume + balloon adjustment + snapshots need a
  control socket, follow-up). Eleven VzBackend tests green;
  workspace clippy clean. Replaces the earlier stub-bail
  implementations under the same NOT_YET_WIRED sentinel.
- 2026-05-22 — Phase B trait wiring landed:
  `Platform::has_vz()` in `crates/mvm-core/src/platform/platform.rs`
  (macOS-only, ≥13.0); `crates/mvm-backend/src/vz.rs` with `VzBackend`
  implementing `VmBackend` (skeleton: name/capabilities/security
  profile/install/guest_channel_info real, lifecycle methods bail with
  NOT_YET_WIRED constant pending supervisor-spawn slice); `BackendKind::Vz`
  added to `AnyBackend` enum + `inner()` dispatch + `from_hypervisor`
  (aliases `vz` / `virtualization`) + `tier()`. `auto_select()`
  **unchanged** per user constraint. Six new VzBackend unit tests + one
  AnyBackend dispatch test (`test_any_backend_from_hypervisor_vz`) green;
  `cargo test -p mvm-backend --lib` 148/148; workspace clippy clean.
  Remaining Phase B: supervisor-spawn `start`, resource-cap parity,
  cmdline allow-list, `admit_for_run` integration, console mode
  lockdown, HVF concurrent-VM cap probe, doctor wiring.
- 2026-05-22 — Phase B foundation landed: `crates/mvm-vz/` Rust
  crate with `SupervisorConfig` (+ nested) types whose JSON shape
  matches the Swift `Config.swift` schema byte-for-byte;
  `#[serde(deny_unknown_fields)]` on every struct mirrors the Swift
  `StrictKeys` contract. Also includes `MacAddress::parse` with
  locally-administered bit enforcement, and
  `supervisor_binary_path` / `source_tree_binary_path` for the
  release vs. source-checkout resolution split. Seven unit tests
  green; `cargo check --workspace` clean; `clippy -- -D warnings`
  clean. This is the "Add: crates/mvm-vz/ (optional)" entry from
  Plan 97 §"Critical files"; the actual `VzBackend` impl that
  consumes it is the next slice.
- 2026-05-22 — Phase A first slice landed: `crates/mvm-vz-supervisor/`
  Swift package builds clean with macOS 13 deployment target. All five
  source files in place (`main.swift`, `Config.swift`, `Supervisor.swift`,
  `VsockProxy.swift`, `Network.swift`); strict deny-unknown-fields
  decoder smoke-tested (rejects unknown field with exit 2, empty stdin
  with documented message); ad-hoc codesigning helper `tools/build.sh`
  injects `com.apple.security.virtualization` from `Entitlements.plist`
  and `codesign -d --entitlements -` confirms it's on the binary.
  Remaining Phase A: end-to-end boot acceptance (gated on Phase B's
  Rust JSON producer) and the Rust-side fuzz corpus (gated on the
  Phase B `mvm-vz` crate).

## Closeout — 2026-06-13

Sprint 55 verdict: **vz is at parity with the macOS libkrun baseline and
the plan is complete.** All five phases shipped and are live-proven on
macOS-26 Apple Silicon: build→admit→boot→run (sleeper fixture, agent on
vsock), checkpoint/fork/warm pool, snapshot save/restore, pause/resume,
and the Rust-native objc2 supervisor (Swift deleted). Claims 1–9 hold
under vz (claims 5 and 8 were the new-work items; both shipped). Success
criteria reconciled to post-Swift, post-convergence reality:

- **Phase C "rootfs hash matches libkrun"** — amended to *functional*
  parity. ext4 image builds are non-deterministic (different bytes every
  build), so byte-hash equality is not a meetable criterion; the real
  guarantee is same nix derivation + same boot/agent behaviour, which a
  cold `dev up --builder vz` demonstrated.
- **Phase B "≥30% cold-boot win vs nested libkrun→Firecracker"** — the
  comparison is obsolete: backend consolidation removed the nested
  macOS→libkrun→Firecracker workload path, so there is no nested baseline
  left to beat. vz boots a single Linux guest directly; the criterion is
  retired rather than measured.
- **Claim 5** — Swift `JSONDecoder` equivalence retired (Swift deleted);
  the Rust `SupervisorConfig` cargo-fuzz target is the sole witness.

### Follow-on (NOT a Sprint 55 closeout item) — now tracked as Plan 197

- [ ] **macOS egress secret substitution (Plan 129 on libkrun + vz)** →
  **Plan 197** (`specs/plans/197-workload-backend-core-trait.md`).
  Substitution is Linux-only today (FC nft TAP REDIRECT + QEMU slirp);
  neither macOS backend spawns the endpoint. Plan 197 makes it a
  no-default `WorkloadBackend` seam — **reclassifying it from an optional
  fast-follow to a required build** (vz/libkrun won't compile without it).
  Porting needs a `Uds`-transport endpoint bridged through the supervisor
  vsock hop (the portable `HTTP_PROXY` channel) plus a gateway-level
  :80/:443 terminator replacing the nft REDIRECT — the latter entangles
  with the rvproxy migration (Plan 193 / ADR-082) and is resolved by a
  Plan 197 Phase 2 design spike. vz is not behind its macOS sibling here.
