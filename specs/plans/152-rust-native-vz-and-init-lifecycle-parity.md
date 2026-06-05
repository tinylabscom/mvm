# Plan 152 — Rust-native `Virtualization.framework` supervisor + guest `/init` lifecycle parity

> **Status (2026-06-04):** Findings recorded; not yet started. Sequenced
> **after the current artifact-model refactor and the core-demo bring-up
> land** — depends on Plan 120 (`core_demo_e2e` green) and Plan 134
> (architecture-aware artifact model). Do not start WS-A until the
> function-workload boot path is stable on `feat/artifact-model`, or the
> `/init` diff is measured against a moving target.
>
> **Numbering caveat:** picked 152 as next-after-highest from local
> `specs/plans/`. Reconcile against open PRs before merge — the
> `check-spec-numbers` Lint gate hard-fails on a duplicate integer prefix.
>
> **Direction change (2026-06-04):** a wider prior-art review (Findings →
> *External prior art*) **reverses** this plan's original "keep the Swift
> supervisor" decision. We now intend to **drop Swift** and reimplement
> the VZ supervisor in Rust against `objc2-virtualization`, kept as a
> **separate per-VM codesigned binary** so the entitled TCB stays tiny.
> The entitled-TCB invariant only ever argued for a *separate process*,
> never for Swift. The reviewed Rust-native projects are **inspiration
> only, never a dependency**. See *Decision* below; the migration is
> **WS-B**. Also adds **WS-D** (nested-virt `/dev/kvm`) and **WS-E**
> (VZ-config hardening). This plan is the **foundation**; the broader
> vz-inspired DX/feature build-out is **Plan 159**. External repos
> referred to obliquely per repo naming policy; an oblique-reference key
> lives in auto-memory (`reference_objc2_vz_external_references`).
>
> **Plan 141 reconciliation RESOLVED (2026-06-04 brainstorm) — this plan
> absorbs 141's Vz arm.** 141 keeps only its backend-agnostic
> `payload_tap` core (libkrun + Firecracker); **Vz `payload_tap` is
> delivered here** (WS-B). Because this plan makes Rust own the VZ device,
> the bridge runs **in-process** against the socketpair Rust attaches to
> `VZFileHandleNetworkDeviceAttachment` — no SCM_RIGHTS fd-handoff, no
> surviving Swift, no NDJSON ingest hop (the cleanest form of 141's "Rust
> owns the shuffle"). Decision record: ADR-064 §8. **Still open:** WS-D
> (nested-virt `/dev/kvm`) ↔ Plan 147's Lima carve-out.

## Context

Plan 97 gave us the `vz` backend by way of a **separate codesigned Swift
binary** (`crates/mvm-vz-supervisor/`, one supervisor process per VM,
mirroring `mvm-libkrun-supervisor`). That binary carries the
`com.apple.security.virtualization` entitlement; the Rust side
(`crates/mvm-backend/src/vz.rs`) hands it a `SupervisorConfig` JSON on
stdin and drives lifecycle over a newline-framed control socket
(`crates/mvm-backend/src/vz_control.rs`).

While scoping future Vz work we reviewed several open-source Rust microVM
projects in the same problem space (untrusted-agent execution on macOS).
The common thread: they drive `Virtualization.framework` **entirely from
Rust, with no Swift binary at all**, via the `objc2` ecosystem. Combined
with what already exists in our own tree, this is enough to commit to
dropping Swift — see the Decision.

A second, independent finding: their guest `/init` implements a clean
exit-code propagation contract that is a near-exact reference for the
lifecycle our function-workload path keeps failing (Plan 120 — the
workload `/init` reboots instead of powering off; see
`project_function_workload_entrypoint_collision`).

## Findings

The references drive VZ from Rust via the `objc2` ecosystem —
`objc2-virtualization`, `objc2-foundation`, `objc2-core-foundation`,
`block2`, `dispatch2`. No SwiftPM step; any C in-tree is a
`cbindgen`-generated FFI header for an embeddable `cdylib`/`staticlib`,
not an Objective-C shim.

- **Config & devices.** A `vz/`-style module builds
  `VZVirtualMachineConfiguration`, the Linux boot loader, virtio
  block/fs/net, the vsock socket device, CPU/memory, and a snapshot
  path — all in Rust against the objc2 bindings. One reference also
  builds the macOS-guest path (`VZMacOSBootLoader` + platform config).
- **Delegate.** A `declare_class!`-defined delegate implements
  `VZVirtualMachineDelegate`, installed via
  `ProtocolObject::from_ref(&delegate)` + `setDelegate`. Terminal
  events (`guestDidStop` / `stopWithError`), the timeout completion,
  and the start-failure completion all write a **write-once terminal
  slot**; a blocked `wait()` is woken via a condvar (or a tokio `watch`).
- **Completion handlers.** `block2::RcBlock`, e.g.
  `startWithCompletionHandler`; bridged to futures via `oneshot`.
- **Threading (the useful bit).** Each VM runs on its **own private
  serial dispatch queue**; libdispatch's worker pool services it —
  **no `CFRunLoop`/`dispatch_main` pumping needed, and VZ calls never
  touch the main thread**. Non-`Send` objc2 `Retained` handles cross
  threads through a `QueueBound<T>(Retained<T>)` wrapper with
  `unsafe impl Send`, only ever dereferenced inside closures dispatched
  back onto that queue. This **debunks the "VZ needs the main thread +
  NSRunLoop" assumption** and matches our Swift supervisor's existing
  dedicated-`DispatchQueue` design (`ControlSocket.swift`,
  `VsockProxy.swift` already serialize on one queue). Note our
  `apple_container` objc2 path currently dispatches `start_vm` onto
  `DispatchQueue::main()` (`providers/apple_container/macos.rs`) — the
  private-serial-queue model is the better pattern for the supervisor.
- **vsock bridge (the new-to-us bit).** On a `VZVirtioSocketListener`
  accept, take `connection.fileDescriptor()` → `libc::dup` →
  `O_NONBLOCK` → `tokio::io::unix::AsyncFd` for an async byte stream.
  This is the clean Rust replacement for `VsockProxy.swift`.
- **Config-time hardening.** Call `validateSaveRestoreSupportWithError()`
  as a **separate gate after** `validateWithError()` — VZ silently boots
  configs that cannot be snapshotted. Pin the NAT device MAC
  (`VZNATNetworkDeviceAttachment` + `initWithString`) to avoid address
  collisions across concurrent VZ VMs sharing the host NAT.
- **Nested virtualization.** One reference exposes `/dev/kvm` inside the
  Linux guest behind a `--virtualization`-style flag; another wires
  `setNestedVirtualizationEnabled(true)` on a `VZLinuxBootLoader` guest
  **end-to-end to host Firecracker inside the VZ guest**, with a guest
  kernel config that surfaces `/dev/kvm`. macOS 26 / Apple Silicon M3+.
  → WS-D.
- **Snapshot/fork.** One reference reports **sub-second snapshot &
  restore (warm ~138 ms, cold ~252 ms)** with agent-forking from a saved
  state; another splits a cheap filesystem-only checkpoint from a full
  memory-state save. A Swift-helper-based tool in the set instead forks
  via **APFS clones (`cp -c`)** for instant CoW roots — which our
  `apple_container` backend already does per-instance. → Plan 159.
- **Guest `/init` exit-code contract.** `/init` reads `/proc/cmdline`
  with shell builtins, mounts pseudo-fs + rootfs + a tmpfs/ext4 overlay,
  optionally brings up networking, runs the command capturing `$?`,
  **writes the exit code to a host-visible channel** (a virtio-fs control
  file, or over vsock), `sync`s, then `poweroff -f`. The host reads it
  after the VM stops. Read-only roots with no control channel cannot
  propagate an exit code. → WS-A.

### External prior art (2026-06-04 review)

Five adjacent projects were reviewed (named obliquely per repo policy;
keyed by trait in the auto-memory `reference_objc2_vz_external_references`). The decisive
observation: **process-separation and implementation language are
orthogonal, and no reviewed project combines both of the choices we
want.**

| Reference (oblique) | Process model | Language | What we take |
|---|---|---|---|
| on-device sandbox | in-process (entitled CLI) | Rust + objc2 | serial-queue/no-runloop model; `/init` exit contract |
| single-shot runner | in-process (entitled CLI) | Rust + objc2 | `--virtualization` nested-virt → `/dev/kvm` (WS-D) |
| multi-crate runtime (the DX reference) | in-process (entitled CLI) | Rust + objc2 | nested-virt end-to-end (WS-D); `validateSaveRestoreSupport`, pinned-MAC, tiered checkpoints (WS-E); vsock fd→dup→`AsyncFd` (WS-B); **its DX surface → Plan 159** |
| agent-microVM tool | in-process (entitled CLI) | Rust + objc2 | sub-second snapshot/restore + fork; vsock session-secret auth; smoltcp SLIRP (note only) |
| CLI + helper tool | **separate** entitled helper | Rust CLI + **Swift** helper | confirms the separate-process model — but kept Swift; APFS-clone CoW forks |

The "CLI + helper" tool is architecturally **us today**: an unprivileged
Rust CLI driving a separate entitled helper — but the helper is Swift.
The four Rust-objc2 projects prove Rust drives VZ fully — but all put it
in-process, entitling the whole CLI. The combination we adopt —
**separate per-VM helper *and* Rust-objc2** — is the unfilled square in
this matrix. (A sixth candidate in the original list turned out to be a
container-orchestration tool with no VZ surface; discarded.)

What the references do **not** have, and we keep: signed/audited
`ExecutionPlan`s (claim 8), dm-verity verified boot (claim 3),
default-deny egress bound to a chain-signed audit log (claim 10), the
supervisor control socket (PAUSE/RESUME/BALLOON/SAVE/RESTORE), and the
gvproxy flow audit. They are **architecture** references, not a
**security** reference — do not regress posture to match them.

## Decision: drop Swift — migrate the VZ supervisor to Rust-native `objc2`

We **reverse** this plan's original "keep the Swift supervisor" call. We
will reimplement the VZ supervisor in Rust against `objc2-virtualization`,
kept as a **separate, per-VM, codesigned binary** (a new `[[bin]]` in
`mvm-vm-host`, sibling to `mvm-libkrun-supervisor`). The reviewed
projects are inspiration only — **no third-party VZ crate becomes a
dependency**. The three legs of the original decision now resolve the
other way:

1. **Entitled TCB — preserved, and it never required Swift.** Whatever
   process calls VZ must carry `com.apple.security.virtualization`. We
   keep that in a *separate* tiny binary so `mvmctl` itself is never
   entitled. That argument is about **process separation, not language**.
   Every in-process reference reviewed entitles + ad-hoc re-signs its
   whole CLI on every build — confirming the cost is intrinsic to going
   in-process, which we are **not** doing.
2. **Supervisor-per-VM — preserved and strengthened.** Our control
   socket, audit chain, and backend symmetry assume a long-lived
   per-VM supervisor *is* the unit of isolation. A Rust supervisor keeps
   all of that and gains **language symmetry** with the already-Rust
   `mvm-libkrun-supervisor`, sharing one codebase for framing, control,
   audit, and codesigning instead of a Swift reimplementation.
3. **Dependency wash — now void, tipping the balance.** The original
   plan called dropping Swift "a wash" (remove SwiftPM, add objc2). That
   is no longer true: **`objc2 = "0.6"` and `objc2-virtualization = "0.3"`
   are already workspace dependencies** (`crates/mvm-backend/Cargo.toml`),
   already used by the `apple_container` backend
   (`crates/mvm-backend/src/providers/apple_container/macos.rs`). Adopting
   them for the supervisor adds **nothing new**, while we delete the
   Swift toolchain, `Package.swift`, `tools/build.sh`, the Swift
   `Entitlements.plist` path, and the `MVM_VZ_SUPERVISOR_PATH`
   Swift-build-output discovery friction (`vz.rs` source-tree resolver).

### What this costs (be honest)

- **vsock multiplexing is the one genuinely new chunk.** The TCP↔vsock
  splice logic lives only in `VsockProxy.swift` today; it must be rebuilt
  in Rust (tokio + `VZVirtioSocketDevice.connect(toPort:)` via objc2,
  fd→`dup`→`AsyncFd`). The `apple_container` backend already has a
  vsock-proxy listener (`start_vsock_proxy_listener()`) we can mine.
- **objc2 lifecycle/threading is new to *us*** (private serial dispatch
  queue, `QueueBound<Send>` wrapper, `RcBlock` completion handlers,
  `declare_class!` delegate) — well-trodden by the references, but a
  learning curve and an `unsafe` surface to review carefully.
- **Codesigning a Rust binary** with `com.apple.security.virtualization`:
  extend the existing `mvm_backend::providers::apple_container::
  ensure_signed()` harness (it already self-signs the
  `com.apple.security.hypervisor` entitlement for libkrun).
- **Scope risk.** The Swift supervisor is shipped and working; this is a
  rewrite of a security-sensitive component. It is gated behind Plan 120
  green like the rest of this plan, and lands behind backend-parity tests
  before the Swift path is removed.

See `reference_on_device_vz_objc2`,
`reference_mvm_vz_supervisor_separate_swiftpm_binary`, and the
`reference_objc2_vz_external_references` key.

## Workstreams

### WS-A — Guest `/init` exit-code / poweroff parity (the actionable one)

Bring `mkGuest`'s `/init` in line with the reference contract so a
finished workload **writes its exit code and powers off**, instead of
the current reboot that strands the agent (Plan 120 root cause).

- [ ] Diff the current `mkGuest` `/init` (in `crates/mvm-guest` +
      the Nix `/init` it bakes) against the reference sequence: run
      command → capture `$?` → write to a host-visible control file →
      `sync` → `poweroff -f`.
- [ ] Define the host-visible exit channel for our backends. We do not
      have a writable virtio-fs control share on every backend; pick
      between (a) a dedicated control vsock port the supervisor reads,
      or (b) a small control share, and document why. Prefer vsock —
      it already exists on libkrun + Vz and avoids a new mount.
- [ ] Implement `poweroff -f` (not reboot) as the workload PID-1
      terminal action, with the exit code emitted on the chosen
      channel first.
- [ ] Surface the captured exit code through `VzBackend` /
      `LibkrunBackend` lifecycle and into the audit chain
      (`plan.launched` → a `plan.exited` with the code, or extend the
      existing terminal event).
- [ ] Regression: a function-workload example that exits non-zero must
      propagate that code to `mvmctl`. Extend `examples/agent_ping`
      or add an `examples/exit_code` fixture.

### WS-B — Migrate the VZ supervisor from Swift to Rust-native `objc2` (the headline)

Replace `crates/mvm-vz-supervisor/` (Swift) with a Rust binary using
`objc2-virtualization`, kept as a separate per-VM codesigned process.
~70% of the substrate is already shared Rust (exploration verdict).

- [ ] New `[[bin]]` `mvm-vz-supervisor` in `mvm-vm-host`, sibling to
      `mvm-libkrun-supervisor` / `mvm-vz-drainer`, cfg-gated macOS. Reads
      the same `SupervisorConfig` JSON on stdin.
- [ ] Reuse, don't reimplement: `mvm_build::vz::SupervisorConfig`
      (schema already mirrored), `mvm_core::framing`,
      `mvm_hostd::supervisor::audit_file::FileAuditSigner`, and the
      gateway audit bridge (`mvm_hostd::supervisor::gateway_bridge` —
      thread it inline; the out-of-process `mvm-vz-drainer` becomes
      optional/removable).
- [ ] Build the `VZVirtualMachineConfiguration` in Rust: `VZLinuxBootLoader`,
      virtio block/fs/net (gvproxy file-handle attachment), vsock device,
      console, cpu/memory, balloon, entropy. Call `validateWithError()`
      **then** `validateSaveRestoreSupportWithError()`; pin the NAT MAC.
- [ ] **Vz `payload_tap` (absorbs Plan 141's Vz arm).** Attach the guest
      net device to a socketpair Rust owns; run the gateway bridge + Plan
      141 observer pipeline (`on_packet`/`Verdict`/etherparse) **in-process**
      against it — no SCM_RIGHTS, no Swift, no NDJSON ingest. Advertise
      `ProviderCapabilities { flow_events: true, payload_tap: true }` for
      Vz; delete the `mvm-vz-drainer` + `BridgeEndpoints::VzIngest` NDJSON
      path (Plan 141 Q10). Reuses 141's backend-agnostic
      `Observer`/`gateway_bridge` core unchanged (ADR-064 §8).
- [ ] Lifecycle: private serial dispatch queue, `declare_class!`
      delegate for terminal events, `RcBlock` completion handlers,
      `QueueBound<Send>` for the non-`Send` `Retained` handles. No
      `CFRunLoop`.
- [ ] Reimplement `VsockProxy.swift` in Rust: per-port UDS listeners at
      `<socketDir>/vsock-<port>.sock` (mode 0700) ↔
      `VZVirtioSocketDevice.connect(toPort:)`, fd→`dup`→`AsyncFd`. Mine
      `apple_container::start_vsock_proxy_listener()` for the port
      allowlist + framing.
- [ ] Reimplement the control socket (`control.sock`, mode 0700,
      newline-framed PAUSE/RESUME/STATUS/BALLOON/SAVE/RESTORE) — the
      client half already lives in `crates/mvm-backend/src/vz_control.rs`;
      extract a shared `vz::control` codec.
- [ ] Snapshot: `saveMachineStateToURL` / `restoreMachineStateFromURL`
      (macOS 14+) with the `<snapshot>.machine-id` sidecar, matching the
      Swift behaviour exactly.
- [ ] Codesign: extend `mvm_backend::providers::apple_container::
      ensure_signed()` to sign the new binary with
      `com.apple.security.virtualization`.
- [ ] Update `vz.rs` `resolve_supervisor_path()` to find the
      `mvm-vm-host` build output; **delete** the Swift-build-output search
      branch and the SwiftPM dependency once parity tests pass.
- [ ] Parity gate: a test matrix asserting the Rust supervisor matches
      the Swift one on boot, vsock round-trip, every control verb, and
      save/restore — **before** removing `crates/mvm-vz-supervisor/`.
- [ ] Remove the Swift crate, `tools/build.sh`, `Package.swift`,
      `Entitlements.plist`, and the `MvmContainerBridge/bridge.swift`
      stub; drop `MVM_VZ_SUPERVISOR_PATH` Swift-discovery from
      docs/memory. Fold the entitled-TCB rationale into an ADR-056
      addendum (was the deferred "drop Swift" note).

### WS-C — Adjacent ideas (deferred, notes only — not scheduled here)

- [ ] Rootfs provider trait alignment (OCI/tar/squashfs) — overlaps
      `mvm-oci`; our squashfs-vs-dm-verity'd-ext4 divergence is by
      design (claim 3), so this is a deliberate non-match, not a gap.
- [ ] `smoltcp` usermode SLIRP NAT (no TAP) — one reference avoids host
      TAP entirely; weigh against gvproxy + the claim-10 flow-audit
      splice, which the SLIRP path would have to re-host. Note only.

### WS-D — Nested-virt `/dev/kvm` in a VZ guest (investigate; could retire the Lima test carve-out)

Two references expose `/dev/kvm` to a Linux VZ guest via Apple's nested
virtualization (macOS 26 / Apple Silicon M3+) — one behind a
`--virtualization`-style flag, the other wired end-to-end
(`setNestedVirtualizationEnabled(true)` on `VZLinuxBootLoader` + a guest
kernel config that surfaces `/dev/kvm`) specifically to host Firecracker
*inside* the VZ guest.

Why this matters: our architecture has no `/dev/kvm` on macOS, so the
Firecracker/Linux-KVM path is Linux-only and we lean on **Lima purely as
a test-env KVM provider** (the one surviving Lima carve-out — see
`project_lima_removed` / AGENTS.md). A nested-virt VZ guest gives us a
real `/dev/kvm` on a Mac, letting us run the Firecracker backend inside
our own VZ builder VM — exercising the Linux path on macOS dev/CI
**without Lima**, and converging the two host stories.

- [ ] Capability probe on the dev host: `isNestedVirtualizationSupported`
      + the `VZGenericPlatformConfiguration` nested flag; confirm the new
      Rust supervisor (WS-B) can set it. Gate strictly on M3+ / macOS 26.
- [ ] Spike: a VZ Linux guest with nested virt on, booting Firecracker
      against `/dev/kvm` inside it, running an existing Firecracker
      workload E2E.
- [ ] If it holds, scope retiring the Lima test-env carve-out and
      document the M3+/macOS-26 floor.

Dev/test convenience only — not a posture change; the workload security
tier is unaffected.

### WS-E — VZ config hardening borrowed from prior art (folds into WS-B)

These ride the WS-B Rust supervisor build; listed separately so they are
not lost if WS-B is staged.

- [ ] `validateSaveRestoreSupportWithError()` as a separate gate after
      `validateWithError()`, before boot — fail/warn early when a VM we
      promise save/restore on cannot actually checkpoint.
- [ ] Pin the NAT device MAC (deterministic `initWithString`) to avoid
      collisions when multiple VZ VMs share the host NAT.
- [ ] Note only: tiered checkpoint classes + sub-second restore are a
      Plan 159 concern (snapshot/fork DX); the supervisor primitives
      (`saveMachineStateToURL`, the APFS-CoW rootfs) land here.

## Non-goals

- Running VZ **in-process** in `mvmctl` (the entitled-TCB invariant —
  WS-B keeps a separate process; we drop Swift, not the process moat).
- Taking any reviewed project as a **dependency** — inspiration only.
- Desktop / VNC session mode — we are headless by design (ADR-001 /
  CLAUDE.md "Headless microVMs").
- Any reduction of the claim 1–14 security posture to match a
  reference's lighter model.
- Adopting SSH-into-guest or in-guest agent injection (one reference does
  this — violates "No SSH in microVMs, ever").

## Verification

WS-A is the first buildable deliverable; WS-B is the larger one.
Validate on the local Vz dev host (this Mac runs the builder via Vz — see
`project_dev_host_runs_builder_via_vz`; isolate with
`MVM_CACHE_DIR`/`MVM_DATA_DIR` to avoid the shared nix-store flock):

1. **WS-A:** build + boot a function workload through the artifact-model
   path (`compile` → `up --flake` → agent ping), confirming the guest
   now `poweroff`s rather than rebooting (watch
   `<vm_state_dir>/console.log`). Run the non-zero-exit fixture; assert
   `mvmctl` returns that exit code and the audit chain carries the
   terminal event.
2. **WS-B:** the parity matrix (boot, vsock round-trip, every control
   verb, save/restore) must pass on the Rust supervisor **before** the
   Swift crate is deleted. Re-run a full `dev up` + workload boot on the
   Rust supervisor end-to-end.
3. `cargo nextest run --workspace`, `cargo test --workspace --doc`,
   `rustup run nightly cargo fmt --all -- --check` (CI Lint uses nightly
   rustfmt), `cargo clippy --workspace -- -D warnings`. Note
   `mvm-backend` test binaries can be SIGKILL'd by macOS codesign
   locally (`reference_mvm_backend_test_binary_macos_codesign_sigkill`) —
   lean on Linux CI for that crate.

Never run `core_demo_e2e` unbounded — background it with `gtimeout`,
redirect stdio to a file, and reap (see
`feedback_never_run_core_demo_e2e_unbounded`).

## References

- `specs/plans/97-vz-backend.md` — the Swift supervisor WS-B replaces.
- `specs/plans/120-core-demo.md` — the `/init` reboot blocker WS-A
  targets.
- `specs/plans/134-architecture-aware-artifact-model.md` — the refactor
  this plan is sequenced after.
- `specs/plans/159-vz-inspired-macos-dx.md` — the DX/feature build-out
  that depends on this plan's Rust supervisor.
- `specs/research/on-device-vz-sandbox-gap-analysis.md` — sibling
  product/feature analysis of one reference; WS-D/WS-E extend it.
- `specs/adrs/056` — Vz backend ADR (entitled-TCB / drop-Swift addendum
  target, WS-B final step).
- `crates/mvm-vz-supervisor/` — the Swift supervisor (`Supervisor.swift`,
  `ControlSocket.swift`, `VsockProxy.swift`, `Network.swift`,
  `Config.swift`) WS-B ports to Rust.
- `crates/mvm-backend/src/vz.rs` + `vz_control.rs` — the Rust driver +
  control-socket client to reuse.
- `crates/mvm-vm-host/src/bin/mvm-libkrun-supervisor.rs` — the Rust
  supervisor sibling whose substrate WS-B shares.
- `crates/mvm-backend/Cargo.toml` + `.../providers/apple_container/
  macos.rs` — the already-present `objc2-virtualization` dep + usage.
- `crates/mvm-guest/` + the baked `/init` — WS-A's edit site.
- External prior art (named obliquely per repo policy): five adjacent
  Rust/VZ projects reviewed; the oblique-reference key is in the auto-memory
  `reference_objc2_vz_external_references`.
