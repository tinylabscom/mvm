# ADR-056 — Vz backend (Apple Virtualization.framework)

**Status:** accepted 2026-05-22, implements Plan 97. Vz is an opt-in
macOS backend (`MVM_BACKEND=vz` / `--backend vz`); `auto_select`
remains unchanged so libkrun is still the macOS default and
Firecracker the Linux deploy default.

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

ADR-002 claim coverage under Vz:

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

- **ADR-002 (microvm security posture).** Adds a Vz row to the
  per-backend claim table at `specs/adrs/002-microvm-security-posture.md`.
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
