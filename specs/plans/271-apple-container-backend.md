# Plan 271: Apple Container backend — Apple's container kernel on HVF

**Status:** stages 1–2 complete — digest-pinned kernel attestation, thin
HVF-runner delegation, and live e2e validation (2026-08-01). Remaining:
container-mode closure (later stage).
**Owner:** mvm core.
**Depends on:** universal initramfs + `ActivateEnvironment` (PR #1914) —
the initramfs itself is a deterministic cargo artifact (reproducible
`cargo zigbuild` of the pinned agent source + deterministic cpio +
content hash), not a Nix build.

> **Design history.** Stage 1 was the fail-closed backend skeleton. Stage 2
> booted Apple's container kernel + the `initfs.ext4` carrying `/sbin/vminitd`
> on the in-house HVF VMM and drove activation through vminitd's gRPC API
> (the Swift/Virtualization.framework shim before that was abandoned,
> PR #1939). **Final design (this revision):** vminitd is dropped entirely —
> it is Swift with no prebuilt artifact, so the backend runs the identical
> initramfs/activation stack as every other runner backend, differing only
> in the kernel image. The backend is now 100% Rust-native: zero Swift
> anywhere, zero VZ/Virtualization.framework anywhere (guarded by
> `xtask check-no-vz`).

## Goal

An `--hypervisor apple-container` backend that runs mvm workloads on
Apple's prebuilt container kernel with the **same guest-visible
functionality** as every other backend: a fail-closed init gate, an
environment-activation step, dm-verity rootfs + runtime overlay, virtio-fs
volumes, privilege drop to uid 901, and the standard operational RPC
surface after activation.

The honest consequence of "all backends, same functionality": the backend
**is** the HVF workload runner with the kernel image substituted. Apple's
container kernel is a fetched binary artifact (the Kata container-kernel
package the containerization project recommends, or any compatible arm64
Linux `Image`) — no toolchain, no Swift, nothing Apple-built runs on the
host or as guest PID 1.

The backend is admitted to the workload funnel: it implements
`WorkloadBackend` (the same `VsockUdsChannel` egress transport as the
runner), so `require_workload_backend` — the single boundary of the
admitted launch path — accepts it, and `mvm_client::start_prepared` plus
the admitted persistent-OCI path boot `--hypervisor apple-container`
exactly as they boot `--hypervisor hvf`. Egress, broker registration,
and the admitted funnel are shared verbatim; only the kernel image
differs.

## Design

```text
Firecracker / libkrun / HVF / QEMU / WHP:  kernel + universal initramfs
                                           → agent is PID 1 → ActivateEnvironment over vsock:5252

Apple Container:                           Apple's prebuilt container kernel + the SAME universal
                                           initramfs on the SAME HVF runner → identical everything
                                           else; only the kernel image differs
```

- **Artifact resolution** (`apple_container/artifacts.rs`):
  `<mvm-cache>/apple-container/vmlinux`, probed at `start`; a missing
  kernel is a typed `ArtifactMissing { what, path, hint }` whose hint
  names the fetch source. The kernel is trusted only with a matching
  `vmlinux.blake3` digest sidecar beside it (bare `<hex>` or `b3sum`
  `<hex>  <name>` form): a missing, malformed, or mismatching sidecar is
  a typed `ArtifactUntrusted { path, reason, hint }`, and an unverified
  kernel never makes the backend `is_available`. Pure `resolve_from(dir)`
  seam for tests.
- **Delegation** (`apple_container_backend.rs`): `start`/`start_with_mode`
  resolve the kernel, clone the config, set `kernel_path` (which the
  runner maps to `KernelImage::Path`), and delegate to
  `crate::backend::hvf_runner()`. Every other operation — stop, stop_all,
  wait, status, list, logs, pause, resume, warm_start, capabilities,
  is_available, install — delegates to the same runner instance. The
  `initrd_path` contract is the runner's own: a sealed boot expects the
  universal-initramfs artifact from the caller (the CLI attach path),
  exactly as for HVF; no gate of its own.
- **Honesty**: `capabilities()` and the claims array of
  `security_profile()` are the HVF runner's verbatim; the notes record
  that the kernel is a fetched artifact attested by a required digest
  sidecar, and that the sealed boot path is live-proven on it. Opt-in
  only; `auto_select` never returns this backend.

What is honestly different, and documented as such: the kernel is an
Apple-built artifact cached on the host, not bundled by mvm. Verified boot
of the rootfs still holds — dm-verity runs in-guest — but the *kernel
image* chain of custody is the artifact cache's, exactly like libkrun's
bundled kernel.

## Milestones

### Stage 1 — Artifact fetch + thin HVF-runner delegation (implemented)

- Kernel-only artifact resolution with the typed, hint-carrying error.
- The delegating backend: kernel substitution, full lifecycle delegation,
  mirrored capabilities/claims with provenance notes.
- Tests: kernel-override mapping (substitutes `kernel_path`, replaces a
  caller-supplied kernel, preserves everything else), artifact-missing
  typed error before any delegation, name/kind, capabilities + claims
  mirror the runner, availability tracks the runner ∧ the artifact,
  never auto-selected.
- Gate: workspace clippy + tests + policy xtasks green; `check-no-vz`
  clean; closure budget back to 270 (the vminitd gRPC client's
  `prost`/`prost-types`/`h2`/`http` and their exclusive transitives left
  the default closure).

### Stage 2 — Live e2e validation (complete, 2026-08-01)

- [x] Kernel attestation landed first: the cached kernel boots only with
      a matching `vmlinux.blake3` digest sidecar; missing, malformed, or
      mismatching sidecars fail closed with the typed `ArtifactUntrusted`
      error (same hash-sidecar honesty as the initramfs artifact). The pin
      is BLAKE3, not SHA-256: it hashes a multi-hundred-MB kernel an order
      of magnitude faster on every supported host, and SHA-256 stays where
      it is contractually locked (OCI digests, dm-verity, snapshot
      signing, the shipped `initramfs.hash` contract).
- [x] Live CLI smoke on macOS HVF: `mvmctl machine run --hypervisor
      apple-container --image alpine -- ps aux` — full boot on the Apple
      kernel. (The original phrasing `mvmctl up --hypervisor
      apple-container` predates the CLI shape: `up` is not a subcommand —
      `machine run` / `machine start` are the boot verbs.) PID 1 is
      `/init` as uid 901, `ps aux` ran as uid 901 (privilege drop),
      dm-verity kernel threads visible, and the operational RPC surface
      (run-command + streamed output) worked over the authenticated
      channel.
- [x] Sealed-boot smoke (universal initramfs + dm-verity rootfs + runtime
      overlay): the gated e2e
      `start_boots_a_sealed_workload_on_the_apple_container_kernel`
      passed in 4.27s against the digest-pinned kernel. Console proof:
      `device-mapper: verity: sha256 using "sha256-lib"` ×2, `EXT4-fs
      (dm-0)` and `(dm-1)` mounted read-only (rootfs + runtime overlay
      both dm-verity verified), `mvm-guest-agent: activation complete,
      serving operational RPCs`.
- [x] Claim-by-claim review of `security_profile()`: the claims array
      stays a verbatim mirror of the HVF runner — the isolation story is
      identical, only the kernel image differs — and claim 3 stays
      DoesNotHold for the virtiofs-root path (owner decision: no flip).
      The notes now record the digest-pin requirement and the live-proven
      sealed boot.
- [x] BDD under `features/suites/s25_apple_container/`: artifact
      resolution fails closed with the hint-carrying error, the
      digest-pin contract (matching sidecar resolves; missing, malformed,
      and tampered sidecars fail closed — the tampered-kernel scenario
      names both the pinned and actual digests), auto-select exclusion,
      and the kernel-substitution mapping.

Follow-up (pre-existing, not AC-specific): transient `machine run`
teardown ends with `wait failed: No child process (os error 10)`;
it reproduces identically with `--hypervisor hvf`, so it is a
shared-runner issue for the HVF runner, not this backend.

## Constraints that do not change

- `ActivateEnvironment` semantics, `guest_mount`, uid 901, the
  `NotActivated` gate, the egress endpoint, and the broker registration
  are shared verbatim — by construction, since the backend delegates to
  the same runner. No backend-specific fork of the guest agent.
- Auto-select never returns this backend; it is opt-in only via
  `--hypervisor apple-container` (alias `container`). The availability
  probe is fail-closed on attestation: a cached kernel without a matching
  `vmlinux.blake3` sidecar never makes the backend `is_available`, so a
  verified artifact is a hard precondition for any use, explicit or
  probed. (This supersedes the earlier "opt-in only until it carries a
  production tier" phrasing — the tier story did not change; the digest
  pin is what landed.)
- `BackendKind` exhaustiveness is load-bearing: the ripple across match
  sites is intentional and keeps every dispatch site honest.
- `xtask check-no-vz` is the permanent guard: no Swift, no
  Virtualization.framework, no Containerization SwiftPM package in the
  tree, ever.
