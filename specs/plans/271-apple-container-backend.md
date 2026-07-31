# Plan 271: Apple Container backend — Apple's container kernel on HVF

**Status:** implemented (thin HVF-runner delegation + kernel artifact resolution); live e2e validation remaining.
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
  names the fetch source. Pure `resolve_from(dir)` seam for tests.
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
  that the kernel is a fetched artifact whose provenance is not an mvm
  build. Opt-in only; `auto_select` never returns this backend.

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

### Stage 2 — Live e2e validation (remaining)

- Fetch a real Apple container kernel into the cache and boot a dev image
  on macOS HVF: `mvmctl up --hypervisor apple-container` to an
  authenticated `Ping`, exercise the operational RPC surface, `down`.
- Sealed-boot smoke (universal initramfs + dm-verity rootfs + runtime
  overlay) reusing the existing HVF lanes' artifacts.
- Claim-by-claim review of `security_profile()` after the smoke; BDD
  scenario under `features/suites/` mirroring the other runner backends.

## Constraints that do not change

- `ActivateEnvironment` semantics, `guest_mount`, uid 901, the
  `NotActivated` gate, the egress endpoint, and the broker registration
  are shared verbatim — by construction, since the backend delegates to
  the same runner. No backend-specific fork of the guest agent.
- Auto-select never returns this backend (opt-in only) until it carries a
  production tier, same discipline as QEMU.
- `BackendKind` exhaustiveness is load-bearing: the ripple across match
  sites is intentional and keeps every dispatch site honest.
- `xtask check-no-vz` is the permanent guard: no Swift, no
  Virtualization.framework, no Containerization SwiftPM package in the
  tree, ever.
