# Tier-1 edge host — the hermetic half, and what the hardware then found

Delivered 2026-08-18.

## Context

The ask was whether Nix could build for "bare metal" so microVMs could run
anywhere. Three different meanings were tangled in that word. Two of the four
cited sources use *bare metal* to mean physical hardware rather than cloud —
both install a full Linux OS. The scoping decision was Tier 1 only (a
KVM-capable aarch64 board hosts real workloads), hermetic only, no hardware.

## Shipped

- **#2658 — one registry for the per-VM binaries `mvmctl` spawns.**
  `resolve_subprocess_bin` finds them adjacent to the executable, falling back
  to `target/{release,debug}` — a path that exists only in a source checkout.
  So the set a contributor gets was not the set a user gets. Three hand-kept
  lists disagreed; the released Linux tarball shipped only
  `mvm-network-endpoint` while `host_agent_daemon_enabled()` defaults on, so a
  plain `up` reached for `mvm-host-agent` and `mvm-signer-helper` that were
  never built. `PER_VM_HOST_BINARIES` is now the single source of truth and
  `xtask check-per-vm-host-binaries-sync` fails on drift in either direction.
  Packaging also stopped being copy-if-exists.

- **#2664 — `machine run --image` no longer panics on a fresh `MVM_HOME`.**
  `resolve_guest_runtime_identity` returns `Ok("pending-<key>")` when the guest
  layout is unbuilt; `oci_runtime_tag` treated every `Ok` as a hash and sliced
  it at 16 bytes. Any fresh home on any platform aborted the process.

- **#2679 — a foreign-arch bundle is refused.** `BundleManifest.arch`'s own doc
  comment promised a refusal nothing implemented. Gated at the two boot sites
  behind `template_artifacts_for_boot`, and authoritatively at
  `admit_plan_for_run`, which holds the signature-verified manifest. The
  earlier attempt was reverted for gating the resolver shared with
  `bundle export` / `manifest export-oci`; those keep the un-suffixed path and
  a regression test proves it.

- **#2682 — the workspace suite runs natively on aarch64.** Every other lane is
  x86_64, so arch-gated code had never been compiled by CI. Its first run
  caught a real portability bug.

## What the hardware then found

A Pi 4 turned out to be available. It is a genuine non-nested aarch64 KVM host
(EL2, nVHE, live `KVM_CREATE_VM`), and Firecracker boots a guest to userspace
there in 0.28 s. That settled `console=ttyS0` and GICv2 on real silicon, and
surfaced two supply failures no hermetic test could have reached:

- **#2675** — the published-kernel fetch derives its release tag from the crate
  version, so it points at a release that does not exist. `kernel-build.yml`
  has never run on a tag push either, so only `v0.16.0` carries
  `vmlinux-aarch64-workload`.
- **#2676** — `HvfError::BadKernel` conflates seven distinct failures and
  discards every underlying cause, so the macOS builder failure is
  undiagnosable by construction.

## Deliberately not claimed

The end-to-end boot witness. `bundle install` → `machine run --manifest <sha>`
exiting 0 with the readiness handshake answered is still unproven, now blocked
on #2675 and #2676 rather than on hardware. The ESP32/no-OS verifier tier and
Nix-as-firmware-builder stayed out of scope throughout.
