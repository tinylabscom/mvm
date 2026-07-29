# Non-Nested aarch64 `machine run` Witness Plan

> **For agentic workers:** Steps use checkbox (`- [ ]`) syntax for tracking. This
> is a short execution plan, not a build-out — the code is already shipped; what
> is missing is one run on hardware the dev Mac cannot provide.

**Goal:** Prove the Tier-1 edge path end to end on real hardware: on a
non-nested aarch64 host, `bundle install` followed by `machine run --manifest
<sha>` exits 0 with the guest agent answering the readiness handshake.

**Architecture:** Nothing new is built. A signed `.mvmpkg` and the cross-built
aarch64 binaries are produced on the dev Mac and carried to an aarch64 host that
exposes real `/dev/kvm`; that host only verifies, admits and boots. This is
exactly the runtime-only split the edge story depends on — the build machine and
the running machine are different machines.

**Tech Stack:** aarch64 Linux with real KVM (Raspberry Pi 5, or AWS
`c7g.metal`), Firecracker v1.14.1, the cross-built `mvmctl` plus the `mvm-hostd`
subprocess binaries, and an aarch64 `.mvmpkg` sealed by the host signer.

## Why this cannot be done on the dev Mac

Under nested KVM (Lima on Apple silicon) the guest boots correctly — kernel up,
`mvm-init` provisions the verb-grant, the agent reaches `control plane ready`
and listens on vsock 5252 — but the host→guest Firecracker-vsock CONNECT never
completes, so `machine run` ends in `guest agent did not answer within 60s`.

That is **not an mvm defect**. The identical readiness handshake succeeds on
bare-metal x86_64 KVM with the same Firecracker v1.14.1 (`machine run --image
alpine -- /bin/echo …` returned its output to the host). The vsock question is
architecture-independent, so the only unproven leg is aarch64 on non-nested
hardware.

## Global Constraints

- No plan/PR/ADR/issue references in code comments (CI-gated). This plan is a
  spec document; keep its identifiers out of any code touched.
- All `~/.mvm` paths go through `mvm_core::config` helpers — never inline
  `$HOME/.mvm`.
- No `sudo` on the dev host. Privileged steps happen on the target box.

## Tasks

### 1. Secure the hardware

- [ ] Pick one: **Raspberry Pi 5 (8 GB)** — the actual Tier-1 target device and
      the most authentic witness — or **AWS `c7g.metal`**, bare metal and rented
      by the hour, which is faster to stand up.
- [ ] Do **not** use an ordinary aarch64 cloud VM: nested virtualization is not
      exposed there, which reproduces the exact condition being escaped.

### 2. Prepare the target host

- [ ] Confirm `uname -m` is `aarch64` and `/dev/kvm` is openable read-write
      (join group `kvm`, or `chmod 666 /dev/kvm` on a throwaway box).
- [ ] Install **Firecracker v1.14.1** — mvmctl's `FC_VERSION_DEFAULT`. Older
      builds reject the `--enable-pci` argument mvmctl passes and exit 153
      before the kernel loads.
- [ ] Confirm no Rust and no Nix are needed: binaries and the bundle are copied in.

### 3. Carry the artifacts over

Staged on the dev Mac at `~/mvm-edge-witness/` (bundle, host-signer pubkey,
aarch64 `mvmctl`, and the `mvm-hostd` subprocess bins).

- [ ] Copy that directory to the target and `chmod +x` the binaries.
- [ ] Put the `mvm-hostd` bins on `PATH` beside `mvmctl` — the Firecracker path
      spawns them as separate processes.
- [ ] If the bundle is stale or gone, rebuild on the Mac:
      `mvmctl machine build --flake ./examples/sleeper --builder hvf`, then
      `mvmctl machine build ./examples/sleeper` to register a slot, then
      `mvmctl bundle export <FULL 64-char slot hash> --out sleeper.mvmpkg`.

### 4. Run the witness

- [ ] `export MVM_HOME=/tmp/mvm-edge` and place the host-signer public key at
      `$MVM_HOME/trusted-publishers/<key_id>.pub`, or `bundle install` refuses
      the archive.
- [ ] `mvmctl bundle install ./sleeper-meta.mvmpkg` — expect **3 artifacts**
      (kernel, rootfs, guest sidecar) and capture the printed content address.
- [ ] `mvmctl machine run --manifest <sha> --entrypoint --timeout 120`.

### 5. Confirm and record

- [ ] `machine run` exits 0.
- [ ] `$MVM_HOME/vms/<vm>/console.log` shows `mvm-init: provisioned verb-grant`,
      the runtime overlay mounted at `/mvm/runtime`, and `control plane ready`.
- [ ] No `guest agent did not answer within` line.
- [ ] Record the result (and the boot timings) back into this plan, and close
      out the edge-path thread in `specs/SPRINT.md`.

## Gotchas already paid for

- `bundle export` wants the **full 64-char slot hash**; the truncated form
  `manifest ls` prints is rejected.
- A fresh `MVM_HOME` fails on a cold workload-kernel cache for the `--image`
  path. The bundle path supplies its own kernel, so this only bites on a detour
  through `machine run --image`.
- **Never diagnose cmdline contents from the guest's `Kernel command line:`
  line.** The kernel's `printk` truncates that log line near 1024 characters and
  it looks exactly like real cmdline truncation — it cost a wrong root cause
  once already. Read `firecracker.log`'s `boot_args`, or `/proc/cmdline` inside
  the guest.
- Pull `main` first. The fixes that make this run possible are all recent and
  all load-bearing: ARM64 `Image` kernels reaching Firecracker, the guest
  reading the host-signer pubkey off the cmdline when there is no config drive,
  `bundle export` carrying the guest sidecar, and the fail-closed cmdline guard.

## If it still times out

Nesting was not the cause, and it needs investigation rather than another
environment. Capture `firecracker.log` and `console.log` and compare the vsock
UDS path and guest CID against what the driver configured; an agent that is
listening while the host cannot connect points at the device/CID wiring rather
than at the agent.
