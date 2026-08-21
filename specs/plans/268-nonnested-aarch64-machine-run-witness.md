# Non-Nested aarch64 `machine run` Witness Plan

> **SUPERSEDED (2026-08-18) for everything except the hardware witness itself.**
> The hermetic half of this plan has shipped; what remains is one run on real
> hardware, and the recipe below is still the recipe. Read this section first,
> then the original plan unchanged beneath it.
>
> **Hardware is no longer the blocker.** A Raspberry Pi 4 Model B (8 GB, Debian
> 13, kernel 6.18) is available at `rpi1.local` and is a genuine non-nested
> aarch64 KVM host: `CPU(s) started at EL2`, `Hyp nVHE mode initialized
> successfully`, `KVM_CREATE_VM` returns a live fd, and `/dev/kvm` is already
> read-write for the login user. Firecracker v1.14.1 boots a guest to userspace
> there in **0.28 s** and powers down cleanly.
>
> **Settled on that hardware, first time non-nested:**
>
> - `console=ttyS0` is correct for Firecracker on aarch64. G1 was previously
>   confirmed only under nested Lima; it now holds on real silicon.
> - **GICv2 is a non-issue.** The Pi 4 carries a GIC-400, not a GICv3. It was
>   an open risk; it is not a blocker.
> - `PF_VSOCK registered` in the guest — the transport the nested attempt died
>   on is present.
> - `mvmctl doctor` on the Pi reports platform OK (Linux with KVM), kvm OK, and
>   resolves the workload backend to Firecracker.
> - The cross-build recipe works: `cargo zigbuild --release --target
>   aarch64-unknown-linux-gnu` for `mvmctl`, and `-p mvm-hostd` for the
>   `PER_VM_HOST_BINARIES` set.
>
> **Witness execution update (2026-08-20).** The cross-built aarch64 GNU
> binaries (`mvmctl` + `mvm-hostd` per-VM set) were carried to `rpi1.local`,
> and the signed `examples/sleeper` bundle (`824b4600…`) was installed
> successfully against the pre-staged trusted publisher key. The run command
> that resolves an installed `.mvmpkg` is a **transient** `machine run`:
>
> ```bash
> mvmctl machine run --manifest 824b4600e8c907485a459335df5e45812b284f435c4ffc5aee81a9e79fac4dc3 \
>   --hypervisor firecracker -- /bin/true
> ```
>
> (Use `--entrypoint --timeout 120` instead of `-- /bin/true` when the bundle
> carries a baked entrypoint.) The bundle SHA is treated as a legacy name by
> `resolve_manifest_arg`, falls through to
> `template_artifacts_dispatched`, and resolves from `~/.mvm/bundles/<sha>`
> because no templates slot with that hash exists.
>
> Two environment prerequisites surfaced on the Pi:
>
> - `firecracker` must be on `root`'s `PATH` because the launch script uses
>   `sudo setsid … exec firecracker`. On this box that required copying the
>   binary into `/usr/local/bin/firecracker`.
> - The `runtime-overlay` cache for `0.18.0/aarch64` must be present under
>   `~/.mvm/cache` before the first boot; the release download URL 404s. The
>   overlay was built/seeded on the dev Mac and rsynced to the Pi.
>
> With those in place the VM boots and Firecracker reaches `InstanceStart`,
> but the HVF-builder-produced bundle kernel does not attach Firecracker's
> PCI virtio-blk/vsock devices (`probe with driver virtio_blk failed with
> error -524`). A Mac-built bundle intended for a Pi Firecracker host must be
> produced with a Firecracker-compatible workload kernel, or the kernel must
> be overridden at run time; the CLI invocation itself is now known.
>
> **What now blocks the witness is not hardware — it is two supply problems,
> both filed:**
>
> - **#2675** — the published-kernel fetch derives its release tag from the
>   crate version, so it points at `v0.18.0`, which has never been released.
>   `kernel-build.yml` has also never run on a tag push, so only `v0.16.0`
>   carries `vmlinux-aarch64-workload` at all. A Pi user following
>   `machine run --image` gets a hard 404.
> - **#2676** — the macOS HVF builder fails with an undiagnosable `BadKernel`,
>   so a signed `.mvmpkg` cannot be built locally. Aux-binary staleness was
>   checked and **ruled out**; the supervisor was fresh and no source was newer.
>
> **Shipped since this plan was written**, all of which this witness depends on:
> #2658 (the release tarball now carries every per-VM binary `mvmctl` spawns —
> the gap this plan hit as "the guest needs the full aarch64 host-side runtime"),
> #2664 (`machine run --image` no longer panics on a fresh `MVM_HOME`), #2679
> (a foreign-arch bundle is refused at boot and at admission), and #2682 (the
> workspace suite runs natively on aarch64 in CI).
>
> One correction to the observability assumption: the Pi has **no USB-TTL serial
> adapter and no HDMI attached**, so a bare-metal or console-only test there is
> blind. `machine run` over SSH is fine; anything that talks only to a UART is
> not.


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
- [x] If the bundle is stale or gone, rebuild on the Mac:
      `mvmctl machine run --flake ./examples/exit_code --builder hvf --hypervisor hvf`
      (builds and registers the slot), then
      `mvmctl bundle export <FULL 64-char slot hash> --out exit-code.mvmpkg`.
      Done: exported `/tmp/exit-code.mvmpkg` (24 MiB) with a freshly compiled
      Firecracker-compatible workload kernel (`virtio_pci`, `virtio_vsock`
      built-in).

### 4. Run the witness

- [ ] `export MVM_HOME=/tmp/mvm-edge` and place the host-signer public key at
      `$MVM_HOME/trusted-publishers/<key_id>.pub`, or `bundle install` refuses
      the archive.
- [ ] `mvmctl bundle install ./exit-code.mvmpkg` — expect **3 artifacts**
      (kernel, rootfs, guest sidecar) and capture the printed content address.
- [ ] `mvmctl machine run --manifest <sha> --hypervisor firecracker -- /bin/true`.

> **2026-08-20 blocker:** `rpi1.local` no longer resolves via mDNS, so the
> Pi-side install/run validation is on hold until network access returns.

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
