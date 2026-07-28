# Plan: a green `machine run` on non-nested aarch64 hardware

Date: 2026-07-28
Status: ready to execute; needs one piece of hardware

## Goal

One witness, one command: `bundle install` → `machine run --manifest <sha>`
exits 0 on a non-nested aarch64 host, with the guest agent answering the
readiness handshake. Everything upstream of that already works.

## Why it can't be done on the dev Mac

Under nested KVM (Lima on Apple silicon) the guest boots correctly — kernel up,
`mvm-init` provisions the verb-grant, the agent reaches `control plane ready`
and listens on vsock 5252 — but the host→guest Firecracker-vsock CONNECT never
completes, so `machine run` ends in `guest agent did not answer within 60s`.

That is **not an mvm bug**. The same readiness handshake succeeds on bare-metal
x86_64 KVM with the identical Firecracker v1.14.1: `machine run --image alpine
-- /bin/echo …` returned its output to the host. The vsock question is
arch-independent, so the only thing still unproven is the *aarch64* leg on
non-nested hardware.

## Hardware — pick one

- **Raspberry Pi 5 (8 GB)** — the actual Tier-1 target device, so the most
  authentic witness. Preferred if one is on hand.
- **AWS Graviton `c7g.metal`** — bare metal, real KVM, rent by the hour.
  Fastest path if there is no Pi.

Do **not** use an ordinary aarch64 cloud VM: nested virtualization is not
exposed, which reproduces exactly the condition being escaped.

## Host prerequisites

1. aarch64 Linux with `/dev/kvm` present and openable (join group `kvm`, or
   `chmod 666 /dev/kvm` for a throwaway box).
2. **firecracker v1.14.1** — mvmctl's `FC_VERSION_DEFAULT`. Older builds reject
   the `--enable-pci` argument mvmctl passes and exit 153 before boot.
3. No Rust and no Nix required on the host: binaries and the bundle are copied in.

## Artifacts to carry over (all produced on the Mac)

- `mvmctl` for aarch64:
  `cargo zigbuild --target aarch64-unknown-linux-gnu --bin mvmctl`
  (`MVM_SKIP_EMBED_BINARIES=1` is fine for this witness).
- The `mvm-hostd` subprocess bins for the same target, placed on `PATH` beside
  `mvmctl` — the Firecracker path spawns them.
- An aarch64 `.mvmpkg`. If the previous one is gone, rebuild:
  ```
  mvmctl machine build --flake ./examples/sleeper --builder hvf   # dev build
  mvmctl machine build ./examples/sleeper                          # registers a slot
  mvmctl bundle export <FULL 64-char slot hash> --out sleeper.mvmpkg
  ```
- The host-signer public key, into the target's
  `$MVM_HOME/trusted-publishers/<key_id>.pub`, or `bundle install` refuses the
  archive.

## Steps on the target

```
export MVM_HOME=/tmp/mvm-edge
mkdir -p "$MVM_HOME/trusted-publishers" && cp <key_id>.pub "$MVM_HOME/trusted-publishers/"
./mvmctl bundle install ./sleeper.mvmpkg          # expect: 3 artifacts
./mvmctl machine run --manifest <sha> --entrypoint --timeout 120
```

## Done when

- `machine run` exits 0.
- `$MVM_HOME/vms/<vm>/console.log` shows `mvm-init: provisioned verb-grant`,
  the runtime overlay mounted at `/mvm/runtime`, and `control plane ready`.
- No `guest agent did not answer within` line.

## Gotchas, all hit while getting this far

- `bundle export` wants the **full 64-char slot hash**; the truncated form
  `manifest ls` prints is rejected.
- A fresh `MVM_HOME` fails on a cold workload-kernel cache for the
  `--image` path. The bundle path supplies its own kernel, so this only bites if
  you detour through `machine run --image`.
- **Never diagnose cmdline contents from the guest's `Kernel command line:`
  line** — the kernel's `printk` truncates that log line near 1024 chars and it
  looks exactly like cmdline truncation. Read `firecracker.log`'s `boot_args`,
  or `/proc/cmdline` inside the guest.
- Pull `main` first. #1888 (ARM64 `Image` kernels reach Firecracker), #1891
  (guest reads the host-signer pubkey off the cmdline when there is no config
  drive), #1893 (`bundle export` carries the guest sidecar) and #1894
  (fail-closed cmdline guard) are all merged and all load-bearing for this run.

## If it still times out

Then nesting was not the cause and it needs real investigation rather than
another environment. Capture `firecracker.log` plus `console.log` and compare
the vsock UDS path and guest CID against what the driver configured; the agent
listening while the host cannot connect points at the device/CID wiring rather
than the agent.
