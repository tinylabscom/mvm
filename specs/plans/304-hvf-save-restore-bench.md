# Plan 304 — HVF save/restore benchmark evidence

Measured 2026-08-08 on macOS 26.5.2 (Darwin 25.5.2), Apple silicon, against a
release `mvmctl` plus release `mvm-hostd` binaries (`mvm-host-agent`,
`mvm-broker`, `mvm-host-signer`, `mvm-audit-signer`,
`mvm-substitution-endpoint`, `mvm-netd`, `mvm-signer-helper`,
`mvm-hvf-supervisor`) — a missing `mvm-host-agent` silently loses
`host.audit.v1` and adds ~700 ms, so every number below is from a fully built
tree.

Subject: a persistent HVF workload, `machine run --image alpine --name
hvf-ckpt-demo -d`. 512 MiB guest RAM; sealed rootfs (dm-verity) plus the
runtime overlay — four read-only, file-served virtio-blk devices, which is the
restorable disk shape.

## `machine checkpoint create --class vm-full` (5 runs)

| run | ms |
|-----|------|
| 1 | 1742.4 |
| 2 | 1631.0 |
| 3 | 1526.5 |
| 4 | 1849.3 |
| 5 | 1635.2 |

**p50 1635 ms, min 1527 ms, max 1849 ms.**

The window is dominated by two 512 MiB writes: `snapshot.ram` and the frame,
which carries its own copy of RAM. It is I/O-bound in guest-RAM size, not in
guest complexity. The source VM is running again when the command returns —
verified by the absence of `pause.state` after each capture.

## `machine checkpoint restore` (3 runs)

| run | ms |
|-----|------|
| 1 | 689.5 |
| 2 | 691.5 |
| 3 | 684.0 |

**p50 690 ms, min 684 ms, max 692 ms.**

Includes cloning the whole checkpoint content dir into a fresh state directory
(APFS copy-on-write), rewriting the launch config, spawning
`mvm-hvf-supervisor`, mapping the saved RAM `MAP_PRIVATE` off the clone,
restoring the vCPU and device frame, and waiting for the supervisor to publish
its pid. Notably flat across runs — the private mapping is lazy, so the restore
does not read 512 MiB before the guest runs.

## What this is not

**Restore is not the warm-launch path, and this work does not change warm-launch
latency.** HVF's fast launch is resident handoff: a live, paused standby parent
handed to a child identity in place, measured at 18.9 ms p50 dispatch on this
machine. A checkpoint restore is ~36× that, and structurally must be — it starts
a new VMM against bytes on disk, where a handoff transfers a process that is
already running and never leaves memory.

The two answer different questions. Handoff answers "start this workload now".
A checkpoint answers "put this exact machine, with this exact memory, back —
tomorrow, on a different boot of the host, with a signed record of where it came
from". Plan 255's fork lineage needs the second and cannot be built on the first.

## Reproducing

```sh
cargo build --release --bin mvmctl
cargo build --release -p mvm-hostd --bin mvm-hvf-supervisor --bin mvm-host-agent \
  --bin mvm-broker --bin mvm-host-signer --bin mvm-audit-signer \
  --bin mvm-substitution-endpoint --bin mvm-netd --bin mvm-signer-helper

./target/release/mvmctl machine run --image alpine --name hvf-ckpt-demo -d
./target/release/mvmctl machine checkpoint create --class vm-full hvf-ckpt-demo --json
./target/release/mvmctl machine stop hvf-ckpt-demo --yes
./target/release/mvmctl machine checkpoint restore <id>
```

## One environmental caveat, recorded because it is easy to misread

On a long-lived developer `~/.mvm`, `mvmctl trust audit verify` may already fail
(`malformed envelope at line 3` on this machine, from accumulated dev history).
`SignedChainAnchor::load` refuses to anchor anything from a chain it cannot
verify, so on such a host **every** checkpoint reads as un-audited and both
`checkpoint verify` and `checkpoint restore` fail closed — which is the gate
working, not a regression. The restore timings above were taken after moving the
broken pre-existing chain aside so a fresh, verifiable one was written. The same
condition breaks `checkpoint verify` on `main` today, independently of this
change.
