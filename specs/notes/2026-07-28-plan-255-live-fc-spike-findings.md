# Live Firecracker spike — findings

De-risking run before implementing `specs/plans/255-live-fc-warm-claim.md`.
The plan's rescope to memory restore rests on assumptions that had never been
checked on real hardware, and the implementer works on macOS where no
Firecracker path is executable. This is what the box actually says.

**Host:** Linux 6.8.0-124-generic, 8 cores, 62 GB RAM, Firecracker **v1.14.1**,
`/dev/kvm` present. Build: `a14432a02` (includes the warm-pool adoption commit
`1c847f458`), **release** profile, musl target installed so `build.rs` embedded
the host-vm binaries for real rather than stubbing them.

## 1. Memory restore works live — 60 ms, release build

`cargo test --release -p mvm-runtime --lib -- --ignored warm_restore_latency_live`

```
[mvm] Firecracker started.
[mvm] Firecracker started.
WARM_RESTORE_MS=60
test vm::instance_snapshot::tests::warm_restore_latency_live ... ok
```

The round trip — boot a source Firecracker VM, `create_snapshot` (pause + `PUT
/snapshot/create` producing `vmstate.bin` + `mem.bin`), kill the source, then
`guarded_load_resume` into a fresh VMM — **completes and resumes**, passing the
no-NIC device-model guard on real hardware. This is the load-bearing assumption
behind the plan's rescope, and it holds.

**This is the first release-build restore latency recorded anywhere in the
repo.** Prior evidence was a qualitative "tens of milliseconds" plus a ~60 ms
*debug* figure.

### The number is more interesting than it looks

Plan 265 attributes its ~60 ms debug figure to "per-call `curl` subprocesses and
a fresh Firecracker spawn per restore". Release measures **the same 60 ms** — so
that overhead is **structural, not compilation-related**. Optimizing the restore
path (its WS2 pre-spawned-VMM item, and replacing the `curl` subprocess calls)
is therefore the whole distance between 60 ms and the ≤30 ms SLO. Compiler
optimization contributes nothing.

That is a useful, non-obvious result for Plan 265, and it is why this slice
deliberately does not attempt the SLO: the remaining cost is not in the code
this slice writes.

## 2. The full checkpoint→fork path is still unproven live

The test exercises `FirecrackerIO::create_snapshot` + `guarded_load_resume` —
the layer *beneath* what the plan calls. It does **not** exercise
`capture_vm_full` (which adds the rootfs clone inside the pause window, the
sidecars, and `device-anchors.json`) or `FcForkRestorer::restore_fork` (the
`memory.bin` → `mem.bin` rename plus anchor remap).

Corroborating: `~/.mvm/checkpoints/` on the box is **empty** — no checkpoint has
ever been captured on this host. Those two functions have most likely never run
end to end on real hardware.

Consequence: Task 4's capture and Task 3's restore delegation remain the
slice's genuine unknowns. The mechanism they sit on is now proven; their own
wiring is not. Task 7 must exercise them explicitly rather than inferring from
this result.

## 3. A relay-less parent boot is still untested

The live test boots a generic rootfs with no mvm guest agent, so it says nothing
about whether a factory parent — no workload, therefore no egress relay wired,
`trusted_builder: false` — survives the guest's egress gate. That risk is
unchanged and cannot be spiked cheaply, because booting a real mvm parent *is*
Task 2. The mitigation stands: if the gate refuses, wire the parent a minimal
vsock egress port; never flip `trusted_builder`, which would disable the egress
gate on workload-bearing content.

## 4. The CLI exposes no checkpoint / pool / trust verbs

Top-level surface is `machine, build, kernel, init, doctor, prepare, explain,
pack, ls, bootstrap`. `commands/vm/checkpoint.rs` compiles in (no feature gate)
but is internal machinery, not a user-facing verb.

Consequence for Task 7: live validation goes through **`mvmctl machine run`**,
whose transient path calls `try_warm_claim` (`exec.rs`), plus the Rust live-test
harness — not a `checkpoint fork` command. There is no user-facing way to
inspect or drive the pool directly, so any fail-closed case that cannot be
reached from `machine run` needs a harness test instead.

## Verdict

Proceed with the plan as rescoped. The mechanism it depends on is proven on real
hardware; the remaining risks (parent boot under the egress gate, the
capture/restore wiring) are the tasks' own work rather than premise failures,
and each has a stated mitigation. Task 7 is retargeted onto `machine run` + the
harness.

## Reusable setup on the box

- Checkout: `/root/mvm-spike-livefc` (detached at `a14432a02`), release binary at
  `target/release/mvmctl`. Kept clear of the other sessions' `/root/mvm`,
  `/root/mvm-plan265`, `/root/mvm-plan255-*`.
- Live-test images: `MVM_LIVE_KERNEL=/root/microvm/vmlinux-5.10.245`,
  `MVM_LIVE_ROOTFS=/root/microvm/ubuntu-24.04.ext4`.
- The musl target had to be installed (`rustup target add
  x86_64-unknown-linux-musl`) before `crates/mvm-cli/build.rs` would build the
  embedded host-vm binaries. The former skip-embed switch did **not** exist in
  `build.rs`, despite being referenced in the contributor docs.
