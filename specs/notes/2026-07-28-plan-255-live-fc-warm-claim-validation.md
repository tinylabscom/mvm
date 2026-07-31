# Plan 255 — live Firecracker warm-claim validation (KVM host)

Date: 2026-07-28

Outcome, as of the third run: **PARTIAL — the spawn+capture half of the warm
pool is proven live on real Firecracker/KVM hardware; the claim half is still
unexercised, and four blockers gate the capability flip. `standby_pool` stays
`false`.**

This is the empirical gate for the Firecracker warm pool built in Tasks 1–6.
Everything below is a command that was actually run on real hardware plus its
real output. Where a check could not be run, that is stated rather than
inferred.

It is written **chronologically**: three live runs on the same host, in order,
plus the structural blockers review found between them. Earlier conclusions are
left standing where a later run superseded them, annotated in place — the
sequence of what was believed, what was fixed, and what the fix did *not* fix is
the point of the record.

| Run | Commit | Result |
|---|---|---|
| 1 | `3879db5c3` | **FAILED.** The parent boots a bare rootfs, finds no guest agent, kernel-panics. Capture never runs. |
| 2 | `03dcf3aa5` (overlay attached to the parent) | **FAILED.** Necessary but not sufficient: nothing in that boot mode mounts the overlay. |
| 3 | `3ac531193` (parent boots the verified-boot shape) | **Parent boots, reaches its agent, capture writes a 512 MiB `memory.bin`.** Claim half still unreachable (BUG-2). |

## Host

| | |
|---|---|
| Host | Hetzner bare metal, `88.99.197.234` |
| Kernel | `Linux 6.8.0-124-generic #124-Ubuntu SMP PREEMPT_DYNAMIC Tue May 26 13:00:45 UTC 2026 x86_64` |
| Firecracker | `Firecracker v1.14.1` |
| `/dev/kvm` | `crw-rw---- 1 root kvm 10, 232 Jul 29 01:47 /dev/kvm` |
| Checkout | `/root/mvm-spike-livefc`, detached at `3879db5c3` (`feat(fc): advertise the standby pool now that spawn and claim are live`), working tree clean |
| Binary | `/root/mvm-spike-livefc/target/release/mvmctl` — **release**, pre-built, not rebuilt |
| Guest kernel | `.../cache/builder-vm/x86_64/kernels/workload/vmlinux`, sha256 `607e4033829fed08ae12e5554ab9c9403811dd02d4b1cad7d89fd1d64772a2d6` |
| Isolated state | `MVM_HOME=/root/mvm-t7-home` (a `cp -a` of `/root/.mvm/cache`, so no other session's state was touched) |
| Image | `docker.io/library/alpine:latest` → `sha256:79ff19e9084a00eece421b2523fb93e22d730e2c0e525905de047e848e56d95f` (already in the OCI cache) |

`/root/.mvm/checkpoints/` was empty before this work and `<MVM_HOME>/checkpoints/`
was **never created** during the first two runs — see "What was NOT reached".
The third run is where that changed.

One environment note: the guest agent had to be rebuilt once for this
checkout's guest fingerprint (`0.18.0-guest-447f29460cdf25e3`), which needs
`cargo` on `PATH` (`export PATH=/root/.cargo/bin:$PATH`). Without it the very
first run fails with `cargo-zigbuild failed: spawn cargo: No such file or
directory`. `mvmctl` itself was not rebuilt.

---

# First live run — the parent panics

Outcome as recorded at the time: **FAILED — the warm pool cannot populate on a
real Firecracker/KVM host at this commit.**

## Result summary

*(as recorded after run 1; rows 1 and 2 were partly superseded by the third run
below, where the capture did complete.)*

| # | What was to be established | Result |
|---|---|---|
| 1 | `capture_vm_full` → `FcForkRestorer::restore_fork` end to end | **NOT REACHED.** The standby parent kernel-panics before its agent starts, so capture never runs. *(Superseded: the capture half completed on run 3; `restore_fork` is still unreached.)* |
| 2 | Restored child answers post-restore handshake `acknowledged`+`reseeded`+`clock_resynced` | **NOT REACHED.** No checkpoint exists to restore from. *(A checkpoint exists as of run 3; the handshake is still unreached, blocked on BUG-2.)* |
| 3 | Fresh child VM name, no kernel boot in the child console | **NOT REACHED.** |
| 4 | Cold-boot vs warm-claim timing | **Cold measured; warm not measurable.** |
| 5 | Fail-closed cases | **1 of 3 verified live** (absent `parent_checkpoint` → refuse + cold-boot, no orphaned child dir). The other two need a real captured checkpoint. |

Two defects were found by the run itself — BUG-1 and BUG-2 — and neither was
fixed during it (the task was validation only; BUG-1 has since been fixed in
code and re-validated live, see the third run). Two further structural blockers,
BLOCKER-3 and BLOCKER-4, were found by review of that fix and are recorded here
because they gate the same capability flip. Both are open.

---

## BUG-1 — the standby parent boots without the runtime overlay and panics

> **Fixed in code, and the fix is live-proven on the third run below.** The
> parent's boot inputs are now derived from the launch's own `VmStartConfig`
> through the same mappers a workload boot uses, and host-side guards assert the
> two shapes are equal. The capability still stays `false` — the *claim* half has
> never run. Everything below is the record of the failing run, unchanged.

**The blocker.** `MVM_RESIDENCY=warm` does reach the feature: `replenish_after_launch`
fires and `FcDriver::spawn_standby_parent` boots a parent. The parent then dies.

```
$ export PATH=/root/.cargo/bin:$PATH
$ export MVM_HOME=/root/mvm-t7-home
$ export MVM_RESIDENCY=warm
$ ./target/release/mvmctl -v machine run --image docker.io/library/alpine:latest \
      --hypervisor firecracker echo hello-from-guest
...
[mvm] Booting transient VM 'happy-pika-0b5b'...
[mvm] Starting Firecracker...
[mvm] Firecracker started.
[mvm] Starting Firecracker...
[mvm] Waiting for API socket...
[mvm] Firecracker started.
 WARN FirecrackerGuard: killing orphaned Firecracker process dir=/root/mvm-t7-home/vms/standby-5aafc4607e89b3dc
 WARN spawn standby failed; pool stays under target error=spawn standby: boot standby parent: Firecracker process for 'standby-5aafc4607e89b3dc' exited before its guest agent came up; see /root/mvm-t7-home/vms/standby-5aafc4607e89b3dc/console.log
Error: Failed to read frame length

Caused by:
    failed to fill whole buffer

real	0m4.536s
```

The standby's own console says why:

```
$ grep -a -n "Run /init\|no guest agent\|Kernel panic\|Rebooting" \
      /tmp/t7standby/standby-ac8b1224e1b65dba/console.log
260:[    0.915735] Run /init as init process
261:mvm-oci-init: no guest agent resolv[e d   f r0o.m9 1/8m3v0m4/] Kreurnnteilm ep aannidc  n-o  nbot syncing: Attempted to kill init! exitcode=0x00000100
283:[    0.930908] Rebooting in 1 seconds..
```

(the interleaving is netconsole double-writing; the two messages are
`mvm-oci-init: no guest agent resolved from /mvm/runtime` and
`Kernel panic - not syncing: Attempted to kill init! exitcode=0x00000100`.)

### Root cause

The workload launch path calls `attach_runtime_overlay_if_cached` before
`backend.start`; `spawn_standby_parent` does not. The contrast is visible in
the two VMs' Firecracker configs.

Workload VM — four drives, overlay attached, verity + overlay cmdline tokens:

```
$ grep -a -o "drive_id[^}]*" /root/mvm-t7-home/vms/t7cap/firecracker.log
drive_id\": \"blk0\", \"path_on_host\": \".../rootfs.ext4\",   \"is_root_device\": true,  \"is_read_only\": true
drive_id\": \"blk1\", \"path_on_host\": \".../rootfs.verity\", \"is_root_device\": false, \"is_read_only\": true
drive_id\": \"blk2\", \"path_on_host\": \".../runtime-overlay/0.18.0/x86_64/overlay.ext4\",   \"is_root_device\": false, \"is_read_only\": true
drive_id\": \"blk3\", \"path_on_host\": \".../runtime-overlay/0.18.0/x86_64/overlay.verity\", \"is_root_device\": false, \"is_read_only\": true

$ grep -a -o "boot_args[^,]*" /root/mvm-t7-home/vms/t7cap/firecracker.log | head -1
boot_args\": \"console=ttyS0 reboot=k panic=1 net.ifnames=0 mvm.roothash=ed9f51dd… mvm.data=/dev/vda mvm.hash=/dev/vdb mvm.runtime_roothash=a20d91ed… mvm.runtime_data=/dev/vdc mvm.runtime_hash=/dev/vdd mvm.runtime_source_policy=required_overlay mvm.verb_grant=…
```

Standby parent — one drive, no overlay, base bootargs only:

```
$ D=/tmp/t7standby/standby-ac8b1224e1b65dba
$ cat $D/mode.json
{"mode":"detached","accessible":true,"rootfs_path":".../rootfs.ext4","runtime_source_policy":"rootfs_only"}

$ grep -a -o "drive_id[^}]*" $D/firecracker.log
drive_id\": \"blk0\", \"path_on_host\": \".../rootfs.ext4\", \"is_root_device\": true, \"is_read_only\": true

$ grep -a -o "boot_args[^,]*" $D/firecracker.log | head -1
boot_args\": \"console=ttyS0 reboot=k panic=1 net.ifnames=0 root=/dev/vda rw rootwait init=/init\"}".
```

The code that produces this is `FcDriver::spawn_standby_parent`
(`crates/mvm-runtime/src/driver/fc.rs`), which builds its `VmmSpec` with
`cmdline: self.workload_base_bootargs(false, true)` and a single
`BlockDev { source: image, read_only: true, slot: 0 }`.

This is fatal on the current overlay-only runtime: the runtime overlay is the
single source of the guest binaries, and every cached OCI rootfs on this host
is overlay-lean —

```
$ grep -h "runtimeLean" /root/.mvm/cache/oci/rootfs/*/mvm-meta.json | sort | uniq -c
     22   "runtimeLean": true
```

— so the parent's rootfs contains no `mvm-guest-agent` for `/init` to exec.
`boot()` never returns, the parent is killed, and `spawn_standby_captured`
never gets to call `capture_vm_full`.

Note also that `spawn_standby_parent`'s comment claims "`boot` returns only
once the guest agent answered over vsock" while passing `vsock: Vec::new()`.
That turns out to be harmless — `fc_config_api_puts` configures `vsock0`
unconditionally, confirmed in both VMs' logs (`"vsock_id": "vsock0"`) — but
the spec field is misleading.

### Consequence

```
$ ls -la /root/mvm-t7-home/checkpoints
ls: cannot access '/root/mvm-t7-home/checkpoints': No such file or directory

$ ls -la /root/mvm-t7-home/pool/
-rw-r--r--  1 root root    0 Jul 29 02:04 claim.lock
-rw-r--r--  1 root root    0 Jul 29 02:04 warm.lock
```

No checkpoint is ever written, no standby is ever registered, so `try_warm_claim`
can never find a candidate and the claim half of the feature is unreachable
through any CLI path.

`mvmctl machine checkpoint create <vm> --class vm-full` (the hidden CLI verb) is
**not** an alternate route to `capture_vm_full` on Firecracker — it is gated by
the coarse snapshot tier, which the FC driver deliberately reports as
unsupported:

```
$ ./target/release/mvmctl -v machine checkpoint create t7cap --class vm-full --json
Error: vm save requires memory-snapshot support, but backend 'firecracker' reports snapshot tier 'unsupported' on this host
```

That gate is intentional (`FcDriver::capabilities` says the standby
capture/restore pair is "a distinct seam from the coarse
`snapshots`/`snapshot_capability` tier"), but it means the warm-pool spawn is
the *only* caller of `capture_vm_full` on Firecracker — and it is broken. The
two are mutually blocking.

---

## BUG-2 — the transient `machine run` path mints no verb-grant sidecar, so the guest agent refuses every control connection

Independent of the pool, the transient run itself cannot complete a guest RPC
on this branch.

```
$ ./target/release/mvmctl machine run --image docker.io/library/alpine:latest \
      --hypervisor firecracker echo hello-from-guest
[mvm] Firecracker started.
Error: Failed to read frame length

Caused by:
    failed to fill whole buffer
```

Capturing the transient VM's state dir before teardown shows the guest side:

```
$ ls /tmp/t7keep/happy-badger-b9f0/
console.log  fc.pid  fc.socket  firecracker.log  mode.json
plan.json  plan.json.tmp  runtime  substitution-endpoint.sock
substitution-env.json  substitution.pid        # <- no verb-grant.json

$ grep -c "host_signer_pub" /tmp/t7keep/happy-badger-b9f0/console.log
0

$ grep -a "guest-agent" /tmp/t7keep/happy-badger-b9f0/console.log | tail -4
mvm-guest-agent: entrypoint validated at /usr/lib/mvm/wrappers/oci-entrypoint (held open for fexecve)
mvm-guest-agent: rejecting control connection without a pinned host key
mvm-guest-agent: rejecting control connection without a pinned host key
mvm-guest-agent: rejecting control connection without a pinned host key
```

Chain of causation, each link observed:

1. `host_signer_pub_cmdline_token` returns `None` unless
   `<state_dir>/verb-grant.json` exists, so no `mvm.host_signer_pub=` token
   reaches the guest.
2. Since `7db2d677d` ("Enforce authenticated encrypted vsock control", #1834,
   2026-07-24 — which predates this branch's merge base `a14432a02`), the guest
   agent refuses **every** control connection without a boot-pinned host-signer
   key.
3. The transient path persists the plan with `plan_persist::write_plan`, which
   writes only `plan.json`. The persistent path uses
   `stash_plan_for_bridge`, which additionally runs `mint_verb_grant_sidecar`.

`--agent-verb` reaches the *plan* on the transient path but not the sidecar:

```
$ python3 -c "import json; p=json.load(open('/tmp/t7keep/happy-badger-b9f0/plan.json')); print(p['agent_verbs'])"
['run-entrypoint']
```

The persistent path proves the transport itself is healthy — with a sidecar
present the authenticated session completes and a verb is refused at the
application layer, not the framing layer:

```
$ ./target/release/mvmctl machine run -d --name t7dbg3 --agent-verb ping \
      --image docker.io/library/alpine:latest --hypervisor firecracker
started machine t7dbg3

$ ls /root/mvm-t7-home/vms/t7dbg3/ | grep verb
verb-grant.json

$ ./target/release/mvmctl machine exec t7dbg3 -- echo hello
Error: verb exec not authorized by the session's verb grant
```

Ruled out: cmdline truncation. It was the first hypothesis (the branch predates
main's `5611c280c` base64 envelope and `9a63a86a9` truncation refusal), but the
guest reaching `authenticated control handshake failed` rather than
`rejecting control connection without a pinned host key` on the sidecar-bearing
boots proves the anchor *did* arrive intact at ~1.9 kB of boot args.

This bug is not attributable to Plan 255 — the guest-side requirement landed
before this branch existed — but it independently blocks the transient
`machine run` entry point that the warm claim hangs off, so it must be fixed
before a live claim can ever be observed.

---

## What WAS verified live (run 1)

### Warm pool is genuinely reachable from the CLI

`MVM_RESIDENCY=warm` on an unnamed transient `machine run` does drive
`replenish_after_launch` → `spawn_standby_parent`. The wiring works; the
parent boot is what fails.

### Fail-closed: a standby with no `parent_checkpoint` is refused

Seeded a pool fixture by hand (there is no CLI verb to create one):

```
$ cat /root/mvm-t7-home/pool/standby-fixture-nocheckpoint/standby.json
{
  "id": "standby-fixture-nocheckpoint",
  "template_id": null,
  "control_socket": "/root/mvm-t7-home/pool/standby-fixture-nocheckpoint/control-fixture.sock",
  "pid": 0,
  "kernel_sha256": "607e4033829fed08ae12e5554ab9c9403811dd02d4b1cad7d89fd1d64772a2d6",
  "vcpus": 2,
  "mem_mib": 512,
  "binding_nonce": "0000000000000000000000000000000000000000000000000000000000000001",
  "spawned_unix_secs": 1785283967,
  "state": "idle",
  "image_sha256": null,
  "parent_checkpoint": null
}
```

Then a warm run:

```
$ MVM_RESIDENCY=warm ./target/release/mvmctl -v machine run \
      --image docker.io/library/alpine:latest --hypervisor firecracker echo hi
 WARN cold-booting standby=standby-fixture-nocheckpoint error=standby 'standby-fixture-nocheckpoint' was never captured to a checkpoint
 WARN spawn standby failed; pool stays under target error=spawn standby: boot standby parent: …

$ ls -la /root/mvm-t7-home/pool/          # fixture removed, only the locks remain
-rw-r--r--  1 root root    0 Jul 29 02:04 claim.lock
-rw-r--r--  1 root root    0 Jul 29 02:04 warm.lock

$ ls -la /root/mvm-t7-home/vms/           # no orphaned child dir from the refused claim
drwxr-xr-x  3 root root 4096 Jul 29 02:13 standby-6eb042d1b9f4326a   # the failed *spawn*, not a claim child
```

So: the claim refuses rather than cloning unverified content, the spent standby
is evicted so the next launch does not retry it, and the refused claim leaves no
child directory behind. The only directory left is the failed spawn's own
parent dir, which the next launch's orphan reaper collects
(`[mvm] Reaped 1 orphaned VM helper(s) left by a prior run.`).

The other two fail-closed cases — a corrupted captured checkpoint, and a clone
stripped of its memory image — **were not run**. Both require a real captured
checkpoint, which BUG-1 prevents. The guards exist in
`FcDriver::fork_standby_child` (it refuses a child dir with neither
`memory.bin` nor `mem.bin`), but that is a code reading, not a live result.

---

## Timings

Release binary, alpine:latest from cache, 2 vCPU / 512 MiB, wall-clock of the
whole `mvmctl` invocation.

**Cold boot to guest-agent-ready** (`machine run -d --name …`, which returns only
after the agent answered over vsock — the working path), 7 reps:

```
rep 1 rc=0 ms=2212
rep 2 rc=0 ms=2079
rep 3 rc=0 ms=2096
rep 4 rc=0 ms=2085
rep 5 rc=0 ms=2186
rep 6 rc=0 ms=2079
rep 7 rc=0 ms=2253
```

median **2096 ms**, range 2079–2253 ms (spread 174 ms).

**Warm claim to ready: not measurable.** No standby can be captured, so no claim
ever runs. There is no number to report and none is invented here.

**Cost of the broken replenish.** The same failing transient run, with and
without `MVM_RESIDENCY=warm`, 5 reps each:

| | reps (ms) | median |
|---|---|---|
| residency unset | 2418, 2387, 2268, 2268, 2372 | 2372 ms |
| `MVM_RESIDENCY=warm` | 5106, 4866, 4999, 4261, 5494 | 4999 ms |

Turning the warm pool on currently adds ~2.6 s (median) to **every** run and
returns nothing, because each launch boots a standby parent that panics.

### On the sub-30 ms target

Nothing here measures the claim path, so this run says nothing about the 30 ms
SLO. What it does show is the floor the surrounding machinery sits on: a
2.1 s cold boot-to-ready, of which the guest itself reaches
`mvm-guest-agent: control plane ready (1ms)` about 0.9 s into its own boot —
the rest is host-side process start, OCI cache resolution, plan
synthesis/sign/verify, and the Firecracker API configuration sequence. Those
costs are structural to the current design (per-call `curl` subprocesses, a
fresh Firecracker spawn per VM) and are unchanged by this work. **Closing the
gap to sub-30 ms is a separate effort from making the warm claim correct**, and
neither of the two defects above is a latency problem.

One of those two structural costs has since moved on `main`: the per-call
`curl` subprocesses were replaced with direct Firecracker API calls. The
measurements above predate that change and were not re-taken.

## Reproduction

```sh
ssh -i ~/.ssh/hetzner-rvproxy root@88.99.197.234
export PATH=/root/.cargo/bin:$PATH
export MVM_HOME=/root/mvm-t7-home
export MVM_RESIDENCY=warm
cd /root/mvm-spike-livefc
./target/release/mvmctl -v machine run --image docker.io/library/alpine:latest \
    --hypervisor firecracker echo hello-from-guest
cat /root/mvm-t7-home/vms/standby-*/console.log
```

Test VMs and leaked Firecracker processes under `MVM_HOME=/root/mvm-t7-home`
were cleaned up; other sessions' Firecracker processes were left untouched.

Incidental observation, not chased down: `machine stop <name>` followed by
`machine rm <name>` left the Firecracker process alive in seven of seven
timing reps (`pgrep -af firecracker` showed seven live
`--api-sock /root/mvm-t7-home/vms/t7cold/fc.socket` processes at the end).
The next launch's orphan reaper collects them one at a time.

## Gate list as written after run 1

*(Superseded by "What must happen before `standby_pool` can flip to `true`" at
the end of this note, which adds the two structural blockers review found and
records item 1 as done. Kept because it is what the first run concluded.)*

1. Fix BUG-1: thread the runtime overlay (and the matching
   `mvm.runtime_*` / verity cmdline tokens) into `spawn_standby_parent`'s
   `VmmSpec`, the way the workload launch path does via
   `attach_runtime_overlay_if_cached`. Until then no Firecracker standby can
   boot on an overlay-only runtime.
2. Fix BUG-2, or the transient `machine run` that hosts the claim cannot
   complete a guest RPC at all.
3. Then re-run: priorities 1–3, the two remaining fail-closed cases, and the
   warm-claim timing.

---

# Second live run — after the overlay-attachment fix

Re-run on the same host at `03dcf3aa5` (`fix(fc): boot the standby parent with
the runtime overlay attached`), release build, isolated
`MVM_HOME=/root/mvm-t7b-home` seeded from the shared cache, fresh checkout at
`/root/mvm-t7b`.

**Outcome: still FAILS. The fix is necessary but not sufficient.**

The overlay is now attached correctly — this half is fixed and verified on the
host side:

```
$ grep -a -o "drive_id[^}]*" /root/mvm-t7b-home/vms/standby-af8f47e692da612b/firecracker.log
drive_id\": \"blk0\", ... rootfs.ext4",     "is_root_device\": true,  "is_read_only\": true
drive_id\": \"blk1\", ... overlay.ext4",    "is_root_device\": false, "is_read_only\": true
drive_id\": \"blk2\", ... overlay.verity",  "is_root_device\": false, "is_read_only\": true

$ grep -a -o "boot_args[^,]*" .../firecracker.log | head -1
boot_args\": \"console=ttyS0 reboot=k panic=1 net.ifnames=0 root=/dev/vda rw rootwait init=/init
 mvm.runtime_roothash=996d1500… mvm.runtime_data=/dev/vdb mvm.runtime_hash=/dev/vdc
 mvm.runtime_source_policy=required_overlay\"
```

The guest still dies the same way:

```
$ grep -a -nE "Run /init|no guest agent|Kernel panic" .../console.log
270:[    0.848812] Run /init as init process
271:mvm-oci-init: no guest agent resolved from /mvm/runtime and no baked fallback — refusing to boot without the mvm control plane
272:[    0.851864] Kernel panic - not syncing: Attempted to kill init! exitcode=0x00000100
```

## Root cause (deeper than BUG-1 as first written)

Attaching the drives and threading the tokens is not enough, because **nothing
in this boot mode consumes them**. The `mvm.runtime_*` tokens are parsed by
`mvm-verity-init` (`crates/mvm-agentd/src/bin/mvm-verity-init.rs`), the
initramfs PID 1, which mounts the overlay read-only at `/sysroot/mvm/runtime`.

The parent boots `root=/dev/vda rw rootwait init=/init`, so the kernel mounts
the rootfs directly and runs `mvm-oci-init` instead. That init only *reads*
`/mvm/runtime` (`resolve_guest_agent()`); it never mounts anything. With no
initramfs in the parent's `VmmSpec`, the overlay is attached but unmounted, the
agent is unresolvable, PID 1 exits, and the kernel panics.

The workload path avoids this by booting the verified-boot shape: an initrd, no
`root=`/`init=` in the cmdline (the initramfs owns root selection), and
rootfs-verity drives alongside the overlay.

## What that run concluded

The capability flip is **reverted** — Firecracker again reports
`standby_pool: false`. Advertising the pool while a parent cannot boot would
turn a configured warm pool into a failed spawn on every launch, which is a
worse outcome than not offering it. The capture, fork-restore, CLI wiring, and
overlay attachment all land; the flip returns with the parent's verified-boot
shape.

## Still open after run 2

- The parent must boot the verity/initramfs shape rather than a direct rootfs
  boot — i.e. `spawn_standby_parent` should build its spec through the same
  mapping the workload uses instead of hand-rolling a `VmmSpec`.
  *(Done: that is exactly what the shipped `workload_runner::standby_boot`
  module does, and run 3 proves the resulting boot shape works.)*
- **BUG-2** is unchanged: the transient `machine run` path still ends in
  `Error: Failed to read frame length` (no verb-grant sidecar minted), which is
  independent of the pool.

---

# Third live run — the boot-shape correction works

Re-run at `3ac531193` (`fix(fc): boot the standby parent in the verified-boot
shape`), release, same host, `MVM_HOME=/root/mvm-t7b-home`, checkout
`/root/mvm-t7b`.

**BUG-1 is fixed. The parent boots, reaches its guest agent, and is captured.**
This is the step that was unreachable in both earlier runs.

```
$ grep -anE "Run /init|verity-init|guest-agent" .../standby-*/console.log
274:[    0.358538] Run /init as init process
275:mvm-verity-init: starting
277:mvm-verity-init: rootfs  data=/dev/vda hash=/dev/vdb roothash=6381e8ee…
279:mvm-verity-init: overlay data=/dev/vdc hash=/dev/vdd roothash=996d1500…
320:mvm-guest-agent: listening on vsock port 5252
```

`mvm-verity-init` is PID 1 (not `mvm-oci-init`), it mounts the runtime overlay,
and the agent binds vsock 5252. No `no guest agent resolved` line, no panic.

The capture then ran, and the pool populated for the first time:

```
$ ls -1 /root/mvm-t7b-home/checkpoints
standby-standby-6939ce49e1b69ad2

$ meta.json → class: vm_full
   blobs: rootfs.ext4, memory.bin, vmstate.bin, mvm-meta.json,
          rootfs.verity, rootfs.roothash, device-anchors.json
$ ls -la content/memory.bin
-rw-r--r-- 1 root root 536870912   memory.bin
```

A real 512 MiB memory image — the property that makes a later claim a restore
rather than a cold boot. Prior runs had no `checkpoints/` directory at all and a
pool holding only `claim.lock` / `warm.lock`.

## How to reproduce (note the capability chicken-and-egg)

Task 6 gates the very path Task 7 must exercise: with `standby_pool: false` the
run stops at `firecracker: standby pool is not supported by this backend` and
`spawn_standby_parent` is never reached. To validate, flip the capability
**locally on the test host only** and rebuild:

```
sed -i "s/^            standby_pool: false,/            standby_pool: true,/" \
    crates/mvm-runtime/src/driver/fc.rs
cargo build --release --bin mvmctl
MVM_HOME=… MVM_RESIDENCY=warm ./target/release/mvmctl -v machine run \
    --image docker.io/library/alpine:latest --hypervisor firecracker echo hi
```

Keep the committed default `false` until a live run earns the flip.

## Still blocked: BUG-2

The end-to-end run still fails, for the unrelated reason recorded above — the
transient path mints no verb-grant sidecar:

```
Error: Failed to write frame length
    Broken pipe (os error 32)
# guest side:
mvm-guest-agent: rejecting control connection without a pinned host key
```

So the **capture half is proven live; the claim half remains unexercised through
the CLI** until BUG-2 is fixed. Not verified this run: that the parent process is
released after capture (the check used was malformed and is not evidence either
way).

## Which implementation the evidence backs

Two implementations of the boot-shape correction existed. The one exercised on
the host was an inline `VmmSpec` build inside `FcDriver::spawn_standby_parent`
(commit `3ac531193`). A better-factored version — a
`workload_runner::standby_boot` module exposing `factory_parent_config` /
`factory_parent_spec`, reusing the workload spec mapping instead of duplicating
it — was developed in parallel, and **that is the one that shipped**: it removes
the duplication that caused this bug rather than working around it. `3ac531193`
was dropped rather than merged.

**The evidence above applies to either**, since both produce the same boot shape:
verity initramfs as PID 1, rootfs hash device at slot 1, overlay at slots 2-3 on
`/dev/vdc` + `/dev/vdd`, and no `root=`/`init=` in the cmdline. The shipped
module additionally holds that shape *by construction* — the parent's device
model and cmdline come from the same `workload_device_spec` +
`cmdline::runner_cmdline` mappers a workload boot uses, and host-side tests
assert the two are equal — so the equivalence is a compile-and-test property
rather than two recipes kept in step by hand. It also fails the spawn closed,
naming the missing artifact, when a launch could not reach a guest agent at all
(a required overlay that was never attached, or a sealed rootfs with no
resolvable initramfs), instead of booting a parent that panics the way run 1's
did — and it applies `main`'s kernel-cmdline truncation refusal to the parent as
well as the workload, which matters more here: a child inherits the parent's
cmdline out of restored memory, so trailing tokens the kernel silently dropped
from a parent would be lost to every child it produces.

---

# Blockers found by review, not by any run

Both are structural, both survive BUG-1's fix, and each independently prevents a
claim from completing. Neither was reachable on the host: the claim path has
never run.

## BLOCKER-3 — a restored child has no host-signer anchor, so it cannot be authorized at all

Found by review of the BUG-1 fix, not by the live run. It is not a variant of
BUG-2: BUG-2 is a missing sidecar on one code path, this is a structural
consequence of a shared parent, and it survives BUG-2's fix.

A forked child is not merely *ungranted*; it is **unauthorizable**. Three links,
each a code reading:

1. **The parent boots with no `mvm.host_signer_pub=` token.** `grant_tokens`
   (`crates/mvm-runtime/src/hvf_bootargs.rs:43-52`) is keyed on `config.name`
   and reads the named VM's `verb-grant.json`. A factory parent has no plan and
   therefore no sidecar, so it emits none — correctly, since a parent must hold
   no workload authority. But the child inherits the parent's cmdline out of
   restored memory rather than deriving its own, so the child boots with **no
   pinned host-signer trust anchor**.
2. **Nothing re-pins one after the restore.** The production
   `VsockPostRestoreSignal` hardcodes `grant_envelope: None`
   (`crates/mvm-runtime/src/vm/instance_snapshot.rs:529`), and every host-side
   construction leaves `predecessor_session_id` / `predecessor_plan_nonce_hex`
   at `None`. Those `VerbGrantEnvelope` fields are wired guest-side only.
3. **The guest-side re-pin cannot succeed without an anchor.**
   `re_pin_verb_grant` deliberately verifies a replacement grant against the
   **boot-pinned** anchor rather than against `envelope.pubkey_hex` — otherwise
   any envelope could nominate its own key. With no anchor pinned there is
   nothing to verify against.

Consequence: the child rejects the PostRestore RPC, `require_fresh_child_identity`
refuses it, `claim_standby` returns `ClaimFailed`, and the launch cold-boots.
Fail-closed — there is no security hole here — but the warm claim is
**structurally unreachable** even after BUG-1 and BUG-2 are fixed.

Suggested shape, recorded but **not implemented** (it is its own slice, and
guessing at it inside a boot-shape fix is how BUG-1 happened): the host-signer
public key is *host identity*, not *workload authority*. Pinning
`mvm.host_signer_pub=` on the factory parent while still withholding
`mvm.verb_grant=` and `mvm.require_grant=` would give every child a trust anchor
without giving the parent any authority — the parent still holds no plan, no
grant, and no verbs. With an anchor present, the natural completion is to carry
a replacement grant over the PostRestore signal using the already-defined
`predecessor_session_id` / `predecessor_plan_nonce_hex` fields, so the child
re-pins to its own admitted plan at claim time. Note that pinning the anchor on
the parent is itself a cmdline change and so must go through the same
`factory_parent_config` / `workload_device_spec` path, with the shape-equality
guards updated to match.

## BLOCKER-4 — a warm-claimed child is wired none of the host channels a cold boot gets

Found by review, not by the live run: the claim path was never reached, so
nothing here was observable on the host. Like BLOCKER-3 it is structural, and it
survives BUG-1, BUG-2 and BLOCKER-3 all being fixed.

A cold boot's host-side vsock wiring happens in exactly two places, and a warm
claim goes through neither.

1. **The guest-dial bridges and the exit capture are `boot`-only.**
   `wire_guest_dial_bridges` and `spawn_workload_exit_capture` are called from
   one site each — `FcDriver::boot`
   (`crates/mvm-runtime/src/driver/fc.rs:580-581`). The claim path runs
   `FcDriver::fork_standby_child` (`fc.rs:495`) →
   `FcForkRestorer::restore_fork` (`crates/mvm-runtime/src/firecracker.rs`),
   which remaps the snapshot's baked-in device paths and resumes the VM. It
   does neither.
2. **The claim spawns the child's endpoint and then drops its address.**
   `claim_standby` stands up the child's own substitution endpoint
   (`crates/mvm-runtime/src/workload_runner/runner.rs:426-437`) but never
   threads the returned `egress_uds()` anywhere, and never calls
   `BrokerRegistrar::register`. Contrast `start_workload` (`runner.rs:322-348`),
   which does both: the endpoint's socket becomes the spec's `egress_gateway`,
   and the broker is registered for the booted VM.

What a claimed child would therefore come up with, once the pool is armed:

- **no `v.sock_<EGRESS_PORT>` symlink**, so the endpoint process the claim just
  spawned is dark — the guest's egress client dials a socket nothing serves;
- **no `v.sock_<BROKER_PORT>`**, so `host.audit.v1` and `host.secrets.v1` are
  silently unavailable to the workload — a *degradation relative to a cold
  boot*, which registers the broker;
- **no `v.sock_<WORKLOAD_EXIT_PORT>` listener**, so `workload.exit` is never
  written and `machine run` reports UNKNOWN instead of the guest's real exit
  code.

All three fail closed — an unwired channel is an unreachable channel, and no
isolation boundary moves — so none of this is a security hole. But a warm claim
that hands back a child with strictly less than a cold boot gives it is not a
fast path; it is a different and worse one.

**Not implemented here**, deliberately: the shape is to lift the host-channel
wiring out of `FcDriver::boot` so the fork path runs the same step, and to give
`claim_standby` the tail of `start_workload` it is missing. Both are their own
slice, and guessing at either inside a records-and-comments pass is how BUG-1
happened.

---

# Two further defects, found by review and fixed alongside BUG-1

Neither needs a separate live gate — but both are worth knowing about when
reading the pool code:

- **The compat key never matched.** The spawn recorded
  `image_sha256: Some(sha256(rootfs))` while the claim computed `None`
  unconditionally, and `StandbyHandle::is_compatible` is exact equality — so
  every claim silently cold-booted while the pool filled and never drained. It
  was masked in run 1 because the hand-seeded fixture in "Fail-closed" above
  carried `image_sha256: null`, which is why *that* one was selected. Both
  halves now build the key through one function (`compat_for_launch`), keyed on
  the same digest claim-8 admission puts on `plan.image.sha256` and that
  `bind_plan_to_parent` checks the captured parent against.
- **`mvm.vsock_egress=1` was a second cmdline divergence.** A factory parent was
  deny-all by construction, so a launch with `--network-allow` would boot the
  workload with the token and the parent without it — and a child inheriting the
  parent's cmdline would come up with no network, silently. Such launches were
  first excluded from the warm pool at both ends (claim and replenish) rather
  than served with the wrong shape.

  **Since resolved by keying instead of excluding.** The exclusion assumed the
  parent could not carry the launch's egress without leaking that launch's shape
  to the next claim. The token is a bare boolean — no host, no allow-list reaches
  the guest — and the destination set is resolved host-side per child, on the
  egress endpoint the claim wires from that child's own launch config. So the pool
  partitions on egress **enablement** alone:
  `StandbyCompat::vsock_egress` makes a parent claimable only by launches whose
  guest boots the same way, `factory_parent_config` takes that enablement from the
  matched record (`spec.vsock_egress`) and carries no destination, and
  `warm_eligible_launch` no longer refuses the shape. The key is the *effective*
  enablement (`egress_shared::effective_vsock_egress`: the policy allows egress
  **and** the admitted plan binds no secret), which is the same condition the token
  itself is derived from — so a secret-bearing launch keys token-less exactly as
  its cold boot boots, and the key can never be more permissive than the cold boot
  it stands in for.

---

# What must happen before `standby_pool` can flip to `true`

The current gate list, superseding the run-1 list above. In order; each is a
hard gate.

1. **BUG-1 — fixed in code and confirmed live.** The parent's boot inputs now
   come from the launch's own `VmStartConfig` through the same mappers a
   workload boot uses. The third run confirms on the KVM host that the parent
   reaches agent-ready and `capture_vm_full` writes a memory-carrying
   checkpoint.
2. **BUG-2 — open.** Without a verb-grant sidecar on the transient `machine run`
   path there is no guest RPC at all, so the run that hosts the claim cannot
   complete. Pre-existing; fix outside this slice.
3. **BLOCKER-3 — open.** Without a boot-pinned host-signer anchor on the child,
   the post-restore identity handshake refuses and every claim falls back to a
   cold boot. Structural; fix outside this slice, along the shape above.
4. **BLOCKER-4 — open.** A claimed child is wired none of the host channels a
   cold boot gets: no egress socket for the endpoint the claim itself spawned,
   no broker registration, no exit capture — so it has no `host.audit.v1` /
   `host.secrets.v1` and its exit code is never reported. Fail-closed, but
   strictly worse than the cold boot it replaces. Structural; fix outside this
   slice, along the shape above.
5. **Deferred, known-sharp: a failed child stop leaves an invisible live VM.**
   On the claim refusal path `force_stop` logs and swallows a failure
   (`crates/mvm-runtime/src/workload_runner/runner.rs:462`; the swallow is at
   `:594-605`), and `ClaimCleanup::drop` then removes the child's state dir. A
   stop that fails
   therefore leaves a live Firecracker still holding the parent's CSPRNG with
   **no state dir at all** — invisible to the caller (which sees only
   `ClaimFailed`), invisible to orphan-state-dir reaping, and findable only with
   `pgrep`. Harmless while the pool is disarmed because the path is unreachable,
   so it is not a merge blocker; it must not be armed with this open. The fix is
   to order the removal after a *successful* stop, or to leave a reapable marker
   behind when the stop fails.
6. Only then: re-run the Task 7 priorities (capture → restore, the reseed
   handshake, a fresh child name with no kernel boot in its console, warm vs
   cold timings, and the two fail-closed cases that need a real captured
   checkpoint), and flip the capability only if that run is green.

In short: BUG-1 is fixed and live-proven; BUG-2 and BLOCKER-3 are both open and
each independently prevents a claim from ever completing; BLOCKER-4 lets a claim
complete but returns a child wired none of the host channels a cold boot gets.

---

## Fourth live run (2026-07-30) — capture proven on the full blocker set; claim blocked by a double reservation

Host: Linux 6.8.0-124, Firecracker v1.14.1, `/dev/kvm`, release build of the
four-blocker state (`65a43af1d`). Capability flipped to `true` **on the test host
only**; the committed default stays `false`. Isolated `MVM_HOME=/root/mvm-live-home`
with the runtime-overlay cache symlinked in.

### Capture: works, reproduced on the complete blocker set

`MVM_RESIDENCY=warm mvmctl machine run --image docker.io/library/alpine:latest
--hypervisor firecracker echo hello-live` → workload ran, `EXIT=0`. The log shows
`plan admitted`, then `runtime_source_status="overlay-required"` with
`overlay_attached=true` — the overlay attachment whose absence made the parent
kernel-panic in the second run. `replenish_after_launch` then spawned and captured
a parent:

```
pool/standby-ecee9d16f0fa5f70/standby.json
  state=idle  pid=0  parent_checkpoint=standby-standby-ecee9d16f0fa5f70
checkpoints/standby-standby-ecee9d16f0fa5f70/meta.json
  class=vm_full  blobs=[rootfs.ext4, memory.bin, vmstate.bin, mvm-meta.json,
                        rootfs.verity, rootfs.roothash, device-anchors.json]
  content/memory.bin  536870912 bytes
```

`pid=0` is the release-after-capture the design intends: a pool slot costs disk,
not a resident VM.

### Claim: refused, and the cause is a double reservation

The second identical run refused:

```
WARN standby claim failed; cold-booting standby=standby-ecee9d16f0fa5f70
     error=claim standby: parent is not in a claimable state
```

Two layers each reserve the parent:

- `SupervisorStandbyPool::claim_idle_compatible` (`standby_pool.rs:106`) selects
  **and** reserves — `mark_claimed` at `:115`, `state = Claimed` at `:116`.
- `reserve_and_verify_parent` (`runner.rs:789`) then loads that parent, finds
  `!state.is_claimable()` at `:800`, and refuses `ParentNotClaimable`.

So a warm claim on a runner-backed backend can never succeed. The CLI then removes
the parent as spent and cold-boots, and the next replenish warms a fresh one — the
pool fills and never drains, indefinitely.

Both halves are correct alone. The runner's reserve is the one to keep: it reserves
and verifies inside a single locked section, which is strictly stronger. The CLI
should select without reserving (`select_idle_compatible`, `:92`). Two launchers
can then both select one parent; the runner's lock serializes them and the loser is
refused into a cold boot — the same outcome the CLI-side reservation bought, without
deadlocking the winner.

**Why no test caught it.** The `claim_or_cold` tests drive `AnyBackend::Mock`, whose
`claim_standby` answers from its own in-memory state and never runs the runner's
reserve. The two-layer interaction existed only on a live host.

### Not yet exercised

The post-restore handshake (`acknowledged` + `reseeded` + `clock_resynced`) and the
child's egress/broker/exit channels still have not run: the claim never got far
enough. They remain the open live question after this fix.

### Two incidental findings

- `host-agent registration failed; host.audit.v1 unavailable for this VM — could
  not locate the mvm-host-agent binary (set MVM_HOST_AGENT_PATH)`. This fires on the
  **cold** boot too, so it is an environment gap on this host rather than a claim-path
  defect — but it means broker reachability cannot be judged from this run either way.
- 14 orphaned `firecracker --api-sock /tmp/.tmpXXXX/vms/mvm-forkblank-parent-*`
  processes are alive on the box. That is a test-fixture name, so a live harness leaks
  its parent VMs instead of reaping them; each holds guest memory.

### Timings (not a warm-vs-cold comparison yet)

Run 1 wall clock 173 s, dominated by a runtime-overlay rebuild from source
("source-built cache is stale") plus image work — not a boot measurement. Run 2,
with the overlay cached, was 10.0 s for cold boot + capture + replenish. The earlier
cold-boot-to-agent-ready baseline of 2096 ms median (n=7) still stands as the number
to beat; a warm figure needs the claim to succeed.

---

## Fifth live run (2026-07-31) — the claim finally executes, and fails closed on an un-audited parent

Host: Linux 6.8.0-124, `/dev/kvm`, release build at `main` (`d0ccada18`) plus
the two open boot fixes (#1959, #1961). Capability flipped to `true` **on the
test host only**; the committed default stays `false`. Fully unshared
`MVM_HOME=/root/mvm-live3-home` — **no cache symlink**, workload kernel built
into it directly.

### Three boot blockers had to be cleared first

No Firecracker workload could boot at all, and the failures were serial: each
one only became visible once the previous was fixed.

1. **#1945 / #1948 (merged).** `mount_early_filesystems` mounted `/proc`,
   `/sys`, `/dev` without creating them; the universal initramfs ships only
   `init`. PID 1 died on ENOENT and the kernel panicked.
2. **#1957 / #1959.** The host-signer anchor rides the kernel cmdline as
   `mvm.host_signer_pub=<hex>`, but the only code writing it to
   `/run/mvm/host-signer.pub` lived in `mvm-oci-init` — which never runs under
   the universal initramfs, where the agent itself is `/init`. The agent parsed
   no cmdline tokens at all, so it had no pinned key, refused every control
   connection, and the run died at `ActivateEnvironment`, its first RPC.
   *This is BLOCKER-3 in the gate list below, on the boot path.*
3. **#1961.** devtmpfs was mounted only `if !Path::new("/dev/console").exists()`.
   The kernel creates a bare `/dev/console` in the initramfs rootfs so init has
   stdio — which is exactly why agent output reaches the serial console — so the
   guard always skipped the mount. `/dev` then held that one node and dm-verity
   found no `/dev/mapper/control`, failing activation.

With all three, a guest boots and fully activates:

```
mvm-guest-agent: host-signer anchor provisioned from cmdline
mvm-guest-agent: control plane ready (0ms)
mvm-guest-agent: activation complete, serving operational RPCs
```

**A methodology trap worth recording.** The first attempt reproduced the #1945
panic *byte-for-byte against a build that already contained the fix*.
`resolve_or_build_local_initramfs` tries the isolated cache, then
`seed_from_default_cache` — which reads `~/.mvm/cache/initramfs`, a path that
deliberately ignores `MVM_HOME` — and only then runs `nix build`. The initramfs
cache is keyed on `(version, arch)` **only**, never on guest-agent source, so an
unshared `MVM_HOME` silently re-imported a pre-fix initramfs (both `init`
binaries hashed `e500f3cf…`). Clearing *both* caches forced a real build
(`7c5f4152…`). Same family as the workload-kernel staleness, but by design, so
`MVM_HOME` discipline alone does not avoid it. Filed as a secondary finding on
issue #1957.

### The claim executes for the first time — and is refused

With an idle, compat-matching parent in the pool:

```
DEBUG machine run warm-pool eligibility mode=Transient warm_pool_size=1
WARN  standby claim failed; cold-booting
      standby=standby-6702024cb03918fe
      error=claim standby: parent has no signed audit entry;
            refusing to fork an un-audited parent
```

This clears BUG-2 and the double-reserve as claim blockers: eligibility opens,
`select_idle_compatible` **finds** the parent (so the compat key matches), and
the refusal now comes from parent verification — strictly further than any
previous run reached.

**Root cause (issue #1962): no parent is ever audited at spawn.**
`reserve_and_verify_parent` verifies the parent's checkpoint against the signed
audit chain; the anchor looks for a `checkpoint.created` entry. Nothing on the
spawn path emits one — `bind_checkpoint_created` has exactly one production
caller, the user-facing checkpoint command, and `SpawnContext`
(`workload_runner/runner.rs:283`) carries only `checkpoints` and `launch`, with
no `AuditEmitter` and no `ExecutionPlan` to emit *with*. Confirmed against the
live chain: 78 entries across three cycles, zero `checkpoint.created`.

So **every** captured parent is unclaimable by construction. Both sides are
individually correct — refusing to fork an un-audited parent is exactly right
for claim 8 — and nothing carries the anchor across the seam.

**Secondary effect: the pool churns.** On verification failure the parent is
quarantined by removal, then replenish spawns a fresh one, so every launch pays
a wasted boot + capture and the pool never converges. The standby id rotates
each run while `idle` stays pinned at 1:
`7e386f9d…` → `6702024c…` → `8ae4af1f…`.

**Observability gap.** `try_warm_claim` returns `Ok(None)` from four gates with
no log, and `claim_or_cold` cold-boots silently when selection finds nothing.
The one informative path is a `tracing::warn!` that default CLI verbosity does
not surface — so at default settings a claim that never happens is
indistinguishable from one never attempted. This is why the previous runs could
not tell the two apart. Worth logging the claim decision where operators see it.

### Cold boot to activation — measured, 10 reps

`machine start` returns once the guest reports activation complete, so this
brackets kernel boot + PID-1 early setup + anchor provisioning + dm-verity
rootfs + activation. 10/10 reached `activation complete`, `rc=0`.

```
1766 1775 1775 1808 1817 1858 1859 1877 2027 2119   (ms, sorted)
min 1766 · median 1837.5 · p90 2027 · max 2119 · mean 1868.1 · spread 353
```

Median 1837.5 ms against the 2096 ms baseline recorded earlier — same order,
~12% faster, on a now-correct boot path.

**Warm is not measurable through the claim path** while #1962 stands: no claim
can complete, so there is no warm-to-agent-ready number to report. The ~60 ms
figure quoted elsewhere is the *driver-seam* restore
(`fc_warm_pool_live.rs`, which calls `fork_standby_child` directly with
`channels: &[]` and asserts the capability stays disarmed) — it measures the
restore mechanism, deliberately not the claim wiring, and should not be quoted
as a claim latency.

### Gate list — updated

1. **BUG-1** — fixed, live-proven (unchanged).
2. **BUG-2** — no longer blocks the claim. The transient `machine run` path
   reaches the claim decision and completes guest RPC setup.
3. **BLOCKER-3** — **boot half fixed** by #1959: the child now gets a
   boot-pinned host-signer anchor from the cmdline. The post-restore re-pin half
   is still unexercised, because no claim completes.
4. **BLOCKER-4** — still open and still unexercised.
5. **NEW / BLOCKER-5 — issue #1962, now the hard blocker.** Standby parents are
   never audited at spawn, so every claim fails closed with `ParentUnaudited`.
   Fix options in the issue; option 1 (admit a plan for the factory parent and
   emit `checkpoint.created` under it) is the one consistent with claim 8.
   Relaxing the claim-side check is not an option.
6. **Deferred, known-sharp** — failed-stop leaves an invisible live VM
   (unchanged).
7. Only then: re-run the Task 7 priorities and flip the capability if green.

`standby_pool` stays `false`. The flip was not proposed: the claim is refused,
not green.
