# Plan 255 — live Firecracker warm-claim validation (KVM host)

Date: 2026-07-28
Outcome: **FAILED — the warm pool cannot populate on a real Firecracker/KVM host at this commit.**

This is the empirical gate for the Firecracker warm pool built in Tasks 1–6.
Everything below is a command that was actually run on real hardware plus its
real output. Where a check could not be run, that is stated rather than
inferred.

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
was **never created** during it — see "What was NOT reached".

One environment note: the guest agent had to be rebuilt once for this
checkout's guest fingerprint (`0.18.0-guest-447f29460cdf25e3`), which needs
`cargo` on `PATH` (`export PATH=/root/.cargo/bin:$PATH`). Without it the very
first run fails with `cargo-zigbuild failed: spawn cargo: No such file or
directory`. `mvmctl` itself was not rebuilt.

## Result summary

| # | What was to be established | Result |
|---|---|---|
| 1 | `capture_vm_full` → `FcForkRestorer::restore_fork` end to end | **NOT REACHED.** The standby parent kernel-panics before its agent starts, so capture never runs. |
| 2 | Restored child answers post-restore handshake `acknowledged`+`reseeded`+`clock_resynced` | **NOT REACHED.** No checkpoint exists to restore from. |
| 3 | Fresh child VM name, no kernel boot in the child console | **NOT REACHED.** |
| 4 | Cold-boot vs warm-claim timing | **Cold measured; warm not measurable.** |
| 5 | Fail-closed cases | **1 of 3 verified live** (absent `parent_checkpoint` → refuse + cold-boot, no orphaned child dir). The other two need a real captured checkpoint. |

Two defects were found. Neither was fixed (this task is validation only).

---

## BUG-1 — the standby parent boots without the runtime overlay and panics

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

## What WAS verified live

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

---

## What must happen before this validation can be re-run

1. Fix BUG-1: thread the runtime overlay (and the matching
   `mvm.runtime_*` / verity cmdline tokens) into `spawn_standby_parent`'s
   `VmmSpec`, the way the workload launch path does via
   `attach_runtime_overlay_if_cached`. Until then no Firecracker standby can
   boot on an overlay-only runtime.
2. Fix BUG-2, or the transient `machine run` that hosts the claim cannot
   complete a guest RPC at all.
3. Then re-run: priorities 1–3, the two remaining fail-closed cases, and the
   warm-claim timing.

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

---

## Second live run — after the overlay-attachment fix

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

### Root cause (deeper than BUG-1 as first written)

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

### What this slice ships instead

The capability flip is **reverted** — Firecracker again reports
`standby_pool: false`. Advertising the pool while a parent cannot boot would
turn a configured warm pool into a failed spawn on every launch, which is a
worse outcome than not offering it. The capture, fork-restore, CLI wiring, and
overlay attachment all land; the flip returns with the parent's verified-boot
shape.

### Still open

- The parent must boot the verity/initramfs shape rather than a direct rootfs
  boot — i.e. `spawn_standby_parent` should build its spec through the same
  mapping the workload uses instead of hand-rolling a `VmmSpec`.
- **BUG-2** is unchanged: the transient `machine run` path still ends in
  `Error: Failed to read frame length` (no verb-grant sidecar minted), which is
  independent of the pool.
