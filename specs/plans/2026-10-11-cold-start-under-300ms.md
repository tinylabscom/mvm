---
kind: design
issue: https://github.com/tinylabscom/mvm/issues/4308
status: accepted
---

# Cold workload start under 300 ms

Backing: preview
Validation: none

This note ranks the ways to bring a launch that
does not claim a warm standby under the 300 ms startup limit, from measurements
taken on 2026-10-11. The issues linked below own status and scope.

## The window

"Startup" here is what a caller waits before its command can be sent:
resolution, drives, admission, VMM start and guest boot to an answering agent.
The prepared-cold dispatch ceiling starts after
admission, so it never saw the costs this note is mostly about.

The shape measured is the one a warm standby cannot serve today: a named
`mvmctl machine run --image alpine --name … -- /bin/true`. Named runs, launches
with volumes, launches whose policy admits egress, and launches from a bundle's
own boot assets all take this path (`warm_eligible_launch`,
`warm_claim_requested`).

## Measurements

Firecracker 1.17 on the shared KVM host (i7-7700-class, 12 threads, rotational
md-RAID), release builds, 20 interleaved cold launches per build per round.
Every build ran from its own checkout and its own `MVM_HOME`, because a source
build's initramfs staleness check reads the checkout and the two builds would
otherwise evict each other's cache. The baseline's 20 ms contributor-only
initramfs fingerprint walk is subtracted throughout; a release binary does not
run it.

| build | host I/O (PSI some) | startup p50 / p95 / max | admit_plan p50 / p95 | endpoint_spawn p50 / p95 | guest_boot p50 / max |
| --- | --- | --- | --- | --- | --- |
| main (`e9cc3968da`) | 5–13% | 377 / 670 / 1044 | 121 / 374 | 50 / 117 | 89 / 116 |
| + identity drive and root flush | 5–13% | 269 / 454 / 471 | 83 / 272 | 0.7 / 1.0 | 87 / 130 |
| + `loglevel=3` prototype | 5–13% | 239 / 344 / 541 | 77 / 101 | 0.6 / 1.0 | 62 / 123 |
| main | 20–30% | 478 / 2048 / 2186 | 189 / 1253 | 96 / 637 | 87 / 119 |
| + identity drive and root flush | 20–30% | 289 / 733 / 855 | 96 / 578 | 0.6 / 0.9 | 85 / 119 |
| + `loglevel=3` prototype | 20–30% | 254 / 848 / 957 | 95 / 692 | 0.6 / 1.1 | 61 / 91 |

A first quiet run of main (load 3, PSI under 2%) measured startup 342 p50 /
358 max, with admit_plan 109, endpoint_spawn 42, vmm_start 53, guest_boot 84 and
activation 29 ms. The guest's own clock read 0.13 s at workload exec.

On macOS 27 / HVF this Mac sat at a load average of 260–320 for the whole
session, so no end-to-end HVF number from it means anything. The two fsync
costs were measured directly instead: `F_FULLFSYNC` is 5.0 ms p50 on a file and
4.1 ms on a directory. The last HVF warm figures are #4317's: startup 191 p50 /
224 max.

## Ranked approaches

Savings are p50 / p95 / max on Firecracker at PSI 5–13% unless stated; HVF is
the component cost removed.

| rank | approach | FC saving | HVF saving | complexity | security | cold under 300? |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | Write the per-boot identity drive without fsync | endpoint_spawn −50 / −116 / −346; under heavy I/O −95 / −636 | ≈ −9 ms (2 × `F_FULLFSYNC`) | trivial | none: same 0600 inode, rename-published, minted per boot | needed, not enough alone |
| 2 | Publish the admission root inside the admission flush | admit_plan −38 / −102 p50/p95; under heavy I/O −93 / −675 | ≈ −9 ms (2 serial syncs) | small | none: admission records stay durable before boot; the root no longer lands before the entries it covers | with 1: p50 269 |
| 3 | Stop the duplicate virtio-mmio registrations reaching the serial console | guest_boot −25 / −15 / −7 (prototype) | n/a (virtio console) | small, in mvm-images or the cmdline | `loglevel=3` would also hide `Out of memory: Killed process`; the kernel-config route hides nothing | with 1–2: p50 239 |
| 4 | Overlap admission with VMM start; release activation only after admission is durable | hides the remaining ≈ 40–90 ms admission behind ≈ 85 ms of guest boot | ≈ admission (23 ms in #4317) | high | no workload code before admission holds if `ActivateEnvironment` waits; the host budget check must still precede the spawn | p50 ≈ 200, and takes the I/O tail off the critical path |
| 5 | Pre-spawned VMM and scope | vmm_start is 63 ms; `systemd-run --user --scope` 6–32 ms, launch script 6 ms, poll overshoot | supervisor spawn | medium–high | a pre-spawned process must carry no guest and no plan until claimed | −30 to −40 ms |
| 6 | Snapshot restore for shapes the pool refuses | warm claim startup 134 / 147 / 149 (#4317) | 191 / 223 / 224 | high per shape | each shape must keep its own isolation: fresh identity, its own drives, its own egress bit | yes, per shape covered |
| 7 | Quieter guest agent on the serial console during activation | ≈ 13 ms estimated (≈ 900 B at ≈ 15 µs/byte) | n/a | small | none | small |
| 8 | Fewer agent handshakes (readiness Ping after the activation ACK) | agent_auth is 2–3 ms | similar | small | none | negligible |

### 1. Identity drive without fsync

Every cold boot writes `flowmux-identity.ext4` through `write_private`: a synced
temporary plus a synced parent directory. The VMM reads the drive from the page
cache, every boot mints a new one, and a crash that could lose it also ends the
guest that would read it. Those two syncs were the whole `endpoint_spawn` phase
of a deny-all launch, and the 130–355 ms "endpoint spawn stalls" seen on this
host under disk load (#4317) were them.

### 2. Admission root inside the admission flush

`record_admission` runs inside `AuditEmitter::batched`, which folds the chain's
fsyncs into one concurrent flush. `publish_root` bypassed it: the root history
and the root sidecar each synced on their own, serially, before the batch's
flush. The remaining pre-boot flush is the claim 8 barrier and stays.

### 3. Kernel console

On Firecracker x86, quiet boots still print 15 `KERN_ERR` lines over the
emulated 16550: `PCI: Fatal: No config space access function found`, then a
`-EBUSY` pair for each of the seven virtio-mmio devices the cmdline registers
again after ACPI already described them. The line spacing puts each line at
1.4–1.7 ms. The workload kernel keeps `VIRTIO_MMIO_CMDLINE_DEVICES` and ACPI
both, which is what produces the duplicates. `loglevel=3` removes the cost and
was measured as a prototype; it also hides `pr_err` lines the console scanners
look for, so the fix belongs in the kernel configuration.

### 4. Overlap admission with VMM start

After 1 and 2, the only admission cost before boot is one concurrent fsync
round, which is the claim 8 barrier and must stay. It does not have to be
serial with the VMM: the guest boots to an agent that refuses everything but
`ActivateEnvironment`, so the VMM and kernel can start while admission records,
and activation waits for the admission to be durable. Two things stay ordered:
the host budget check before any spawn, and activation after admission.

### 5. Pre-spawned VMM

`vmm_start` is 63 ms p50: a `bash` launch script, a `systemd-run --user --scope`
round trip (6–32 ms measured on its own), `setsid`/`nohup`/`sh` execs, two
backoff polls and eleven API PUTs on separate connections. A small pool of
scoped, idle Firecracker processes with no guest and no plan, configured on
claim, removes most of it.

### 6. Snapshot restore for shapes the pool refuses

A Firecracker standby is a saved checkpoint plus a preloaded child, and one
claim consumes the record. The cold shapes need their own handling: a named run
needs only a name binding, since identity already rotates on claim; an
egress-allowing launch needs a parent warmed with the egress bit; volumes need
placeholder drives, because Firecracker cannot hot-add a block device; bundle
boot assets need a parent prepared from the bundle. A claim without a preloaded
child re-hashes the parent's content twice, which is O(memory + rootfs) per
launch, so per-launch restore from a saved image needs a verified-content cache
keyed by the authenticated chunk index before it is a cold path.

## Not on the startup path

Teardown is 450–550 ms here, with about four fsyncs on the exit path and a
full-history `read_leaves` in `seal_session`. The caller already has its output
by then, so it is outside the window, but it bounds how fast launches can
follow each other.

## Follow-ups

- Identity drive written without fsync — #4350
- Admission root joins the admission flush — #4351
- Duplicate virtio-mmio registrations on the serial console — #4343
- Overlap admission with VMM start — #4344
- Pre-spawned Firecracker processes with their scopes — #4345
- Agent diagnostics off the serial console during activation — #4346
- Prepared-cold samples held to 300 ms from invocation — #4347
- Exit-path fsyncs and the full-history seal read — #4348
- Warm parents for the shapes the pool refuses today, and a verified-content
      cache for claims without a preloaded child — #4338
