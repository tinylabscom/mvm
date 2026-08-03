# No workload runs as root — cause, fix, and live witness

**Status:** Evidence record. Every result below was produced by running the command shown on the host shown.
**Scope:** #2091 — HVF ran the OCI entrypoint as root while Firecracker dropped to uid 901, for the same command and image.
**Owner ruling:** a workload entrypoint is the workload's main process and must never run as root.

## The cause

Not a backend difference, despite presenting as one.

`mvm-oci-init` is pid 1 on the OCI path. It performs the mounts and provisioning as root, then calls
`spawn_one(&agent, "guest-agent")` — a plain `Command::spawn` that sets no uid. The agent is therefore a
*child*, so `init::is_pid1()` is false, so `apply_activation` returns before reaching
`guest_mount::drop_privilege`. The agent keeps uid 0.

That matters because the agent has five distinct workload-spawn sites — the entrypoint runner, the exec
stream, the console, the lifecycle hooks, and the worker pool — and **none of them sets a uid**. Each
inherits the agent's identity. A root agent means a root workload, at every one of them.

Firecracker boots the agent *as* pid 1, so it reaches the drop and lands on 901. Same command, two inits,
two postures. HVF was not the variable; the init was. Any backend on the OCI path had the same defect.

## The fix

Two independent changes, deliberately kept separate.

**1. The mechanism.** `mvm-oci-init` now spawns the agent with the workload identity from the start. The
agent needs no privilege on this path — the init has already done every root-only step by the time it
spawns. This converges the OCI path on the posture Firecracker already had rather than inventing a
second one.

`drop_privilege_raw` is now the single drop implementation, allocating on no path, because the new caller
runs in a `pre_exec` hook — in the forked child before `exec` — where allocating can deadlock if another
thread held the allocator lock at fork time.

`/run/mvm` deliberately stays root-owned. It holds the host-signer anchor, so making it workload-writable
would let a compromised workload replace that anchor and undermine verb-grant trust. The agent only reads it.

**2. The backstop.** `Verb::spawns_workload_process()` classifies every wire verb exhaustively, and one
check on the shared request path refuses when the agent is uid 0. `ActivateEnvironment` is classified as
non-spawning on purpose: it performs the mounts and the pivot and so legitimately runs while still root.
If the gate caught it, no guest could reach the privilege drop at all.

Guarding the five spawn sites individually was considered and rejected — it guards the symptom five times
and still misses the sixth site someone adds later. The property is single: the agent is not root when it
serves a request that runs workload code.

The gate is what protects the fix. Reverting the mechanism does not silently restore root; it makes every
workload run fail loudly, on every boot.

## Live results

Command: `mvmctl machine run --image alpine [--hypervisor hvf] -- /bin/sh -c 'echo MVM_BOOT_OK; id'`

| | Before | After |
|---|---|---|
| Firecracker (Linux/KVM, Hetzner) | `uid=901 gid=901` | `uid=901 gid=901` |
| HVF (macOS 26.5.2 arm64) | **`uid=0(root) gid=0(root)`** | **`uid=901 gid=901`** |

Both "after" figures are runs of a binary built from this branch, with the guest
binaries recompiled on each host — not a carry-over of the earlier result. The
Firecracker column is the regression check: the fix changes the OCI init, and
Firecracker had to be shown still landing on 901 rather than assumed to.

## The gate, witnessed live

Reverting only the mechanism and re-running on HVF — a planted defect, not a hypothetical:

```
Error: guest agent refused exec: it is still running as uid 0, so the workload
would have run as root. The agent never reached its privilege drop.
```

The refusal names the verb and the uid, so the diagnosis is in the error rather than in a console-log hunt.
Restoring the mechanism returns the run to `uid=901`.

Unit-level, the same discipline: moving `Exec` to the non-spawning side turns two tests red; deleting the
`uid != 0` condition turns another red; removing the host-side handling turns the typed-error test red.

## An obstacle worth recording

The first two HVF attempts failed — one on a substitution-endpoint handshake timeout, one hanging outright —
and the console showed `spawned guest-agent pid=46` with no `uid=` suffix, i.e. the *old* binary. An
orphaned `mvm-hvf-supervisor` from an earlier run, 2.5 hours old, was still holding the previous
`overlay.ext4` open and serving a stale VM. The runs were never exercising the new code.

Worth knowing generally: **a stale supervisor makes a fixed build look broken.** Check for orphaned
supervisor processes before believing a live result. The tell was the console line's missing field, not
the error message.

## Not witnessed here

- **Claim 15** (no interactive access to a sealed production microVM) — needs a sealed prod image; the
  alpine image used here is neither sealed nor prod.
- **Claims 1 and 2 proper** — witnessing these needs a guest that *attempts* host-fs access and *attempts*
  elevation, not a report of its starting uid.
- The `forward proxy failed to start: binding forward proxy on 127.0.0.1:18080` line in the guest console
  is the known NIC-less loopback gap, pre-existing and untouched by this work.
