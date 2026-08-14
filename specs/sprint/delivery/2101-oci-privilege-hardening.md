# OCI workload privilege hardening — `no_new_privs` and a bounded capability set

**Issue:** #2101
**Branch:** `fix/2101-oci-privilege-hardening`
**Plan:** `specs/plans/300-open-issue-closeout.md` Phase 1

The OCI boot path reaches the workload by a different route than the nix-built
guest: nothing plays the part `mvm-setpriv` plays there, so the agent and every
workload beneath it inherited PID 1's full capability bounding set
(`CapBnd 000001ffffffffff`) and `NoNewPrivs: 0`, on both HVF and Firecracker.

The outcome still held — the image ships zero setuid binaries and the rootfs is
read-only — but by circumstance rather than by the mechanism ADR-001 W2.3
names. With `no_new_privs` off, a setuid bit or file capability in an image
would be honoured on exec.

## What changed

- `guest_mount::harden_init_process()` — called from `mvm-oci-init` after the
  last root-only step and before the agent is spawned. Narrows the bounding set
  to `RESTORE_AGENT_CAPABILITIES` and sets `no_new_privs`. Both are inherited
  across fork and exec and can only shrink, which is what lets one call by a
  parent bind every descendant.
- `guest_mount::drop_workload_capability_bounding_set()` — called from the
  entrypoint `pre_exec`, the last point anything runs on the workload's behalf.
  Empties the bounding set. The agent keeps `CAP_KILL` (reap children) and
  `CAP_SYS_TIME` (correct a restored clock); the workload needs neither.
- `drop_guest_agent_privilege_raw` also drops the bounding set, so the
  initramfs path and the OCI path reach the same posture.
- `set_no_new_privileges()` — the shared `prctl` wrapper all three use.

Two drop points rather than one, because the agent and the workload need
different sets. An earlier attempt used a single call and described the result
as an empty bounding set; it was not empty, because it retained what the agent
needs.

## Bug found and fixed

The drop loop walks capability slots `0..=63` but tested the keep mask with
`1u32 << cap`, which panics at slot 32 in debug and mis-answers every slot
above 31. The mask arithmetic is now `bounding_set_retains`, widened to `u64`.

## Verification

- `cargo nextest run -p mvm-agentd` — 770 passed.
- Three new tests run on every host with no root and no gating: mask arithmetic
  across all 64 slots, the agent mask retaining exactly `CAP_KILL|CAP_SYS_TIME`,
  and the workload mask being empty and a strict subset of the agent's.
- Red-before-green: reverting only the `u64` widening fails two of the three
  with `attempt to shift left with overflow`.
- `cargo fmt --all -- --check`; `cargo clippy --workspace --all-targets --
  -D warnings`.
- `cargo zigbuild --target x86_64-unknown-linux-gnu -p mvm-agentd --all-targets
  --all-features` — the change is entirely Linux-gated, so a macOS-only check
  would hide a break in it.

## Follow-up: unprivileged spawn regression

The first revision applied the bounding-set drop before `NoNewPrivs`, and
propagated every error from it. `PR_CAPBSET_DROP` needs `CAP_SETPCAP`, so on any
host where the agent lacks it the drop returned `EPERM`, the `pre_exec` closure
returned that error, and the spawn failed outright — 20 `entrypoint_execute`
tests went red with `spawn /proc/self/fd/4: Operation not permitted`.

Two changes: `NoNewPrivs` is now set first on both paths, so a bounding-set
failure can no longer skip the control this document already described as the
load-bearing one; and the workload drop treats `EPERM` — and only `EPERM` — as
"never enforceable by this caller" rather than as a failure. Every other errno
still propagates and still fails the spawn closed, and `harden_init_process()`
is unchanged in that respect: at init the agent is root, so a failure there is
real and still refuses.

This does not widen the workload's privilege. An agent without `CAP_SETPCAP`
cannot grant a capability it does not hold, and the bounding set a child
inherits is already no wider than the agent's own.

`only_eperm_is_treated_as_an_unenforceable_bounding_drop` pins the errno
classification on every host, including that a non-errno error is never
swallowed.

## Deliberately not done

The issue stays open. Its closure gate is the adversarial probe from
`specs/research/no-root-workload-live-witness.md` re-run on HVF **and**
Firecracker; no Linux/KVM host was available. The original finding was only
visible because that probe attempts elevation rather than reporting its
starting uid, so unit tests do not substitute for it.

The ADR-001 claims 1/2 scope decision — whether they extend to the OCI workload
process or are scoped to mkGuest services where W2.3 already applies — is an
owner call and is not made here. The change is correct either way; the decision
only determines whether it is claim-bearing or defense-in-depth. The ADR-001
claims table is untouched.
