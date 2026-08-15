# The guest agent could not spawn itself — capability bounding set, wrong order

**Issue:** #2522
**Branch:** `fix/2522-agent-spawn-capbset`
**Regressed by:** #2478 (issue #2101, `specs/plans/300-open-issue-closeout.md` Phase 1)

Every `mvmctl machine run --image <ref>` on `main` failed with `guest agent did
not become reachable within 30s`. Bisected on one host, one `~/.mvm`, one set of
caches — only the binary differed:

| build | result |
| --- | --- |
| `69a2e581b` (= `a6599e1cb^`) | `hi`, exit 0 |
| `ae8f576d9` | agent unreachable, exit 1 |

## What was wrong

`drop_guest_agent_privilege_raw` narrowed the capability bounding set *after*
`set_capabilities` had reduced the process to `CAP_KILL|CAP_SYS_TIME`.
`PR_CAPBSET_DROP` requires `CAP_SETPCAP`, which is not in that set, so the
syscall returned `EPERM` every time. On the OCI route the function runs inside
`spawn_one_as`'s `pre_exec`, so the errno came back out of `Command::spawn()`
and the agent was never started:

```
mvm-verity-init: switching to /init
mvm-guest-init: spawn guest-agent at /mvm/runtime/agent: Operation not permitted (os error 1)
```

The nix route reaches the same function from PID 1 (`bin/mvm-guest-agent/init.rs`),
so it was broken identically. Nothing about the failure was backend-specific.

#2478 diagnosed this exact interaction for the *workload* spawn and fixed it
there, by tolerating `EPERM` in `drop_workload_capability_bounding_set`. The
agent's own drop kept the broken ordering, and there were two copies of the
same three-line `match` rather than one.

## What changed

- `guest_mount::drop_guest_agent_privilege_raw` narrows the bounding set
  immediately after `PR_SET_KEEPCAPS` and before `setgroups`/`setgid`/`setuid`,
  while the caller still holds `CAP_SETPCAP`. This enforces the narrowing rather
  than skipping it; the bounding set is inherited across fork and exec, so it
  binds the agent and everything under it exactly as before. `set_capabilities`,
  `raise_ambient_capabilities`, `set_no_new_privileges` and the `getuid() == 0`
  paranoia check are unmoved. `CAP_KILL` and `CAP_SYS_TIME` are retained by the
  mask, so the ambient raise is unaffected by the earlier narrowing.
- `narrow_bounding_set_where_enforceable` is now the single implementation of
  "enforce where possible, fail closed on any other errno", shared with
  `drop_workload_capability_bounding_set`. A future fix to one cannot miss the
  other.
- `harden_init_process` is untouched. It still runs as root in init, orders
  `NoNewPrivs` first and fails closed, and remains the load-bearing control on
  the OCI path.

## Why it was invisible

On HVF the guest console accumulated in `Pl011.output` and reached
`console.log` only after the run loop returned. For the whole 30s the host
spends waiting for the agent the file is 0 bytes, so the CLI's
`emit_guest_console_diagnostic` — the diagnostic that exists specifically for a
boot that never comes up — could only ever report "Guest console … was empty".
The console above was recovered by booting detached, letting it fail, stopping
the VM, and only then reading the file.

`Pl011` now takes an optional write-through sink (`Pl011::stream_to`), flushed
per line and at a 512-byte cap so an unterminated line still surfaces. The
supervisor passes `console_log` through `HostChannels`, and the device opens it
with the existing `open_console_capture` — write-only, which is what keeps
claim 15's "no host input fd" true. The change is additive: `output` still
accumulates identically and the supervisor's authoritative rewrite after the run
loop returns is unchanged, so every consumer of `KernelBootResult.console` sees
what it saw before. What changed is that the log is readable *during* the run,
and survives a `SIGKILL`.

## Why CI did not catch it

`oci-image-runner-smoke` and the live-VM lanes live in `ci-full.yml`, which is
`workflow_dispatch:`-only. No PR-gating lane boots a guest, so a change that
makes every guest fail to boot passes every required check. Worth a follow-up;
not fixed here.

## Tests

- `the_agent_never_retains_the_capability_its_bounding_drop_requires` — pins the
  invariant the ordering rests on (`CAP_SETPCAP` ∉ `RESTORE_AGENT_CAPABILITIES`),
  and runs on every host.
- `drop_guest_agent_privilege_reaches_the_agent_identity_from_root` — live
  witness behind `MVM_GUEST_PRIVILEGED_TESTS=1` + root, matching the existing
  `harden_init_process_*` idiom. Asserts the drop returns `Ok` — which is the
  whole regression — and lands on uid 901 with `CapBnd` = `CAP_KILL|CAP_SYS_TIME`
  and `NoNewPrivs: 1`.
- Five `Pl011` tests: a completed line reaches the sink before the device is
  dropped (the property whose absence hid this bug), an unterminated line
  flushes at the cap, streaming leaves the in-memory transcript byte-identical,
  a failing sink latches instead of faulting the guest or retrying per byte, and
  restore clears pending parent output without detaching the child's sink.

`narrow_bounding_set_where_enforceable` has no logic of its own beyond
`bounding_drop_is_unenforceable`, which is already tested on every host; it is
Linux-gated and needs root, so it has no separate unit test.

The end-to-end witness is the live boot, against the pre-#2478 binary as the
known-good baseline:

| backend | broken `main` | fixed |
| --- | --- | --- |
| HVF (macOS 26) | agent unreachable after 30s | `alpine` → `hi`, `python:3.12` → `4` |
| libkrun (macOS) | agent unreachable after 30s | `alpine` → `hi` |
| Firecracker (Linux/KVM) | not witnessed — see below | not witnessed |

libkrun matters as the second witness because it shares nothing with HVF except
the guest, which is where the bug is. It also printed the failing line straight
to the terminal — it hands the console fd to the VMM — so on that backend the
diagnostic worked all along.

Firecracker could not be witnessed either way. That host fails earlier, at vCPU
resume, with the Firecracker process exiting before the guest emits anything;
this branch fails identically there. That is #2510, a distinct defect this does
not fix — the agent-spawn `EPERM` cannot make a VMM exit, because
`mvm-oci-init` logs the failure and falls through to `idle_forever()`, leaving
the VM alive. Firecracker reaches the same privilege drop through the same code,
so it is affected by construction; it just cannot be observed there until #2510
is resolved.
