# Plan 278 — Transparent connect interception for non-cooperative workloads

**Status: REJECTED — 2026-08-20, no implementation**

W0's investigation refuted the plan's own framing: the two candidate
resolutions are a conjunction, not a choice, and one of them means a more
deliberate weakening than originally written. The compatibility benefit does
not justify making workload memory readable to a same-uid supervisor. The
supported FlowMux adapters remain the compatibility boundary; a workload that
ignores them has no network route and fails closed. Nothing in W1–W3 was
implemented, `DUMPABLE=0` and the empty capability bounding set remain intact,
and no seccomp user-notification listener is installed.

Workload microVMs have no NIC. Egress leaves the guest over vsock, to the
host-side substitution endpoint, and that is what makes claim 10 (default-deny),
claim 13 (no raw secret to the guest) and the audit chain enforceable: the host
*originates* every outbound connection, so it can authorize, substitute and log
it. Nothing in this plan changes that, and nothing in it adds a NIC.

What it closes is a **compatibility** gap, not a security one.

## The gap

Interception today is cooperative. `mvm-core`'s `guest_netd` points a workload at
a SOCKS5h proxy on `127.0.0.1:1080` and a DNS stub on `127.0.0.1:53` through the
standard proxy environment variables. An application that honours `ALL_PROXY` /
`HTTP_PROXY` works; the host endpoint sees `connect host:port`, applies the
shared `EgressGate`, and originates the connection.

An application that does not honour them opens a socket to a real address and
gets nothing, because there is no route to anywhere. It fails closed. That is
the correct security outcome and it is also an app-compat wall: statically
linked binaries, runtimes that ignore proxy env, anything issuing raw syscalls,
and most Go programs that use their own dialer all hit it.

## The framing that makes this tractable

**Interception is a compatibility feature, not a security control.** The
security property is "no NIC, therefore no route" — it holds whether or not
interception works, and it holds against a workload that deliberately defeats
interception. A workload that evades the mechanism in this plan does not gain
network access; it loses it.

That is worth stating up front because it removes the usual reason this kind of
work is hard. The mechanism does not need to be tamper-proof, it does not need
to be in the TCB, and a bypass is not a vulnerability. It only needs to be
correct on the cooperative-by-accident path.

## Findings

**F1 — `seccompiler` cannot express the notify action.** `SeccompAction` in
seccompiler 0.5 (`backend/mod.rs:154`) has `Allow`, `Errno`, `KillThread`,
`KillProcess`, `Log`, `Trace`, `Trap` — no `Notify`. Its install helper
`apply_filter_with_flags` is private, hard-codes `TSYNC` for the all-threads
variant, and discards the `seccomp(2)` return value, which is exactly the
listener fd we need. The crate cannot be coaxed into producing a notify
listener, and forking it for one action is not worth it.

**F2 — filter stacking gets us there without touching seccompiler.** Seccomp
filters compose: every filter in the tree is evaluated and the highest-precedence
action wins. The kernel's ordering is `KILL_PROCESS` > `KILL_THREAD` > `TRAP` >
`ERRNO` > `USER_NOTIF` > `TRACE` > `LOG` > `ALLOW`. So we keep installing the
tier filter through seccompiler exactly as today, then install a **second**,
hand-written BPF program — a few instructions, `SECCOMP_RET_USER_NOTIF` for
`connect`, `SECCOMP_RET_ALLOW` for everything else — via a raw `seccomp(2)` with
`SECCOMP_FILTER_FLAG_NEW_LISTENER`, and keep the returned fd. `USER_NOTIF`
outranks the tier filter's `ALLOW`, so the stacked verdict for `connect` is
`USER_NOTIF`. Only one filter in a tree may carry a listener; we install exactly
one.

**F3 — the tier filter must permit `connect`.** `ERRNO` outranks `USER_NOTIF`. If
the active tier denies `connect` with an errno, the notify never fires and the
workload sees the tier's refusal, which is the status quo. This must be
confirmed per tier before wiring, and a tier that denies `connect` should skip
listener installation rather than install one that can never fire.

**F4 — redirect via `ADDFD`, not by rewriting guest memory.** `connect(2)` acts
on an existing fd, so there is nothing to return. The supervisor instead:
performs the SOCKS handshake to the loopback proxy for the requested
destination, then uses `SECCOMP_IOCTL_NOTIF_ADDFD` with
`SECCOMP_ADDFD_FLAG_SETFD` to install the already-connected socket **over the
workload's existing fd number**, and returns success for the syscall. This is
what `ADDFD_FLAG_SETFD` exists for. It needs Linux ≥ 5.9; the guest kernel pin
tracks 6.12.x, so there is no floor problem.

**F5 — the classic notify TOCTOU is not a security problem here.** Reading the
`sockaddr` out of the target's memory is racy by construction: the workload can
change it after the supervisor reads it. In a security-enforcing use of seccomp
notify that is fatal. Here it is not, because the authorization decision is made
by the host endpoint from the SOCKS request, not from the address the supervisor
read. A workload that wins the race gets connected somewhere the host endpoint
then independently authorizes or denies. The race can produce a *wrong*
connection, never an *unauthorized* one.

**F6 — `mvm-seccomp-apply` is the natural insertion point.** It already sets
`PR_SET_NO_NEW_PRIVS`, compiles the tier's allowlist through seccompiler,
installs it, and `execve`s the wrapped command. It gains one step between
install and exec: install the notify filter, hand the listener fd to the agent,
then exec as before. No new process in the launch line and no change to the
`setpriv` shape.

## Open question — reading the destination address

This is the one genuine risk and it should be settled before any code lands.

To know where the workload wanted to go, the supervisor must read the `sockaddr`
from the target's address space, via `/proc/<pid>/mem` or `process_vm_readv`.
Both are gated by `ptrace_may_access`. Two things in the current posture push
against it: `runner/hardening.rs` sets `prctl(PR_SET_DUMPABLE, 0)`, which makes
the process unreadable to non-root peers, and the agent runs as uid 901 while
the workload runs under its own per-service uid.

Two candidate resolutions were proposed:

1. **Co-uid supervisor.** Run the notify supervisor as the workload's uid — a
   small dedicated task rather than the agent proper — so `ptrace_may_access`
   passes on the ownership check. Keeps `DUMPABLE=0` and the agent's uid intact.
   Costs a process per workload.
2. **Relax `DUMPABLE` and lean on `RLIMIT_CORE=0`.** `hardening.rs`'s own comment
   describes `PR_SET_DUMPABLE` as belt-and-suspenders on top of the agent-side
   `RLIMIT_CORE = 0` for the coredump property.

**They are not alternatives. Measured, the design needs both.**

### Measured result

Run against Linux 6.8.0 with `yama/ptrace_scope=1`, modelling the real shape —
supervisor as the **parent**, workload as the child, so the Yama descendant rule
is satisfied and `DUMPABLE` is the only variable under test. Both read routes
(`process_vm_readv` and `/proc/<pid>/mem`) were probed per case.

| supervisor | workload | `DUMPABLE` | result |
|---|---|---|---|
| uid 1001 | uid 1001 | 1 | **readable** — both routes return the payload |
| uid 1001 | uid 1001 | 0 | denied — `EPERM` / `EACCES` at `open` |
| uid 1001 | uid 1002 | 1 | denied — `EPERM` / `EACCES` at `open` |
| uid 1001 | uid 1002 | 0 | denied — `EPERM` / `EACCES` at `open` |

**Candidate 1 alone is refuted.** Same uid, parent of the target, Yama satisfied
— still denied when `DUMPABLE=0`. The dumpable check in `__ptrace_may_access` is
independent of credentials, so matching uids does not buy past it.

**Candidate 2 alone is insufficient.** Row 3 shows `DUMPABLE=1` is still denied
across a uid boundary. Exactly one configuration reads: same uid **and**
`DUMPABLE=1`.

Because the denial in row 2 arrives despite Yama being satisfied, the result
does not depend on Yama at all — it comes from the core-kernel dumpable check,
so it holds identically on a guest built without `CONFIG_SECURITY_YAMA`.

### The finding that changes the shape of candidate 2

"Relax `DUMPABLE`" is not "delete the `prctl` in `hardening.rs`". Measured
separately: a credential change leaves the process at `dumpable = 2`
(`SUID_DUMP_ROOT`), not 0 —

```
as root, before drop     : dumpable=1
explicitly set to 1      : dumpable=1
AFTER setuid(1001)       : dumpable=2
re-raised after the drop : dumpable=1
```

`ptrace_may_access` requires `SUID_DUMP_USER` (1), so a workload that simply
drops privileges and sets nothing is *already* unreadable. Interception would
therefore require the launch path to **affirmatively raise `dumpable` to 1 after
the privilege drop** — a stronger, more deliberate weakening than "stop
hardening", and it has to live in the launch path (`mvm-seccomp-apply` /
`setpriv` sequence), not in `hardening.rs`.

### Surviving design, and its cost

Same-uid supervisor **and** an explicit post-drop `dumpable = 1`. What that
costs: the workload's `/proc/<pid>/mem` becomes readable by anything running at
the workload's uid. Since uids are per-service the blast radius is one service,
and the coredump property is unaffected because it rests on the agent-side
`RLIMIT_CORE = 0`, not on `DUMPABLE`.

`CAP_SYS_PTRACE` for the supervisor would sidestep all of it and is **rejected**:
the guest empties the bounding set under `setpriv --bounding-set=-all`, and
re-introducing a capability that reads any process's memory to buy an app-compat
feature is the wrong trade against claims 1 and 2.

Caveat on transfer: measured on 6.8.0, guest kernels pin 6.12.x. The dumpable
gate in `__ptrace_may_access` is long-stable, but the numbers above are from
6.8.0 and should be re-run once against a real guest before W1 lands.

## Workstreams

### W0 — settle address reading *(decision complete)*

- [x] Confirm `ptrace_may_access` behaviour for both candidates, measured rather
      than reasoned from the docs. Four-case matrix on Linux 6.8.0 with
      `ptrace_scope=1`; both read routes probed. See "Measured result" above.
- [x] Establish that the two candidates are a conjunction, not a choice:
      candidate 1 alone is refuted, candidate 2 alone is insufficient, and only
      same-uid + `DUMPABLE=1` reads.
- [x] Establish that a privilege drop leaves `dumpable = 2`, so candidate 2 means
      affirmatively raising it post-drop in the launch path, not deleting a
      `prctl` in `hardening.rs`.
- [x] **Maintainer decision: reject the surviving design.** Accepting
      means the workload's `/proc/<pid>/mem` is readable at the workload's own
      uid, for an app-compat feature that is explicitly not a security control.
      That trade is rejected; the cooperative path remains the documented
      boundary and W1–W3 are permanently descoped.
- [x] ~~Re-run the matrix once on a real guest at the pinned 6.12.x kernel.~~
      Descoped because no implementation depends on transferring the 6.8.0
      measurements.

### W1 — notify listener install *(rejected; no implementation)*

- [x] Descoped the per-tier `connect` investigation with the rejected design.
- [x] Descoped the hand-written seccomp `USER_NOTIF` filter; no listener is
      installed on either architecture.
- [x] Descoped listener-fd transfer; `mvm-seccomp-apply` sends no new
      `SCM_RIGHTS` message.
- [x] Descoped stacked-filter tests because the second filter does not exist.

### W2 — supervisor loop *(rejected; no implementation)*

- [x] Descoped notification reads and destination recovery.
- [x] Descoped `SECCOMP_IOCTL_NOTIF_ADDFD`; no workload socket is replaced.
- [x] Descoped interception-specific errno handling.
- [x] Descoped notification-ID validation because no notification loop exists.

### W3 — validation *(reframed around the rejected boundary)*

- [x] Rejected direct-socket compatibility; non-cooperative direct sockets
      intentionally have no route.
- [x] Descoped interception-specific `EgressGate` coverage because no second
      interception path exists.
- [x] A workload using a direct socket still reaches nothing. This is covered
      at the supported public boundary and proves the security property does
      not rest on interception.
- [x] Descoped interception latency measurement because no notify path exists.

## Out of scope

- Adding a NIC to a workload microVM, in any form, for any tier. The whole point
  of this plan is to close the compat gap *without* one.
- Making interception a security control. It is not one and must not be
  described as one, in code comments or docs.
- ICMP and raw sockets, which are being handled separately as their own
  vsock-mediated capability rather than as general socket interception.
- Non-Linux guests. Seccomp is Linux-only; guests always are.
