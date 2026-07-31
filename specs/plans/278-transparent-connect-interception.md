# Plan 278 — Transparent connect interception for non-cooperative workloads

**Status: Proposed**

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

Two candidate resolutions, neither yet chosen:

1. **Co-uid supervisor.** Run the notify supervisor as the workload's uid — a
   small dedicated task rather than the agent proper — so `ptrace_may_access`
   passes on the ownership check. Keeps `DUMPABLE=0` and the agent's uid intact.
   Costs a process per workload.
2. **Relax `DUMPABLE` and lean on `RLIMIT_CORE=0`.** `hardening.rs`'s own comment
   describes `PR_SET_DUMPABLE` as belt-and-suspenders on top of the agent-side
   `RLIMIT_CORE = 0` for the coredump property. If that holds, `DUMPABLE=1`
   costs the `/proc/<pid>/mem` hardening but not the coredump guarantee. That is
   a real reduction in the guest's internal hardening and needs an explicit
   decision, not a silent flip.

Resolving this is W0 and blocks everything after it.

## Workstreams

### W0 — settle address reading *(blocking)*

- [ ] Confirm `ptrace_may_access` behaviour for both candidates against a live
      guest, not by reasoning about the docs.
- [ ] Decide co-uid supervisor vs `DUMPABLE` relaxation; record the decision and
      the hardening delta in this plan.
- [ ] If neither is acceptable, stop here and close the plan — the cooperative
      path stays as-is and this is a documented non-goal.

### W1 — notify listener install

- [ ] Confirm per tier whether `connect` is permitted (F3); skip listener
      installation for tiers that deny it.
- [ ] Hand-written BPF: `USER_NOTIF` for `connect`, `ALLOW` otherwise, installed
      via raw `seccomp(2)` with `SECCOMP_FILTER_FLAG_NEW_LISTENER`, arch-gated
      for aarch64 and x86_64 the way the tier tables already are.
- [ ] Pass the listener fd from `mvm-seccomp-apply` to the supervisor over
      `SCM_RIGHTS` before `execve`.
- [ ] Unit test: stacked filters yield `USER_NOTIF` for `connect` and the tier's
      verdict for everything else.

### W2 — supervisor loop

- [ ] Read the notification, recover the destination, dial the loopback SOCKS
      proxy, complete the handshake.
- [ ] Install the connected socket with `SECCOMP_IOCTL_NOTIF_ADDFD` +
      `SECCOMP_ADDFD_FLAG_SETFD` over the target fd; return success.
- [ ] Handle every failure by returning the errno the workload would have seen
      with no interception, so a supervisor bug degrades to today's behaviour
      rather than to a hang.
- [ ] `SECCOMP_IOCTL_NOTIF_ID_VALID` before acting on any notification, so a
      dead target cannot cause an fd to be installed into a recycled pid.

### W3 — validation

- [ ] A non-cooperative fixture — a static binary that dials a real address with
      no proxy env — reaches an admitted destination through the endpoint.
- [ ] The same fixture against a denied destination is refused by the shared
      `EgressGate`, with the refusal in the audit chain. Interception must not
      become a second gate.
- [ ] A workload that defeats interception (raw syscall, filter evasion) still
      reaches nothing. This is the test that proves the security property does
      not rest on this mechanism.
- [ ] Latency delta on the cooperative path is zero: proxy-env-honouring apps do
      not enter the notify path at all.

## Out of scope

- Adding a NIC to a workload microVM, in any form, for any tier. The whole point
  of this plan is to close the compat gap *without* one.
- Making interception a security control. It is not one and must not be
  described as one, in code comments or docs.
- ICMP and raw sockets, which are being handled separately as their own
  vsock-mediated capability rather than as general socket interception.
- Non-Linux guests. Seccomp is Linux-only; guests always are.
