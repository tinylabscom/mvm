---
title: "ADR-075: Rootless guest runtime — no uid 0 reaches workload or guest-controlled code, and no usable root account exists"
status: Proposed
date: 2026-06-09
related: ADR-002 (microVM security posture — claim 2 / §W2); ADR-066 (target architecture; guest layout); Plan 25 (microVM hardening); Plan 26 (W2 defense in depth); Plan 165 (entrypoint presence + sealed interactivity — claim 15); specs/02-project.md (the product-level rootless-runtime statement this ADR backs)
---

## Status

Proposed. Formalizes a posture the codebase already half-implements (the agent
runs as uid 901 under `setpriv --no-new-privs --bounding-set=-all`; per-service
uids; read-only `/etc/{passwd,group,nsswitch.conf}`) and pins down the stronger
property the product overview now asserts: *the runtime itself never runs as
root, and there is no usable root account inside the guest.* The implementing
work — the boot-shim privilege-drop invariant, the no-setuid-root build check,
and the runtime euid witness — is sequenced in a follow-on hardening plan; the
new numbered claim lands in `specs/claims/catalog.md` in that same change, when
its witnesses exist (the `check-claim-catalog` gate requires a resolvable
witness, so the catalog row cannot land ahead of the test).

## Context

Claim 2 in ADR-002 is narrow: **"no guest binary can elevate to uid 0."** Its
witnesses are `setpriv --no-new-privs` (a process cannot *gain* privileges via
`execve` of a setuid binary) plus read-only config binds so a compromised service
cannot mint a uid 0 `/etc/passwd` entry. That is an *anti-escalation* property.
It does **not**, by itself, say anything about the runtime's *default* execution
identity. A workload launched directly as uid 0 with `--no-new-privs` would
satisfy claim 2 and still be running as root.

`specs/02-project.md` ("Confining the guest") now asserts the stronger posture:

> The workload runtime does not run as root: code executes as an unprivileged
> user, no root account is available to log into or escalate to, and no guest
> binary can elevate itself to root.

That statement spans three distinct properties — *never runs as root*, *no usable
root account*, *cannot elevate* — only the third of which claim 2 currently
covers. This ADR scopes the other two precisely so the enforcement matches the
promise, and decides how the property is numbered and witnessed.

### The constraint that shapes the decision

A standard Linux boot hands PID 1 (`/init`) to userspace **as uid 0**. The kernel
provides no supported way to start init as a non-root uid. So a literal "rootless
PID 1" — init never holding uid 0 — is not achievable without exotic kernel
surgery, and chasing it buys nothing the guest can observe. What *is* achievable,
and what matters for the threat model, is that **no workload code and no
guest-controlled surface ever executes with uid 0**, and that **uid 0, where it
exists at all, exists only inside a minimal boot shim that processes no untrusted
input and surrenders the privilege irrevocably before anything reachable by a
workload runs.**

## Decision

Adopt **privilege-drop-after-minimal-init**, and define the rootless-runtime
invariant as the conjunction of the following, all enforced:

### 1. No uid 0 for workload or guest-controlled code

uid 0 exists in the guest **only** within a fixed, audited boot shim (the
`/init` / guest-netinit path) that performs a closed set of setup steps —
filesystem mounts, seccomp installation, kernel-knob and network setup, the
dev-console `/dev/pts` mount — and runs **no workload code, no entrypoint, no
agent request handling, and no other guest-controlled input** while privileged.
Before any of those guest-reachable surfaces start, the shim drops
**irrevocably** to a fixed unprivileged uid (the established 901 for the agent;
per-service uids for services) via `setpriv --no-new-privs --bounding-set=-all`.
The transition is one-way: there is no setuid path, capability, or stored
credential by which a dropped process returns to uid 0. "Transiently uid 0 during
fixed early boot, never uid 0 once anything attacker-reachable is live" is the
exact, honest shape of the guarantee — not a claim that uid 0 never exists.

### 2. No usable root account

- **No root login and no root shell.** The sole interactive surface is the
  dev-only PTY-over-vsock console (ADR-002 §claim 15 / Plan 165), which is absent
  from production builds and, even in dev, attaches to a shell running as the
  unprivileged workload uid — never a root shell. A sealed production guest has
  no interactive surface at all.
- **No setuid-root path.** The production rootfs ships **no setuid-root
  binaries** and no `su`/`sudo`/`doas`. This is enforced two ways (belt and
  suspenders): `--no-new-privs` neutralizes the setuid bit at `execve` time, and
  a build-time check asserts no setuid-root binary is present in the image in the
  first place. `/etc/{passwd,group,nsswitch.conf}` remain read-only bind mounts
  (existing W2.2), and the root entry carries no usable login.
- The dm-verity-sealed read-only rootfs (claim 3) means a workload cannot
  *introduce* a setuid-root binary at runtime either.

### 3. Numbering: a new claim, reinforcing claim 2

Add a **new numbered security claim** to ADR-002 / the catalog rather than
overloading claim 2:

> **Claim 16 — The guest runtime runs rootless.** No workload or guest-controlled
> code executes with uid 0; the production guest ships no usable root account, no
> root login or shell, and no setuid-root path.

Rationale for a new claim over folding into claim 2: claim 2 is specifically an
*anti-escalation* assertion (`--no-new-privs` + RO config binds), and it stays as
is. The rootless-runtime property is about *default execution identity and the
absence of a root account* — independently witnessable (process euid, image
setuid-bit scan, login/shell absence) and clearer as its own line. Claim 16
strictly reinforces claim 2; the two are complementary, not redundant. The
catalog row and its witnesses land with the implementing plan.

### 4. Per-backend applicability

The invariant lives in the **shared guest userspace** (the init shim, the
privilege drop, the rootfs contents) — which is identical across libkrun, Vz,
Firecracker, Apple Container, and cloud-hypervisor. The privilege drop is
therefore enforced uniformly regardless of host VMM. Backend-specific boot
differences (e.g. Vz's input-less console, per-backend PID 1 entrypoints) all
sit *before* the drop inside the boot shim, so they do not weaken the property;
any early privileged setup a backend needs is done in the shim, never by leaving
the workload at uid 0. The WASM sandbox backend has no POSIX uid model and is out
of scope for this claim — its isolation is provided by the WASM sandbox itself
(ADR-069), and the catalog row scopes claim 16 to the Linux-guest backends.

## Consequences

**Positive**
- The enforced posture matches the product promise: a workload compromise lands
  on an unprivileged uid with no route to root and no root account to target.
- Shrinks blast radius beyond claim 2: even a workload that *wanted* to run as
  root cannot, by construction.
- Independently witnessable, so it joins the CI-gated claim ledger.

**Costs / constraints**
- Anything that genuinely needs privilege at runtime (binding ports < 1024,
  certain mounts) cannot be served by "run as root." Such setup is done in the
  boot shim before the drop, or via an explicitly granted capability — never by
  running workload code as root. Workloads bind high ports; the host handles
  forwarding. This is a deliberate constraint, documented for image authors.
- The build-time no-setuid-root check is a new gate to maintain (sibling to
  `prod-agent-no-exec` / `prod-agent-no-console`).

## Alternatives considered

- **Keep only claim 2 (anti-escalation), assert nothing about default identity.**
  Rejected: claim 2 permits a workload running as root with `--no-new-privs`,
  which contradicts the product statement and leaves a larger blast radius.
- **Literal rootless PID 1 (kernel starts init non-root).** Rejected as
  impractical for a standard Linux boot; the privilege-drop-after-minimal-init
  posture yields the same guest-observable property (no workload/guest-code at
  uid 0) without kernel surgery, and is honest that uid 0 exists transiently in
  the boot shim.
- **User namespaces (map guest uid 0 to an unprivileged host uid).** Orthogonal:
  that is host-side containment of an in-guest root, whereas we are removing
  in-guest root for workload code outright. We already have hardware VM isolation
  at the host boundary; adding userns inside the guest adds complexity without
  serving this claim. Not adopted.

## Follow-ups (sequenced in the implementing plan)

- [ ] Assert the boot-shim privilege drop is unconditional and one-way; add a
  runtime witness that the workload/agent euid is non-zero once live.
- [ ] Add the build-time no-setuid-root-binary check on the production rootfs.
- [ ] Confirm no root login/shell in the production image; the dev console shell
  runs as the unprivileged workload uid.
- [ ] Append Claim 16 to `specs/claims/catalog.md` with its resolvable witnesses
  (runtime euid test + setuid-scan CI lane), and add the narrative row to
  ADR-002's claim table. The catalog gate requires the witness to exist, so this
  step lands with the tests, not ahead of them.
