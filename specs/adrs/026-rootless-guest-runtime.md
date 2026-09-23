# ADR-026: Rootless guest runtime

## Status

Proposed. Formalizes a posture the codebase already half-implements — the agent
runs as an unprivileged uid through the first-party static
`/sbin/mvm-setpriv --no-new-privs` helper, each service runs under its own uid,
and `/etc/{passwd,group,nsswitch.conf}` are read-only bind mounts — and pins
down the stronger property the product overview asserts: the runtime
itself never runs as root, and there is no usable root account inside the
guest. The build-time no-setuid-root check and the runtime euid witness
this ADR requires do not exist yet.

## Context

mvm's existing anti-escalation posture is narrow: no guest binary can
elevate to uid 0. Its witnesses are `--no-new-privs` (a process cannot
gain privilege via `execve` of a setuid binary) plus the read-only config
binds that stop a compromised service from minting a uid-0 `/etc/passwd`
entry. That is an anti-escalation property; it says nothing about the
runtime's *default* execution identity. A workload launched directly as
uid 0 with `--no-new-privs` still satisfies that property while running
as root.

The product overview now asserts a stronger posture: the workload
runtime does not run as root at all — code executes as an unprivileged
user, no root account exists to log into or escalate to, and no guest
binary can elevate itself to root. That statement spans three properties
— never runs as root, no usable root account, cannot elevate — of which
only the third is currently enforced. This ADR scopes and decides how to
enforce the other two.

### The constraint that shapes the decision

A standard Linux boot hands PID 1 to userspace as uid 0; the kernel gives
no supported way to start init as a non-root uid. A literal "rootless PID
1" is therefore not achievable without exotic kernel surgery, and chasing
it buys nothing observable from the guest. What is achievable, and what
matters to the threat model, is that no workload code and no
guest-controlled surface ever executes with uid 0, and that uid 0 —
where it exists at all — exists only inside a minimal boot shim that
processes no untrusted input and surrenders the privilege irrevocably
before anything workload-reachable runs.

## Decision

Adopt privilege-drop-after-minimal-init. The target rootless-runtime invariant
is the conjunction below. The status section records which parts are already
enforced and which witnesses still block acceptance.

### 1. No uid 0 for workload or guest-controlled code

uid 0 exists in the guest only within a fixed, audited boot shim (the
`/init` and network-init path) that performs a closed set of setup steps
— filesystem mounts, seccomp installation, kernel-knob and network setup,
the dev-console mount — and runs no workload code, no entrypoint, no
agent request handling, and no other guest-controlled input while
privileged. Before any guest-reachable surface starts, the shim drops
irrevocably to a fixed unprivileged uid via the first-party static helper
`/sbin/mvm-setpriv` (`--reuid`, `--regid`, `--clear-groups`, and
`--no-new-privs`). The agent separately narrows the Linux capability bounding
set before workload exec. The transition is one-way:
no setuid path, capability, or stored credential lets a dropped process
return to uid 0. The exact, honest shape of the guarantee is "transiently
uid 0 during fixed early boot, never uid 0 once anything
attacker-reachable is live" — not a claim that uid 0 never exists.

### 2. No usable root account (target state)

No root login and no root shell: the sole interactive surface is the
dev-only PTY-over-vsock console, absent from production builds and, even
in dev, attached to a shell running as the unprivileged workload uid,
never as root. A sealed production guest has no interactive surface at
all. `--no-new-privs` makes setuid bits inert at `execve` time. Acceptance
also requires a build-time scan proving that the production rootfs contains no
setuid-root binary and no `su`/`sudo`/`doas`; that scan has not shipped and is
deferred with the runtime-euid witness below. Until it does, this ADR does not
claim that image contents satisfy that stronger property.
`/etc/{passwd,group,nsswitch.conf}` stay read-only bind mounts and the root
entry carries no usable login. The dm-verity-sealed read-only rootfs prevents
a workload from changing the image contents at runtime.

### 3. Claim numbering is deferred to the implementing change

This property is independently witnessable — process euid, an image
setuid-bit scan, login/shell absence — and reinforces rather than
replaces the existing anti-escalation claim, which stays exactly as
scoped today. It does not yet carry a claim number: the claims catalog is
append-only and a row cannot land ahead of a resolvable witness, so
numbering happens in the same change that ships the runtime-euid test and
the setuid-scan CI lane, not in this ADR.

### 4. Per-backend applicability

The invariant lives in the shared guest userspace — the init shim, the
privilege drop, the rootfs contents — which is identical across every
Linux-guest backend, so the privilege drop is enforced uniformly
regardless of host VMM. Backend-specific boot differences all sit before
the drop inside the boot shim, so they never weaken the property: any
early privileged setup a backend needs happens in the shim, never by
leaving the workload at uid 0.

## Consequences

**Positive.** Once the missing witnesses and image scan land, the posture will
match the product promise: a workload compromise lands on an unprivileged uid
with no route to root and no root account to target. It will shrink blast
radius beyond the existing anti-escalation claim and is independently
witnessable, so it can join the CI-gated claim ledger with its tests.

**Costs.** Anything that genuinely needs privilege at runtime (binding a
port below 1024, certain mounts) cannot be served by "run as root" —
such setup happens in the boot shim before the drop, or via an explicitly
granted capability, never by running workload code as root. Workloads
bind high ports and the host handles forwarding; this is a deliberate,
documented constraint for image authors. The build-time no-setuid-root
check is a new gate to build and maintain, alongside the existing
production-agent symbol-absence gates.

## Alternatives considered

Keeping only the existing anti-escalation claim and asserting nothing
about default identity was rejected: it permits a workload running as
root with `--no-new-privs`, which contradicts the product statement and
leaves a larger blast radius. A literal rootless PID 1 (the kernel
starting init as non-root) was rejected as impractical for a standard
Linux boot; privilege-drop-after-minimal-init yields the same
guest-observable property without kernel surgery, and is honest that uid
0 exists transiently in the boot shim. User namespaces (mapping guest uid
0 to an unprivileged host uid) were not adopted: that is host-side
containment of an in-guest root, orthogonal to removing in-guest root for
workload code outright, and it adds complexity on top of hardware VM
isolation without serving this decision.

## Follow-ups

- Assert the boot-shim privilege drop is unconditional and one-way; add a
  runtime witness that the workload/agent euid is non-zero once live.
- Add the build-time no-setuid-root-binary check on the production
  rootfs.
- Confirm no root login or shell in the production image; the dev
  console shell runs as the unprivileged workload uid.
- Append the new claim to the catalog with its resolvable witnesses once
  they exist, and add the narrative row to the security-posture ADR's
  claim table in the same change as the tests.
