# ADR-021: pid0 portability boundary

## Status

Accepted.

## Context

mvm runs guest workloads across multiple hypervisor backends —
Firecracker, libkrun, HVF, and QEMU as workload/dev backends, plus a
Mock backend for testing. The guest-side init layer (pid 1 →
`mvm-verity-init` → `switch_root` → minimal init → `mvm-guest-agent`) is
structurally identical across every backend, but that convention lives
implicitly across several source files and the per-backend supervisor
wiring rather than as one stated contract. A contributor adding a new
backend has to reverse-engineer what "this thing is a valid mvm guest"
means by reading existing implementations.

This ADR makes the contract explicit: what any pid0 implementation —
today's Rust binaries, or a future rewrite — has to do to be a valid mvm
guest. It does not mandate an implementation language and does not
change any current backend's behavior.

## Decision

### 1. What the pid0 control surface is

The pid0 control surface is the guest-side code the host's control plane
talks to or depends on: the init binary (`mvm-verity-init` in the verity
initramfs path, then whatever pid 1 is after `switch_root`), one-shot
pre-workload binaries (`mvm-guest-netinit`, which installs mandatory deny
routes before the agent starts), the long-lived control-plane agent
(`mvm-guest-agent`, uid 901, vsock port 5252), and any addon binaries
that are part of the minimum boot sequence.

It excludes: the workload itself (spawned by the agent on
`RunEntrypoint`, as a child of the agent, not part of pid0); and the
host-side services broker — a guest reaches it as a client over its own
vsock port, but the broker's processes run on the host, are addressed per
tenant rather than per VM, and are not part of the pid0 contract.

### 2. Transport contract

Every backend MUST provide virtio-vsock with a stable CID assignment
(host CID 2, guest CID 3 by convention); a backend that abstracts the CID
space internally must expose the guest end as a Unix-domain socket the
host supervisor can bind. Every payload on that channel is wrapped in an
`AuthenticatedFrame` — Ed25519-signed, with a session id and monotonic
sequence number for replay defense. **No alternate control transport.**
Backends MUST NOT route control-plane traffic over virtio-net,
virtio-fs, block devices, or any side channel. A backend that cannot
satisfy vsock with this framing is not a valid mvm backend.

### 3. Boot handshake contract

The guest agent MUST implement the protocol-hello sequence: the first
message in every session is a `ProtocolHello` carrying protocol version,
minimum supported version, agent version, and supported capabilities.
Mismatch returns a typed `ProtocolMismatch` before any other dispatch —
there is no compatibility shim; an incompatible guest must be rebuilt and
an incompatible host must be upgraded. The agent MUST emit readiness
state tracking each of: control plane, entrypoint, warm pool,
integrations, probes, and volumes. A component not applicable to a given
image reports as disabled, never as failed.

### 4. Lifecycle states

The pid0 control surface MUST move through these states in order:

1. **boot** — kernel-to-userspace handover; `mvm-verity-init` sets up
   dm-verity (when verity-enabled), then `switch_root`.
2. **netinit** — the mandatory-deny-route installer runs and exits
   before the agent starts.
3. **agent-listen** — the agent is bound to its vsock port and serving
   `ProtocolHello`.
4. **ready** — the agent has reported control-plane readiness; the host
   may dispatch any production-safe verb.
5. **workload** — `RunEntrypoint` has spawned the workload as a child of
   the agent; entrypoint events stream to the host.
6. **drain** — the host issued shutdown; the agent stops accepting new
   work, drains in-flight RPCs, and signals the workload to stop.
7. **shutdown** — the agent exits cleanly; init reaps it; the backend
   tears down the VM.

States 1–3 are mandatory in order; 4–7 may overlap or condense for
non-interactive workloads, but their relative ordering must hold.

### 5. What pid0 MUST NOT do

No host-fs assumptions — the guest never assumes any host path is
visible; volume mounts arrive over an explicit RPC bound at runtime, not
inferred from environment or hardcoded. No SSH — no sshd, no SSH keys, no
SSH users, in any rootfs; the only interactive path is the dev-only PTY
over vsock. No shell-out beyond audited verbs — the agent does not exec
arbitrary binaries on the host's behalf outside the process-start and
entrypoint paths that emit audit events, and production builds strip the
general-purpose exec handler entirely. No broad seccomp escape — the
agent runs under `setpriv --bounding-set=-all --no-new-privs` with the
standard seccomp profile; a pid0 implementation may not require a more
permissive profile than verity-init's own dm-verity setup needs. No
bypass of `AuthenticatedFrame` — every host-guest control message is
signed and replay-protected, and no backend may introduce an out-of-band
control channel that skips verification.

### 6. Cross-platform constraints

**pid0 binaries dynamically link against glibc, bundled with their own
loader.** They are not statically linked, because they are mounted at
runtime into arbitrary guest userspaces — including OCI-pulled rootfs
trees that carry no compatible libc of their own — via the runtime
overlay disk, which bundles a dynamic loader, libc, and libgcc and
relinks every overlay binary to load against that bundled copy rather
than whatever the surrounding rootfs provides. This is a distinct
population from the separate, Linux-only, builder-VM-only binaries
(embedded and cross-compiled as static-musl by the CLI's own build
process) that never run inside a workload guest.

**Kernel cmdline is a stable surface.** `mvm.roothash=<64-hex>` (required
when verity-enabled), `mvm.runtime_roothash=<64-hex>` (required when the
runtime overlay is in use), `console=hvc0` (required for libkrun),
`init=/init` (points at verity-init or minimal init). Additional flags a
backend introduces MUST use the `mvm.*` prefix and be documented here.

**No host Nix dependency.** The guest boots from an image built inside a
managed builder VM; mvmctl never evaluates Nix on the host and never
falls back to a host Nix installation.

### 7. Audit chain integration

Every RPC dispatch in the pid0 control surface MUST emit an audit event
carrying the verb name. A pid0 implementation that bypasses the host's
audit emission path is invalid.

### 8. Language neutrality

This ADR does not mandate any implementation language. The current Rust
implementation satisfies the contract; any future rewrite satisfies it
equally as long as it preserves the contract surfaces byte-identically:
the `AuthenticatedFrame` wire format, the guest request/response/
capability enum variants, the `ProtocolHello` semantics, the audit-emit
invariant, and the kernel cmdline contract.

## Consequences

**Positive.** A new backend has a single document to satisfy instead of
reverse-engineering the convention from existing implementations. A
future agent rewrite has an explicit contract to meet rather than an
implicit one to preserve by accident.

**Negative.** This ADR documents status quo, not a fully independently
re-derived spec; a backend added later may surface a contract gap this
document needs an amendment to close.

**Neutral.** This ADR changes no current binary's behavior — it states
what the system already does and commits to keeping doing it.

## Out of scope

The host-side services broker and its process model are host-side
concerns; the guest's client code that calls into it is not part of the
pid0 contract. Encrypting the vsock channel beyond the existing
authenticated-cleartext framing is a separate decision if ever made. The
control-plane-versus-data-plane partition for large payloads is covered
by the guest protocol versioning decision, not repeated here.
