# ADR-019: Guest protocol versioning, runtime readiness, and receipts

## Status

Accepted.

## Context

A host talking to a guest agent over vsock can fail in ways that look
identical from the outside but mean very different things: the backend
accepted launch but the agent isn't reachable yet; the agent is reachable
but too old for the requested verb; the agent is up but a service is
still warming; a streaming operation is backpressured rather than hung.
Without an explicit contract, every one of these collapses into the same
undifferentiated timeout or hang from the caller's point of view.

mvm already has the security substrate this needs to build on: signed
execution plans, vsock-only host-to-guest control, `deny_unknown_fields`
on every protocol type, and verified boot. What was missing was a single
contract tying protocol versioning, capability negotiation, readiness,
and backpressure together so a caller can always distinguish these
failure modes instead of reading raw logs.

## Decision

### Protocol hello, every session

Every guest-agent session — including a pure reachability probe — begins
with a `ProtocolHello`: the host sends its protocol version, minimum
supported version, host binary version, and requested capabilities; the
guest replies with the same shape. A version mismatch returns a typed
`ProtocolMismatch` naming the required remediation (`upgrade_host`,
`rebuild_guest`, or `downgrade_host`) before any operational request
dispatches. There is no untyped compatibility shim: a non-hello first
request in a session, or an incompatible version, is rejected and the
connection closed rather than silently degraded. Protocol types stay
closed Rust enums with `#[serde(deny_unknown_fields)]`.

### Capability negotiation

Capabilities are a closed enum, never ad hoc strings: `Ping`,
`IntegrationStatus`, `EntrypointStatus`, `RunEntrypoint`, `FilesystemRpc`,
`ProcessRpc`, `Console`, `UnixSocketForward`, `VolumeMount`,
`UpdateIdleTimeout`, `Readiness`. A caller that needs a capability the
guest doesn't advertise fails closed before the command runs, with the
missing capability named in the error.

### Runtime readiness is separate from lifecycle

The coarse VM lifecycle (created, running, stopped, ...) answers whether
the backend accepted and is running the VM. A separate readiness report
answers whether it's actually *usable*, tracked per component:
`control_plane` (the vsock listener itself — always ready if the agent
answered at all), `entrypoint` (workload validation), `warm_pool`
(warm-process pool state), `integrations` (drop-in integration health),
`probes` (drop-in readiness probes), and `volumes` (mount state). Each
component reports one of `Disabled` (not configured for this image —
distinct from `Ready`, never conflated with it), `Starting`, `Ready`, or
`Failed { message }`. Readiness never invents a new lifecycle state; it's
a status detail layered on top of the existing one.

### Control plane and data plane stay separate

Small control requests and responses ride the guest protocol described
above. Large data — command output, transferred artifacts — moves over
streaming or chunked paths with their own frame caps. Payload bytes are
never copied into audit entries, readiness reports, or receipts; where a
receipt needs to reference output, it stores a hash, not the bytes.

This is a logical and scheduling separation within the authenticated guest
protocol, not a claim that every verb has a dedicated socket. The agent
classifies every verb exhaustively, caps every encoded request and response at
256 KiB, admits at most 64 concurrent sessions, and reserves 16 of those slots
for control-plane work by limiting data-plane requests to 48. Filesystem
payloads and process output use 15.5 KiB chunks so JSON encoding cannot consume
the frame headroom. That figure is derived, not chosen: content crosses two
nested `Vec<u8>` JSON encodings before it reaches the wire — the request or
response body, and then the sealed envelope's ciphertext — and the worst-case
four-bytes-per-byte expansions multiply. Sizing the chunk against a single
encoding is what previously let a chunk pass the handler's own frame check and
fail the identical check on the sealed envelope. Dedicated raw transports, such as console and port-forward
sockets, remain separate and accept only the host vsock CID.

### Backpressure is typed, non-terminal product state

A backpressured operation (today: `ProcWait`) reports one of a closed set
of reasons rather than simply hanging: the guest agent is unreachable
within its grace period, one or more service-health probes are still
pending (naming which services), the host isn't draining output fast
enough, an input buffer is full, an artifact transfer is paused, or the
shared builder VM is occupied by another build. Backpressure is
non-terminal — the caller keeps waiting, now with a reason instead of
silence.

### The managed builder VM is the only builder mode

`mvmctl` always drives Nix builds through its own managed builder VM.
There is no host-Nix path: `mvmctl` never shells out to a host `nix`
binary, never consults a host Nix installation, and never falls back to
one implicitly or explicitly. A host happening to have Nix installed
produces identical behavior to a host that doesn't. This is stricter than
merely defaulting to the managed builder VM — the alternative doesn't
exist as a selectable mode.

### Receipts are default-safe

A successful `run`/`up`/`build` invocation can record a small receipt:
what was invoked (hashed, not the raw argv or env values), the outcome
(exit code, success, and hashes of stdout/stderr rather than their raw
bytes), and enough metadata (backend, network posture, egress
enforcement fidelity) for later review. A receipt never stores raw argv
values, environment values, stdin, stdout, stderr, secrets, or tokens —
only their hashes and metadata survive.

## Consequences

**Positive.** Callers can distinguish "booting," "agent unavailable,"
"service not ready," "protocol mismatch," and "backpressured" without
reading raw logs. The managed-builder-only posture removes an entire
class of "worked on my machine because I have Nix installed" bug.
Receipts and readiness share one vocabulary across the CLI and any other
consumer of the same guest protocol.

**Negative.** Every guest-agent caller that depends on a capability
beyond the unconditional baseline has to negotiate before dispatch.
Receipt redaction needs its own tests to keep proving raw payloads never
land in a receipt, since a regression there is a silent leak, not a
loud failure.

**Non-goals.** This ADR does not commit to a structured progress-event
system across CLI text, JSON output, and other consumers, or to a
dedicated `explain`-style command mapping failures to remediations —
neither exists today; either is a future ADR's decision if built.
