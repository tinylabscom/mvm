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

### Session prelude

Every guest-agent session — including a pure reachability probe — begins
with the authenticated handshake. In it the guest's `SessionHelloAck` carries
a `ControlOffer`: its control protocol range, its agent version, and the
closed set of capabilities it serves. The offer is covered by the guest's
handshake proof and by the host's transcript signature, so a swapped or
stripped offer fails the handshake. The host's protocol range rides in
`SessionHelloConfirm`; it is not signed, because a forged range can only make
the guest refuse. Both sides refuse before any request dispatches: the host
refuses a guest whose ack carries no offer or whose range does not overlap its
own, before it writes the confirm; the guest refuses a host whose range does
not overlap, or that sent none, by answering the first request with a typed
`ProtocolMismatch` and closing without dispatching it. The remedy is
`upgrade_host` when the host's newest protocol is below the guest's oldest and
`rebuild_guest` when the host's oldest is above the guest's newest; an ack with
no offer is `rebuild_guest`. There is no compatibility shim: a peer that offers
no advertisement, or an incompatible range, is refused with a typed remedy, and
control protocol 3 does not speak to 2. The other planes that share this
handshake send no offer and no range, and a plane that receives one refuses it.
Protocol types stay closed Rust enums with `#[serde(deny_unknown_fields)]`.

### Capability negotiation

Capabilities are a closed enum, never ad hoc strings: `Ping`,
`ResourceUsage`, `IntegrationStatus`, `EntrypointStatus`, `RunEntrypoint`,
`AgentPrompt`, `Drive`, `RunExtension`, `FilesystemRpc`, `ProcessRpc`,
`Console`, `UnixSocketForward`, `VolumeMount`, `UpdateIdleTimeout`,
`Readiness`. Every request verb maps, exhaustively, to the capability it
needs or to none (`Verb::capability`). A caller that needs a capability the
guest doesn't advertise fails closed before the command runs, with the
missing capability named in the error. The host checks the guest's signed
advertisement at the single point where it writes a request
(`HostControlSession::send`); no other writer exists on the host. The
advertisement only narrows what the host sends. It is never read by an
authorization decision: the agent's profile gate, signed verb grants and
seccomp tier decide what runs, and a guest that advertises more than it serves
gains nothing. The advertisement is held for the life of one connection and is
never persisted or reused across a restore.

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

**Negative.** Callers do not negotiate; the session checks each verb against
the advertised set. A guest agent built before the advertisement existed is
refused with `rebuild_guest`, and so is any runtime that still carries
control protocol 2. Receipt redaction needs its own tests to keep proving raw payloads never
land in a receipt, since a regression there is a silent leak, not a
loud failure.

**Non-goals.** This ADR does not commit to a structured progress-event
system across CLI text, JSON output, and other consumers, or to a
dedicated `explain`-style command mapping failures to remediations —
neither exists today; either is a future ADR's decision if built.
