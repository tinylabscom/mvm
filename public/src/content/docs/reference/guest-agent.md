---
title: Guest Agent
description: The mvm guest agent provides host visibility and control over microVMs via vsock.
---

Every microVM built with `mkGuest` exposes **mvm-guest-agent**, a lightweight
Rust daemon that runs inside the guest on vsock port 5252.

How the agent reaches the guest depends on the image policy:

- **Dev / preferred-overlay images** keep a baked copy in the rootfs.
- **Sealed / required-overlay images** boot through the read-only,
  verity-protected runtime overlay mounted at `/mvm/runtime`; `/init` execs the
  overlay-resident agent from there instead of falling back to a baked rootfs
  copy.

The runtime overlay is **version-matched** to the host `mvmctl` build and is
treated as a boot-time dependency. A running VM keeps the agent/runtime version
it booted with until restart; mvm does not hot-swap a different runtime overlay
into a live guest. Stopped VMs pick up an updated version-matched overlay on
their next boot.

## Capabilities

| Capability | Description |
|------------|-------------|
| **Health checks** | Runs per-service health commands on a schedule, reports results to the host |
| **Worker status** | Tracks idle/busy state by sampling `/proc/loadavg` — used by fleet autoscaling |
| **Snapshot lifecycle** | Coordinates sleep/wake: flushes data, drops page cache before snapshot, signals restore |
| **Integration management** | Loads service definitions from `/etc/mvm/integrations.d/*.json` |
| **Probes** | Loads read-only system checks from `/etc/mvm/probes.d/*.json` (disk usage, custom metrics) |
| **Filesystem diff** | Walks the overlay upper dir to report files created, modified, or deleted since boot |
| **Remote command** | Dev-only: execute commands inside the guest via vsock |

## Runtime location

The guest agent binary is not always part of the immutable rootfs closure:

- On fallback/dev images it lives in the rootfs as before.
- On overlay-required images it lives on the read-only runtime overlay under
  `/mvm/runtime`.

Other guest-runtime helpers, including `mvm-guest-netinit` and
`mvm-egress-client`, follow the same overlay-first contract on
overlay-required boots.

Only guest-executed runtime helpers move into that overlay. Host-executed
builder/bootstrap binaries remain outside it.

That split is intentional. It lets mvm update the guest runtime for **future
boots** without rebuilding the workload rootfs, while keeping the runtime sealed
and version-pinned for the life of a running VM.

## Protocol

The agent communicates using **length-prefixed JSON frames** over vsock on every
supported microVM backend:

1. Host writes `CONNECT 5252\n` to the socket
2. Agent responds with `OK 5252\n`
3. All subsequent communication is request/response pairs

Request types: `ping`, `status`, `sleep-prep`, `wake`, and more.

## Control plane and data plane

The agent has separate logical **control** and **data** planes. They share the
authenticated guest-protocol listener, but classification is exhaustive and
drives admission: at most 64 requests run concurrently, data-plane work is
limited to 48, and the remaining 16 slots stay available for health,
readiness, lifecycle, and cancellation requests. A saturated transfer cannot
consume all control capacity.

Every encoded request and response is capped symmetrically at 256 KiB before
any bytes are written. User-content chunks are at most 15.5 KiB, leaving enough
headroom for worst-case JSON encoding and the response envelope.

That chunk size is derived from the 256 KiB cap rather than chosen. Content is
encoded twice on its way to the wire: once as a `Vec<u8>` in the request or
response body, and again as the sealed envelope's ciphertext, which is itself a
`Vec<u8>`. Neither hop is base64, so the worst case — four characters per byte,
`255,` — applies twice and the expansions multiply. The split is
orthogonal to the agent profile gate: `Exec` is dev-only and data-plane;
`Ping` is always available and control-plane.

### Control-plane verbs

Small bounded JSON in and out, with no user process or file payload bytes.

| Verb | Response shape | Notes |
|---|---|---|
| `ProtocolHello` | `ProtocolHelloAck` / `ProtocolMismatch` | Required first request in every session; protocol v2 is a hard cutover. |
| `Ping` | `Pong` | Reachability probe. Requires `Ping` capability. |
| `WorkerStatus` | `WorkerStatus { status, last_busy_at }` | Idle/busy sampled from `/proc/loadavg`. |
| `ReadinessStatus` | `ReadinessStatusReport` | Component-level readiness (see "Readiness model" below). |
| `IntegrationStatus` | `IntegrationStatusReport { integrations: Vec<…> }` | One per declared integration. |
| `EntrypointStatus` | `EntrypointStatusReport` | Validation result + warm-pool state. |
| `ProbeStatus` | `ProbeStatusReport { probes: Vec<ProbeResult> }` | One per declared probe. |
| `SleepPrep` / `Wake` / `PostRestore` / `CheckpointIntegrations` | Ack | Snapshot lifecycle handshakes. |
| `UpdateIdleTimeout` | Ack with previous + new values | Adjusts the idle-eviction window. |
| `MountVolume` / `UnmountVolume` | `MountVolumeResult` (closed enum) | Volume metadata only — no file contents. |
| `ProcStart` / `ProcSignal` / `ProcKill` / `ProcList` | `ProcResult` (closed enum) | Process control. `ProcStart` accepts an `argv` up to capped length but does not echo it back. |
| `FsStat` / `FsMkdir` / `FsRemove` / `FsMove` | `FsResult` (closed enum) | Bounded filesystem metadata and mutations. |
| `ConsoleOpen` / `ConsoleClose` / `ConsoleResize` | Ack with vsock port | Allocates a PTY forwarder. The PTY itself runs on a different vsock port — that's the data plane. |

### Data-plane verbs

Streaming, chunked, or potentially large bounded transfers. These requests
share the 48-request data admission budget.

| Verb | Flow | Frame cap | Chunk size | Terminal | Backpressure | Payload in audit? |
|---|---|---|---|---|---|---|
| `RunEntrypoint` | Request → `EntrypointEvent` stream | 256 KiB per event | 15.5 KiB stdout/stderr | `Exit` / `Killed` / `TimedOut` / `Error` | Bounded process buffers. | No. |
| `ProcWait` | Request → `ProcWaitEvent` stream | 256 KiB per event | 15.5 KiB stdout/stderr | `Exit` / `Killed` / `TimedOut` / `Error` | Typed non-terminal backpressure events. | No. |
| `ProcSendInput` | Bounded request → ack | 256 KiB | At most 15.5 KiB per protocol frame | `InputAccepted` | Caller retries subsequent chunks. | No; byte count only. |
| `FsRead` / `FsWrite` | Repeated offset requests → bounded responses | 256 KiB | 15.5 KiB | Each chunk response | Caller advances the offset; the first write truncates and later chunks do not. | No; offsets, sizes, and counts only. |
| `FsList` / `FsDiff` | Request → bounded metadata response | 256 KiB | Protocol-bounded result | Response itself | Result caps and frame cap fail closed. | No file contents. |
| `Exec` / `ExecBatch` / `RunCode` (dev-only) | One-shot request and capture | 256 KiB | Protocol-bounded result | Response itself | Oversized encoded responses fail closed. | No. |
| Console PTY traffic | Raw bytes on a dedicated vsock port | Raw transport | TTY-shaped reads | Close or PTY exit | Kernel/socket backpressure; only the host CID may connect. | No. |
| Declared ingress | Authenticated FlowMux frames on `NetworkFlow` | 256 KiB per frame | Credit-bounded stream chunks | Flow close/refusal | Shared per-VM FlowMux budget. | Metadata only; payload bytes never enter audit. |

### Redaction invariant

The following audit / readiness / progress / receipt surfaces are
guaranteed by ADR-019 §4 / §5 to **never** contain data-plane
payload bytes. The list is the authoritative one:

- `~/.mvm/audit/<tenant>.jsonl` chain-signed entries.
  Detail strings carry IDs, hashes, counts, and policy tags — not
  argv values, env values, stdin, stdout, stderr, file contents,
  or filesystem paths inside the guest.
- `InstanceReadiness::ServicesStarting { pending }` /
  `Degraded { unhealthy }` — both carry only **service names** (the
  declared integration `name` field). Health-check command output
  never appears.
- `ProcWaitEvent::Backpressure { reason, detail }` — the `detail`
  string is metadata only: byte counts, threshold, and cap.
- `BackpressureReason::ServiceHealthPending { pending }` — service
  names only.
- Receipts written by `mvmctl run` / `mvmctl machine run` / `mvmctl machine build`
  store hashes and metadata. Raw stdout / stderr /
  stdin / env / argv values are never written.
- `mvmctl machine ls --json` rows — the `readiness` and
  `last_readiness_change_at` fields render directly from the
  registry; the registry only stores the closed enum + RFC 3339
  timestamps.

The classification is encoded by `Verb::traffic_plane()`. Because its match is
exhaustive, adding a verb requires choosing a plane at compile time.

## Profile gate

Every guest image declares an **agent profile** in its
`/etc/mvm/security.json` (plan 76 Phase 1). The profile is the
dispatcher-side allowlist for vsock verbs — dev-only requests
sent to a sealed-prod agent are rejected before any handler runs:

| Profile | Effective verb set | Used by |
|---------|-------------------|---------|
| `sealed-prod` (default) | Lifecycle, status, entrypoint, sleep/wake, volume mount/unmount, idle-timeout updates, and the entrypoint stdin verbs `StreamInput` / `CloseStreamInput`. The full ADR-001 production-safe surface. The stdin verbs write to an entrypoint fixed at admission and select nothing; the host gates them on a grant in the signed plan, so a prod-safe verb is not an ungated one — see [Workload input](/guides/workload-input/). | Production images. The policy file lives on a dm-verity rootfs (ADR-001 §W3) so the profile cannot be widened at runtime. |
| `dev` | `sealed-prod` plus shell `Exec`, process RPC, filesystem RPC, console PTY, port forwarding, and `RunCode`. | Dev-tier images built with the `interactive` feature — the ones `mvmctl machine console` or `mvmctl machine run -it` can attach to. |
| `builder` | Reserved for builder-only verbs. The current builder agent speaks a separate `BuilderRequest` protocol, so this profile is wire-stable but unused for the tenant agent. | Future builder VM agent if/when its verbs land on the tenant wire. |

Rejected requests return a typed `UnsupportedInProfile` response:

```json
{ "UnsupportedInProfile": { "profile": "sealed-prod", "verb": "Exec" } }
```

SDK callers can branch on capability without parsing message text —
this is the protocol-layer analog of
`ProcErrorKind::UnsupportedInProduction` for process RPC.

The profile gate is the runtime security boundary for the universal agent.
The same artifact carries the DevOnly handlers in every image, but the
dispatcher refuses them unless the runtime profile and signed `VerbGrant`
authorize the request. Both checks run on every request.

### Run-shaped agent grants

The image profile remains an artifact property, but the host's attenuated
ProdSafe grant is a property of the launch. A baked-entrypoint run on a
non-dev profile is eligible for that restricted grant; a PTY (`ConsoleOpen`) or
an ad-hoc argv (`Exec`) run is not, because those paths require DevOnly verbs.
The decision does not depend on an OCI rootfs being marked sealed. Console
attachment is a separate host-side gate and remains unavailable for sealed
production images; a restricted grant never widens the guest profile or adds
interactive handlers.

## Readiness model

Plan 76 Phase 2 binds the vsock control port **before** entrypoint
validation and warm-process pool startup. Phase 3 extends the same
pattern to integration / probe drop-in scans. The agent accepts
`Ping` / `ReadinessStatus` / `EntrypointStatus` immediately, and
`RunEntrypoint` returns a typed `RunEntrypointError::NotReady` until
entrypoint validation completes.

Background init threads in order of when they start:

1. Entrypoint validation → warm-pool startup (serial inside one
   thread because the pool depends on `VALIDATED_ENTRYPOINT`).
2. Integration drop-in scan + health-loop spawn.
3. Probe drop-in scan + probe-loop spawn.

All three run in parallel after the accept loop is already serving
control-plane traffic. A malformed drop-in cannot block bind or
delay `Ping`; a slow `after_start.sh` only delays
`warm_pool_ready_ms`, not the rest of the readiness report.

A host queries the live state via the `ReadinessStatus` verb:

```json
{
  "ReadinessStatusReport": {
    "control_plane": "ready",
    "entrypoint": "starting",
    "warm_pool": "disabled",
    "integrations": "ready",
    "probes": "disabled",
    "volumes": "disabled",
    "profile": "sealed-prod",
    "boot_millis": {
      "agent_started_ms": 7,
      "vsock_bound_ms": 7,
      "first_accept_ms": 12,
      "entrypoint_ready_ms": null,
      "warm_pool_ready_ms": null,
      "integrations_ready_ms": null,
      "probes_ready_ms": null
    }
  }
}
```

`ComponentState` values:

| State | Meaning |
|-------|---------|
| `disabled` | Subsystem isn't configured for this image (no policy → no state machine to advance). Distinct from `ready` so the host can tell "image opted out" from "still warming". |
| `starting` | Background init in progress. `RunEntrypoint` while `entrypoint = starting` returns `NotReady` — the host should poll readiness and retry. |
| `ready` | Subsystem is up and accepting work. |
| `failed` | Subsystem failed to initialize. Carries a short human-readable `message` (no secrets, no host paths the caller doesn't already know). For `entrypoint`, this maps to `RunEntrypoint` returning the existing `EntrypointInvalid`. |

`BootTimingReport` exposes monotonic milliseconds since agent
process start. Phase 3 closed out the per-component `*_ready_ms`
fields by stamping them on each first transition out of
`Starting`. A cold-tier image with no warm pool / integrations /
probes correctly reports `None` for those — the stamp only fires
once a background init thread actually ran.

### Host commands

- `mvmctl machine wait <vm> --for <component> [--timeout <secs>]` —
  Blocks until the named component reaches `Ready`, `Disabled`,
  or `Failed`. Targets: `control-plane`, `entrypoint`,
  `warm-pool`, `integrations`, `probes`, or `all` (the default).
  Exit codes: `0` ready, `65` (`EX_DATAERR`) component failed
  with message printed, `75` (`EX_TEMPFAIL`) deadline hit.
  `Disabled` counts as `Ready` (intentionally — a cold-tier
  image asking `--for warm-pool` must not spin forever).

- `mvmctl machine boot-report <vm> [--json]` — Single round-trip; prints
  the same `ReadinessReport` `mvmctl machine wait` polls, including the
  per-phase timing table. Useful right after `mvmctl machine run` to
  inspect cold-path latency.

Both verbs require `GuestCapability::Readiness` from the
protocol-hello prelude; the agent advertises it in
`supported_capabilities()`.

## Health Checks

Health checks defined in `mkGuest`'s `healthChecks` parameter are automatically written to `/etc/mvm/integrations.d/` at build time:

```json
{
  "name": "my-service",
  "health_cmd": "curl -sf http://localhost:8080/health",
  "health_interval_secs": 10,
  "health_timeout_secs": 5
}
```

The agent picks them up on boot and begins periodic checks immediately.

### Startup Grace Period

Services that take time to initialize (e.g., running database migrations) can specify a grace period. During the grace period, health check failures are suppressed and the service reports `Starting` status instead of `Error`:

```json
{
  "name": "my-service",
  "health_cmd": "curl -sf http://localhost:8080/health",
  "health_interval_secs": 10,
  "health_timeout_secs": 5,
  "startup_grace_secs": 120
}
```

In a Nix flake, set the grace period via `startupGraceSecs`:

```nix
healthChecks.my-app = {
  healthCmd = "curl -sf http://localhost:8080/health";
  healthIntervalSecs = 10;
  startupGraceSecs = 120;  # suppress failures for 2 minutes after boot
};
```

After the grace period expires, normal health reporting resumes.

## Querying from the Host

```bash
# Check guest console output
mvmctl machine logs my-vm

# Follow logs in real time
mvmctl machine logs my-vm -f

# List VMs and their status
mvmctl machine ls
```

Health check results and probe output are included in the guest console logs.

## Probes

Probes are read-only system checks loaded from `/etc/mvm/probes.d/*.json`:

```json
{
  "name": "disk-usage",
  "command": "df -h /mnt/data | tail -1 | awk '{print $5}'",
  "interval_secs": 60
}
```

Probe results are reported via the vsock protocol and included in guest console logs.

## Snapshot Coordination

Before creating a snapshot, the host sends a `sleep-prep` request. The agent:

1. Runs checkpoint commands for each integration
2. Syncs filesystem buffers
3. Drops page cache
4. Responds with "ready"

On wake (checkpoint or snapshot restore), the host sends a `wake` request and the agent runs restore commands for each integration.

## Filesystem Diff

The agent can report all filesystem changes since boot by walking the overlay upper directory. When the rootfs is mounted read-only with an overlay (`readOnlyRoot = true` in mkGuest), all writes go to the upper dir. The agent detects:

- **Created** files: present in the overlay upper dir
- **Deleted** files: overlay whiteout files (`.wh.*`)
- **Modified** files: existing files overwritten in the upper dir

Query the diff from the host:

```bash
mvmctl machine diff my-vm         # human-readable output
mvmctl machine diff my-vm --json  # JSON array of {path, kind, size}
```

This is useful for auditing what an AI agent modified during execution.
