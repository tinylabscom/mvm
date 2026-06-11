---
title: Guest Agent
description: The mvm guest agent provides host visibility and control over microVMs via vsock.
---

Every microVM built with `mkGuest` includes **mvm-guest-agent**, a lightweight Rust daemon that runs inside the guest on vsock port 5252.

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

## Protocol

The agent communicates using **length-prefixed JSON frames** over vsock (Firecracker, Apple Container, microvm.nix) or a unix socket (Docker):

1. Host writes `CONNECT 5252\n` to the socket
2. Agent responds with `OK 5252\n`
3. All subsequent communication is request/response pairs

Request types: `ping`, `status`, `sleep-prep`, `wake`, and more.

## Control plane and data plane

Plan 74 / ADR-053 §4 splits the agent's wire surface into a
**control plane** (small, single-frame, bounded requests/responses)
and a **data plane** (streaming or chunked operations where the
payload size is dominated by user content, not metadata). The
distinction is load-bearing for the redaction invariant: data-plane
payload bytes never appear in audit records, readiness messages,
progress events, backpressure events, or receipts. The control
plane is fully tracked in those surfaces; the data plane carries
hashes and counts only.

Every verb in the table below is also gated by an agent profile
(see "Profile gate" below) — but the control-plane / data-plane
split is **orthogonal**. `Exec` (dev-only) is a data-plane verb;
`Ping` (always available) is control-plane.

### Control-plane verbs

Small bounded JSON in / small bounded JSON out. Maximum response
frame size is `MAX_FRAME_SIZE = 256 KiB` (`crates/mvm-guest/src/vsock.rs`).
No streaming. No payload bytes from user processes.

| Verb | Response shape | Notes |
|---|---|---|
| `ProtocolHello` | `ProtocolHelloAck` / `ProtocolMismatch` | Required first request in every session (ADR-053 §1, hard cutover). |
| `Ping` | `Pong` | Reachability probe. Requires `Ping` capability. |
| `WorkerStatus` | `WorkerStatus { status, last_busy_at }` | Idle/busy sampled from `/proc/loadavg`. |
| `ReadinessStatus` | `ReadinessStatusReport` | Component-level readiness (see "Readiness model" below). |
| `IntegrationStatus` | `IntegrationStatusReport { integrations: Vec<…> }` | One per declared integration. Used by `mvmctl ls --json` readiness column (plan 74 W2). |
| `EntrypointStatus` | `EntrypointStatusReport` | Validation result + warm-pool state. |
| `ProbeStatus` | `ProbeStatusReport { probes: Vec<ProbeResult> }` | One per declared probe. |
| `SleepPrep` / `Wake` / `PostRestore` / `CheckpointIntegrations` | Ack | Snapshot lifecycle handshakes. |
| `UpdateIdleTimeout` | Ack with previous + new values | Adjusts the idle-eviction window. |
| `MountVolume` / `UnmountVolume` | `MountVolumeResult` (closed enum) | Volume metadata only — no file contents. |
| `StartPortForward` | `PortForwardStarted { vsock_port, … }` | Sets up a vsock→TCP forwarder. The data plane on that forwarder is byte-for-byte; the *control* plane that asks for it is one frame. |
| `ProcStart` / `ProcSignal` / `ProcKill` / `ProcList` | `ProcResult` (closed enum) | Process control. `ProcStart` accepts an `argv` up to capped length but does not echo it back. |
| `FsStat` / `FsList` / `FsMkdir` / `FsRemove` / `FsMove` | `FsResult` (closed enum) | Filesystem metadata. `FsList` truncates at `max_entries` and reports `truncated: true`. |
| `ConsoleOpen` / `ConsoleClose` / `ConsoleResize` | Ack with vsock port | Allocates a PTY forwarder. The PTY itself runs on a different vsock port — that's the data plane. |

### Data-plane verbs

Streaming, chunked, or potentially-large bounded transfers. Each
data-plane verb names its frame cap, chunk size, terminal event,
and backpressure behavior below.

| Verb | Flow | Frame cap | Chunk size | Terminal | Backpressure | Payload in audit? |
|---|---|---|---|---|---|---|
| `RunEntrypoint` | Single request → stream of `EntrypointEvent`s | `MAX_FRAME_SIZE` per event | Stdout/stderr drained per agent tick | `Exit { code }` / `Killed { signal }` / `TimedOut` / `Error` | None today (W4 wires the next slice). | No. Hash of stdout/stderr appears in receipts (plan 74 W6); raw bytes do not. |
| `ProcWait` | Single request → stream of `ProcWaitEvent`s | `MAX_FRAME_SIZE` per event | Stdout/stderr drained per ~50 ms agent tick | `Exit` / `Killed` / `TimedOut` / `Error` | **`Backpressure { reason: OutputConsumerSlow, detail }`** — rising-edge at 75 % of `Caps::max_output_buffer` (16 MiB prod, plan 74 W4). Non-terminal; wait continues. | No. Output streams to the host live; nothing about chunk content goes to audit. |
| `ProcSendInput` | Bounded request → ack | Request body capped at `Caps::max_stdin_per_call` (1 MiB prod) | Single-frame | `ProcResult::InputAccepted { bytes_accepted }` | Caller-driven — request body fails closed if it exceeds the cap (no implicit truncation). | No. `bytes_accepted` count only; never stdin bytes. |
| `FsRead` | Single request → `FsResult::Read { content, total_size }` | `MAX_FRAME_SIZE` per response | The agent caps reads at `max_read_bytes` and reports `total_size` so callers detect short reads. Bigger files require multiple requests with offset/length. | Response itself is the terminal | None — bounded by frame cap. | No. `total_size` and offset/length appear in audit; `content` bytes do not. |
| `FsWrite` | Bounded request → `FsResult::Write { bytes_written }` | Request body capped at the agent's write cap | Single-frame | Response itself is the terminal | Caller-driven — too-large bodies fail closed. | No. Byte count only. |
| `Exec` / `RunCode` (dev-only) | Single request → `ExecResult { exit_code, stdout, stderr }` | Each captured stream capped by the dev caps; total response bounded by `MAX_FRAME_SIZE` | One-shot capture; no streaming | Response itself is the terminal | None — dev-only, not exercised in prod. | No. Hash of stdout/stderr can be receipted; raw bytes are not audited. |
| Console PTY traffic | Bidirectional bytes over a dedicated vsock port (`ConsoleOpen` allocates it) | Per-frame cap defined by the console transport, not `MAX_FRAME_SIZE` | TTY-shaped reads | Caller closes (`ConsoleClose`) or PTY exits | None — interactive, not buffered. | No. Console bytes never enter audit. |
| Port-forward TCP traffic | Bidirectional bytes over the vsock port returned by `StartPortForward` | None — raw TCP | TCP-shaped reads | TCP teardown | None — kernel TCP. | No. Forwarded bytes never enter audit. |
| Builder output (builder VM only) | Streamed during `mvm-host-vm-init` builds | Frame cap on the builder vsock channel | Lines / records | Builder's terminal status | None today; builder egress events (plan 74 W8) will surface backpressure. | No. Build logs are stored next to the receipt; raw bytes never get into audit detail strings. |

### Redaction invariant

The following audit / readiness / progress / receipt surfaces are
guaranteed by ADR-053 §4 / §5 to **never** contain data-plane
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
  string is metadata only: byte counts, threshold, cap. Plan 74 W4
  unit tests pin this.
- `BackpressureReason::ServiceHealthPending { pending }` — service
  names only.
- Receipts written by `mvmctl run` / `mvmctl up` / `mvmctl build`
  (plan 74 W6) store hashes and metadata. Raw stdout / stderr /
  stdin / env / argv values are never written.
- `mvmctl ls --json` rows — the `readiness` and
  `last_readiness_change_at` fields render directly from the
  registry; the registry only stores the closed enum + RFC 3339
  timestamps.

### Exit checks

Plan 74 W3 calls out two contract checks that this section
underwrites:

1. **No code path advertises an unbounded single-frame response.**
   Every entry above either names a frame cap or routes through a
   streaming surface (`ProcWaitEvent` / `EntrypointEvent` / PTY /
   raw TCP).
2. **Docs explicitly state that payload bytes are not included in
   audit or readiness messages.** The "Redaction invariant"
   subsection is that statement.

## Profile gate

Every guest image declares an **agent profile** in its
`/etc/mvm/security.json` (plan 76 Phase 1). The profile is the
dispatcher-side allowlist for vsock verbs — dev-only requests
sent to a sealed-prod agent are rejected before any handler runs:

| Profile | Effective verb set | Used by |
|---------|-------------------|---------|
| `sealed-prod` (default) | Lifecycle, status, entrypoint, sleep/wake, volume mount/unmount, idle-timeout updates. The full ADR-002 production-safe surface. | Production images. The policy file lives on a dm-verity rootfs (ADR-002 §W3) so the profile cannot be widened at runtime. |
| `dev` | `sealed-prod` plus shell `Exec`, process RPC, filesystem RPC, console PTY, port forwarding, and `RunCode`. | `mvmctl dev` images and any image built with `dev-shell` feature. |
| `builder` | Reserved for builder-only verbs. The current builder agent speaks a separate `BuilderRequest` protocol, so this profile is wire-stable but unused for the tenant agent. | Future builder VM agent if/when its verbs land on the tenant wire. |

Rejected requests return a typed `UnsupportedInProfile` response:

```json
{ "UnsupportedInProfile": { "profile": "sealed-prod", "verb": "Exec" } }
```

SDK callers can branch on capability without parsing message text —
this is the protocol-layer analog of
`ProcErrorKind::UnsupportedInProduction` for process RPC.

The profile gate is **complementary** to the existing compile-time
gate (`#[cfg(feature = "dev-shell")]` for `do_exec` / `do_run_code` /
process RPC handlers per ADR-002 §W4.3, claim 4). The compile-time
gate keeps the handler symbols *absent* from production binaries; the
profile gate keeps the dispatcher *reachable but refusing* for dev
verbs in sealed-prod. Both checks run on every request.

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

- `mvmctl wait <vm> --for <component> [--timeout <secs>]` —
  Blocks until the named component reaches `Ready`, `Disabled`,
  or `Failed`. Targets: `control-plane`, `entrypoint`,
  `warm-pool`, `integrations`, `probes`, or `all` (the default).
  Exit codes: `0` ready, `65` (`EX_DATAERR`) component failed
  with message printed, `75` (`EX_TEMPFAIL`) deadline hit.
  `Disabled` counts as `Ready` (intentionally — a cold-tier
  image asking `--for warm-pool` must not spin forever).

- `mvmctl boot-report <vm> [--json]` — Single round-trip; prints
  the same `ReadinessReport` `mvmctl wait` polls, including the
  per-phase timing table. Useful right after `mvmctl up` to
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
mvmctl logs my-vm

# Follow logs in real time
mvmctl logs my-vm -f

# List VMs and their status
mvmctl ls
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
mvmctl diff my-vm         # human-readable output
mvmctl diff my-vm --json  # JSON array of {path, kind, size}
```

This is useful for auditing what an AI agent modified during execution.
