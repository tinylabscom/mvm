# Telemetry data contract for mvm studio

Backing: preview
Validation: fn:studio_fixture_streams_match_the_committed_vectors

The kickoff artifact for mvm studio — the Tauri (desktop + web) app that
shows a user what is happening inside their VM. It names the data shapes
studio renders, the semantics the UI must respect, and the fixture streams
the frontend can build against today, before the live read seam exists.
The shapes are the real ones: every fixture line is produced by the
contract types' own builders and serde, and the sync test above goes red if
a fixture drifts from the code.

## How studio consumes this data

Two modes, one integration surface:

- **Desktop (Tauri core)**: the Rust side links `mvm-client` and calls the
  `MvmClient` facade directly — in-process, no server, no open port. The
  webview receives records over Tauri commands/events.
- **Web**: the same frontend against a thin host-side server that consumes
  the same `MvmClient` facade. The server is studio's, not mvm's; mvm's
  HTTP client is deliberately minimal and serves nothing.

The read seam itself is **planned, not yet built** (the W4 slice after the
embedded-collector change lands): a status-snapshot call, a cursor-paged
record read (`records(vm, cursor) → (batch, next_cursor)`), and a machine
list joined with per-VM coverage status for the dashboard view. Until it
lands, the collector's on-disk outputs (a status JSON and a capped records
JSONL in the VM state dir) are interim observability — readable for
development, not a contract studio should couple to.

## The fixture streams

`tests/vectors/studio-telemetry/*.jsonl` — one JSON record per line, the
same encoding the collector persists and the seam will serve.

| Stream | What it teaches the UI |
| --- | --- |
| `healthy-boot.jsonl` | The ordinary case: coverage announced first, then diagnostics events with every typed attribute kind (unsigned, signed, bool, float, text). One epoch, gapless sequences. |
| `lossy-flood.jsonl` | Capture under pressure: a visible sequence gap (5 → 43) plus `loss` summary records. The gap and the summaries are evidence to surface, not smooth over. |
| `restored-generation.jsonl` | A restore boundary: the old epoch closes with `stopped`, the new generation mints a fresh epoch and announces `started` again. Ordering across epochs is not meaningful. |

## The record shape

Each line decodes as one record (`TelemetryRecord` in
`crates/mvm-core/src/protocol/telemetry/`):

```json
{"format":"mvm.telemetry.v1","epoch":[…16 bytes…],"producer":1,
 "sequence":2,"monotonic_ns":5250000,"source":"guest_agent",
 "body":{"kind":"event","context":null,"level":"info",
         "name":"vsock control plane bound",
         "attributes":[{"key":"port","value":{"type":"unsigned","value":5253}}]}}
```

- `format` — the wire version. A consumer must refuse unknown versions
  rather than guess.
- `epoch` — 16 opaque bytes identifying one producer lifetime. Fresh per
  boot generation; rotated on restore.
- `producer` / `sequence` — a fixed per-source producer number and an
  attempt-counted sequence: **a shed record spends a number**, so a gap in
  sequences is loss evidence the host can detect and the UI should show.
- `monotonic_ns` — the guest's monotonic clock, an ordering hint within one
  producer and epoch. It is **not** a wall clock; wall-clock placement comes
  from host receive time, which the read seam adds alongside each record.
- `source` — the declared source class (`guest_agent`, `stdio`, `sdk`, …).
- `body.kind` — the closed record family:
  - `event`: severity `level`, bounded `name`, up to 16 typed `attributes`,
    optional trace `context` (unused in this phase).
  - `coverage`: `started` / `stopped` / `unavailable` / `degraded` with a
    short `code` — the signal behind a health badge.
  - `loss`: a delta summary — `stage`, `reason` (`capacity`, `rejected`,
    `truncated`, `unavailable`, …), `records`, `bytes`, and `tail`
    (`known` or `unknown` when a crash made further loss uncountable).
  - `log` and `stdio` exist in the contract but no fixture carries them
    yet — they arrive with later capture slices.

Everything is bounded: records ≤ 32 KiB, names/messages/attribute counts
capped by the contract types. A consumer never needs to defend against an
unbounded line.

## Semantics the UI must respect

1. **Records do not name their VM.** VM/boot/generation identity is bound
   by the authenticated session on the host side; the read seam attributes
   records to a VM — a record taken out of that context has no owner.
2. **An epoch change is a hard boundary.** Do not order, diff or correlate
   across epochs; render it as a lifecycle break (the restore fixture).
3. **Sequence gaps are information.** Pair them with `loss` summaries; a
   tally like "37 records shed (capacity)" beside the feed is honest,
   silently contiguous rendering is not.
4. **Loss summaries arrive even when data sheds.** They travel a reserved
   path, so "the feed is quiet but losses are climbing" is a real state the
   UI can and should distinguish from "nothing is happening".
5. **Coverage drives health.** `started` → collecting; `degraded`/`
   unavailable` → show the code; `stopped` → clean end. Absence of records
   is not evidence of health — the status snapshot is.

## The status snapshot (shape pending one in-flight change)

The collector keeps a per-VM status the seam will serve directly — as of
the in-flight embedded-collector change: `vm_name`, `status`
(`connecting` / `collecting` / `degraded:<code>` / `stopped`), `generation`
when collecting, and the host-side `shed` count. Treat this section as the
shape's description, not its freeze; the seam change freezes it with a
generated fixture like the record streams above.

## Scope of this phase, per the recorded decisions

Collection is opt-in (`MVM_TELEMETRY_COLLECT=1`, or any configured OTLP
exporter endpoint) until the enablement workstreams land their live
baselines. The v1 data is: agent diagnostics events, coverage lifecycle and
loss accounting. Workload stdio arrives with the invocation-scoped tee
(detached stdio is a registered inventory gap until the collector machinery
owns it); spans wait for a real span producer. A studio v1 built around a
health badge, a diagnostics feed and loss counters matches what the
pipeline emits; anything more renders fixtures that production will not
send.

## Security note for the web mode

These records will eventually carry workload-derived content (stdio above
all). Redaction/validation of that content is its own workstream and gates
showing records in any browser context beyond the machine owner's own
session; studio's web server must bind locally and authenticate from its
first commit. Desktop mode inherits the OS user boundary and an
in-process call path, which is part of why it is the first-class target.
