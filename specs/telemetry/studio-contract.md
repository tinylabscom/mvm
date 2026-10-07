# Telemetry data contract for mvm studio

Backing: preview
Validation: fn:studio_fixture_streams_match_the_committed_vectors

The kickoff artifact for mvm studio — the Tauri (desktop + web) app that
shows a user what is happening inside their VM. It names the data shapes
studio renders, the semantics the UI must respect, the read seam that
serves them, and the fixture streams the frontend builds against offline.
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

The read seam is two methods on the `MvmClient` facade, answered by
`LocalBackend` from the collector's files beside the VM state and refused
by name on the gateway until a remote collector endpoint exists:

- `telemetry_status(id)` → a `TelemetryStatus`: whether collection was
  provisioned for the machine's current boot, and the collector's standing
  when it was. A health question, cheap to poll.
- `telemetry_records(id, request)` → a `TelemetryReadResponse`: one
  cursor-paged read of the machine's records, oldest first. The reply
  always carries `next_cursor`; an empty page with the same cursor means
  nothing new has arrived, and the consumer polls it again.

The dashboard view's join is on the inventory record itself: every
`MachineInventoryRecord` carries an optional `telemetry` status, absent for a
machine with no state directory. The host library carries the same three
answers over its C ABI as `telemetry.status`, `telemetry.records`, and the
`telemetry` field of `machine.inventory`; the backend's capability report
names the seam as the `telemetry` operation, so a consumer asks before it
calls. The shapes live in `mvm_core::protocol::telemetry::served` and are
frozen as fixtures below. The collector's on-disk files remain its own:
studio reads them through the seam, never directly.

## The fixture streams

`tests/vectors/studio-telemetry/*.jsonl` — one JSON record per line, the
same encoding the collector persists and the seam will serve.

| Stream | What it teaches the UI |
| --- | --- |
| `healthy-boot.jsonl` | The ordinary case: coverage announced first, then diagnostics events with every typed attribute kind (unsigned, signed, bool, float, text). One epoch, gapless sequences. |
| `lossy-flood.jsonl` | Capture under pressure: a visible sequence gap (5 → 43) plus `loss` summary records. The gap and the summaries are evidence to surface, not smooth over. |
| `restored-generation.jsonl` | A restore boundary: the old epoch closes with `stopped`, the new generation mints a fresh epoch and announces `started` again. Ordering across epochs is not meaningful. |

The served shapes are frozen beside them
(`studio_fixture_statuses_and_page_match_the_committed_vectors`):

| Fixture | What it teaches the UI |
| --- | --- |
| `status-not-provisioned.json` | The answer for a machine booted without a collector: nothing dials the guest, no records are expected, and the health badge says so rather than "no data". |
| `status-collecting.json` | A live collector under boot generation 1, with the snapshot's age and the records file's size. |
| `status-degraded.json` | Collection impaired with a short `code` and a non-zero host-side `shed` count. |
| `page-healthy-boot.json` | The healthy-boot stream as one served page: each record in its envelope with its `received_at_ms`, the cursor past the last persisted line, `undecodable` zero, `exhausted` true. |

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
  from host receive time. The collector persists each record inside an
  envelope `{"received_at_ms": …, "record": {…}}`, and the seam serves that
  envelope as a `ReceivedRecord`. A line persisted before receive time was
  stamped serves with no `received_at_ms`; a consumer orders those by
  `monotonic_ns` alone.
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

## The status

`TelemetryStatus` is a tagged object on `collection`:

- `not_provisioned` — no collector was provisioned for the current boot.
- `provisioned` — with `vm_name`, `state`, `shed` (records the host shed
  after receipt), `records_bytes` (the records file's current size), and
  `snapshot_age_ms` when the host can tell. The collector rewrites its
  snapshot about once a second while it lives, so a large age means the
  process that owned the VM is gone; the UI should read a stale `collecting`
  as "was collecting", not "is".

`state` is a tagged object on `kind`: `connecting`, `collecting` with its
boot `generation`, `degraded` with a short `code`, or `stopped`. The
`status-*.json` fixtures above freeze all of it.

## The page

`TelemetryReadRequest` names a `cursor` (`{"offset": …}`, the start of the
stream when absent) and a `limit` (256 by default, 1024 at most).
`TelemetryReadResponse` carries `records` oldest first, `next_cursor`,
`undecodable` (lines in the page's span that were not records — evidence,
not something to hide) and `exhausted` (whether the page reached the end of
what the file held). A cursor the stream no longer honors — past the end,
or inside a line, after a machine was removed and recreated — is refused as
an invalid request rather than resynchronized by guesswork; the consumer
starts over from offset 0.

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
