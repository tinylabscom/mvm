# Telemetry data contract for mvm studio

Backing: preview
Validation: fn:studio_fixture_streams_match_the_committed_vectors

The kickoff artifact for mvm studio — the Tauri (desktop + web) app that
shows a user what is happening inside their VM. It names the data shapes
studio renders, the semantics the UI must respect, the read seam that
serves them, and the fixture streams the frontend can build against.
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

The read seam is three `MvmClient` calls, answered in-process by
`LocalBackend` and over the C ABI by `libmvm_hostlib` as `telemetry.status`
and `telemetry.records` (host-ABI minor 6):

- `telemetry_status(id)` — the typed coverage for one machine
  ([below](#the-status-snapshot)). A machine nobody asked to observe answers
  `not_provisioned`, never an error; an unknown machine is `NotFound`.
- `telemetry_records(id, {after, limit})` — one page of records, cursor-paged
  so a poll costs a `stat` when nothing arrived. Pass the page's `next` back
  as `after`; an unchanged `next` means nothing new. A cursor from before the
  machine's stream was reset (a reboot starts a fresh file) is refused as
  `Rejected`, never silently rebased, so a reader restarts knowingly instead
  of splicing two boots together. Only complete records are served: a line
  the collector is still writing waits for the next read.
- The dashboard's machine list is `list_machines` joined with
  `telemetry_status` per machine; there is no separate joined call.

Capability discovery reports the seam as `operations.telemetry`, true for the
local backend and the mock, false for the remote gateway, which has no
collector endpoint and refuses both calls. The `MockBackend` serves the same
three calls from in-memory state (`set_telemetry_status`,
`push_telemetry_records`, `reset_telemetry_records`), so a frontend can be
driven through the real trait before a VM is ever booted.

The seam reads what the collector persisted in the VM state dir (its status
snapshot and its capped records JSONL) and never writes there, so a polling
dashboard cannot slow or corrupt collection. Those files are the collector's;
the seam is the contract. Host receive time is **not** persisted today, so
the seam serves records without a wall-clock placement — a consumer orders
by `sequence` within an epoch and must not invent one.

## The fixture streams

`tests/vectors/studio-telemetry/*.jsonl` — one JSON record per line, the
same encoding the collector persists and the seam will serve.

| Stream | What it teaches the UI |
| --- | --- |
| `healthy-boot.jsonl` | The ordinary case: coverage announced first, then diagnostics events with every typed attribute kind (unsigned, signed, bool, float, text). One epoch, gapless sequences. |
| `lossy-flood.jsonl` | Capture under pressure: a visible sequence gap (5 → 43) plus `loss` summary records. The gap and the summaries are evidence to surface, not smooth over. |
| `restored-generation.jsonl` | A restore boundary: the old epoch closes with `stopped`, the new generation mints a fresh epoch and announces `started` again. Ordering across epochs is not meaningful. |
| `collector-status.jsonl` | One typed `TelemetryStatus` per line, every coverage state the seam answers, produced from the on-disk snapshots through the seam's own conversion. |
| `records-page.json` | The first three records of `healthy-boot` as one `TelemetryPage`, cut by the seam's pager: `next` is the byte position a consumer hands back, and `more` is true. |

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
  producer and epoch. It is **not** a wall clock. Wall-clock placement would
  come from host receive time, which the collector does not persist yet, so
  the read seam serves none.
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

## The status snapshot

The collector rewrites a per-VM status on a cadence; the seam serves it typed
(`TelemetryStatus`, frozen in `collector-status.jsonl`):

```json
{"coverage":{"state":"collecting","generation":3},"shed":37}
```

- `coverage.state` — `not_provisioned` (no collector for this boot; the
  ordinary opt-out state, with no code), `connecting`, `collecting` with the
  boot `generation`, `degraded` with a static `code`, or `stopped`.
- `shed` — records the **host** dropped because its sink was full. It is
  separate from the `loss` records in the stream, which count what the guest
  shed before sending; a complete loss tally adds both.

The on-disk form behind it (`CollectorStatusSnapshot`: `vm_name`, a
`status` label, `generation`, `shed`) is the collector's own and is not the
contract; a label the seam does not know is a backend error, not a guessed
state.

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
