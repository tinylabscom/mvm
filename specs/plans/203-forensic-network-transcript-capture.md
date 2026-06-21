# Plan 203 — Opt-in forensic network transcript capture

**Status:** Proposed
**Sprint:** 56
**Depends on:** Plan 101 W6/W8, ADR-058

## Goal

Add an explicit, request-only forensic mode that captures byte-exact network
transcripts for a specific tenant / VM / session without changing the default
claim-10 posture.

The default mode stays what the repo already commits to today:

- gateway coverage on the host boundary,
- chain-signed flow metadata,
- aggregated byte counts,
- no payload bytes in the normal audit chain.

Transcript capture is the exception for incident response and compliance
evidence. It is off by default, opt-in per workload/session, and separately
gated from the normal flow-audit path.

## Proposed design

### 1. Keep the existing audit chain as the source of truth

The primary audit chain remains the append-only JSONL log under
`~/.mvm/audit/<tenant>.jsonl`.

Transcript mode adds only manifest-level records to that chain:

- capture armed
- capture disarmed
- transcript chunk sealed
- transcript export requested
- transcript export completed

Those records carry hashes, sizes, timestamps, VM/session identifiers, and the
capture policy that was in force. The chain never stores the raw payload bytes.

### 2. Capture at the host-owned trust boundary

Capture happens at the same host-controlled bridge that already mediates guest
egress and ingress.

That gives one clear rule:

- if the host terminates or proxies the channel before the guest sees it, the
  transcript can contain the plaintext bytes;
- if the host never sees plaintext, the transcript contains the ciphertext bytes
  that crossed the boundary instead.

The capture point is the last host-controlled hop before the guest receives the
data. That keeps the transcript faithful to what crossed the boundary and avoids
pretending the host can reconstruct plaintext it never owned.

### 3. Store transcripts outside the main JSONL log

Transcript payloads live in a separate directory tree, for example:

`~/.mvm/audit/transcripts/<tenant>/<vm>/<session>/<capture-id>/`

Each capture contains:

- a manifest file with hashes, sizes, session binding, and capture policy
- chunk files stored as packet transcripts
- a sealed encryption envelope for the transcript key

The chunk format should be packet-native rather than ad hoc line logging. Using a
standard packet container keeps export tooling simple and preserves the exact
boundary bytes without inventing a second wire format.

### 4. Encrypt transcript payloads at rest

Transcript chunks are encrypted at rest with a per-capture data key.

The manifest records the wrapped data key and the recipient binding that is
allowed to decrypt it later. The intent is:

- raw payloads are never written to the normal audit chain,
- payload files are unreadable without the transcript key,
- export is an explicit action that re-verifies the chain before decrypting.

This is separate from the normal chain-signing path. Chain integrity proves the
capture happened and was not tampered with; transcript encryption keeps the raw
payload from being casually readable on disk.

### 5. Make transcript arming explicit and bounded

Transcript capture is armed only for a specific admitted workload or session.
It is not tenant-wide by default.

The capture policy should be bounded by:

- maximum duration
- maximum bytes
- maximum chunks
- maximum concurrent captures per tenant

If a bound is exceeded, capture fails closed and the chain records the refusal
or truncation. The normal flow-audit path continues to function.

### 6. Add an operator-facing CLI under `mvmctl audit`

The proposal is a small command family:

- `mvmctl audit transcript arm`
- `mvmctl audit transcript disarm`
- `mvmctl audit transcript list`
- `mvmctl audit transcript export`

`arm` binds to a tenant / VM / session and emits the chain record that says a
forensic capture is active.

`export` verifies the manifest hashes and the chain first, then decrypts the
transcript to a destination path or stdout.

The CLI is the only operator surface. There is no background auto-capture.

## Concrete repo touchpoints

- `specs/adrs/058-claim-10-bytes-leaving-trust-boundary.md`
  - tighten the `full_pcap` note into an explicit forensic-transcript mode
  - point readers at this plan for the capture format and lifecycle
- `specs/SPRINT.md`
  - keep the W8 note aligned: aggregated `flow_bytes` is the default, transcript
    capture is a separate follow-on
- `crates/mvm-core/src/policy/audit.rs`
  - add transcript lifecycle kinds so arming, sealing, export, and refusal are
    chain-visible
- `crates/mvm-hostd/src/supervisor/gateway_audit.rs`
  - add the capture sink that writes transcript chunks and manifest records
- `crates/mvm-hostd/src/supervisor/gateway_bridge.rs`
  - tap the host bridge at the capture point and fan bytes into the sink
- `crates/mvm-cli/src/commands/audit.rs`
  - add the `mvmctl audit transcript` CLI family
- `crates/mvm-cli/src/commands/ops/cache.rs`
  - keep transcript cleanup in the same storage hygiene path as the rest of the
    audit directory

## Security posture

This feature is deliberately high risk and therefore must stay opt-in.

- Raw payloads are never emitted by the normal audit chain.
- Arming capture is itself auditable.
- Export is audited.
- Transcript files are encrypted at rest.
- The default path remains metadata-only so the common case stays low volume and
  low risk.

This is a forensic tool, not a monitoring feature.

## Implementation slices

1. **[partly landed]** Add the transcript manifest and lifecycle audit kinds.
   The manifest format + tamper verifier + bounded-capture budget landed as
   `mvm_core::transcript` (`TranscriptManifest`/`ChunkRecord`/`CaptureBinding`/
   `CaptureBounds`, `CaptureBudget::try_add` fail-closed bounds, `verify_chunks`
   re-hashing + unsafe-name/size/missing/tamper/version refusals; serde
   `deny_unknown_fields`; 9 unit tests). The **lifecycle audit kinds are
   deferred to slice 2** (where they are actually emitted), to avoid touching
   the claim-gated audit taxonomy before there is an emitter.
2. **[capture+encryption+export core landed]** The bounded, AEAD-encrypting
   capture writer + verify-and-decrypt export landed as
   `mvm_core::transcript::{TranscriptWriter, TranscriptWriterConfig, export}`:
   `push(direction, plaintext)` budget-checks *before* writing, encrypts each
   chunk at rest with the per-capture data key (`crypto::aead::seal`, reused),
   and records it by the sha256 of its **ciphertext** so `verify_chunks`
   re-hashes what is on disk; `seal()` finalizes the manifest; `export()` runs
   `verify_chunks` then `aead::open` per chunk, failing closed on a wrong key
   (`TranscriptError::Decrypt`) or tamper (`HashMismatch`). 4 new tests
   (round-trip, tamper-refuse, wrong-key-refuse, budget-refuse-without-writing);
   `check-core-runtime-free` stays green (no tokio pulled). **[hostd sink + tap
   landed]** `mvm_hostd::supervisor::transcript_sink::TranscriptCaptureSink`:
   `open_for_vm(transcripts, keys, tenant, vm)` finds an armed (empty-chunk)
   manifest for the VM, unwraps the data key under the host KEK, and opens a
   `TranscriptWriter`; `push`/`seal` fill + finalize it. The
   `gateway_bridge::bridge_copy_bidirectional` tap opens the sink once per VM
   (`None` = no capture armed = zero cost), pushes each forwarded egress/ingress
   frame, and seals + emits `TranscriptSealed` on teardown. Tested through the
   **real** bridge relay (4 tests, `UnixStream` pairs): a forwarded frame is
   captured, sealed, and `transcript::export` decrypts it back byte-for-byte; all
   43 gateway_bridge tests stay green. The transcript lifecycle audit kinds landed
   with the CLI (slice 3).
3. **[key-wrapping landed]** Per-capture key wrapping is done:
   `aead::Key::{wrap_under, unwrap_under, persist, load}` (bytes stay
   encapsulated — no accessor) + `mvm_core::transcript::{load_or_init_kek,
   wrap_data_key, unwrap_data_key}` manage a host KEK at
   `<keys_dir>/transcript-kek.bin` (0600, created on first use) and produce/
   consume the manifest's `wrapped_data_key_b64`. 5 tests incl. an end-to-end
   wrap→capture→unwrap→export round-trip.
   **[CLI + lifecycle audit kinds landed]** `mvmctl trust audit transcript
   {arm,disarm,list,export}` (`crates/mvm-cli/src/commands/ops/transcript.rs`):
   `arm` provisions a capture dir + manifest (per-capture key wrapped under the
   host KEK), `list` enumerates, `disarm` seals, `export` =
   `unwrap_data_key` → `transcript::export` (verify + decrypt) to a file/stdout,
   failing closed on tamper/wrong-key. The 4 lifecycle kinds
   (`TranscriptArmed`/`Sealed`/`Exported`/`Refused`) were added to
   `LocalAuditKind` and are emitted per step; `audit_total_coverage` updated in
   lockstep (`AUDIT_SUB`/`TRANSCRIPT_SUB` tables + `KNOWN_TOKENS`). Captures live
   under `mvm_transcripts_dir()` = `<audit>/transcripts/<tenant>/<id>/`. 6 CLI
   tests (arm/list/disarm/export round-trip via a synthetic-sink capture,
   tamper-refusal, unknown-capture).
   **[capture sink + bridge tap landed]** `supervisor::transcript_capture::
   TranscriptObserver` is an opt-in `Observer` on the Plan-141 packet pipeline:
   `on_packet` copies each forwarded frame's `raw_frame` into the AEAD
   transcript and always returns `Verdict::Forward` (capture never alters,
   delays, or drops traffic). To honor the cheap-`on_packet` contract, the hot
   path only does a bounded `try_send` (dropping + counting frames if a slow
   disk falls behind); a std-thread worker owns the `TranscriptWriter`,
   encrypts + appends off the hot path, and flushes the manifest on a cadence +
   a final flush on drop (the capture-seal point at VM teardown). It is wired
   via `BridgeConfigJson.transcript_capture_dir` (serde-default; the claim-5
   fuzz surface is unchanged) — the `mvm-firecracker-bridge` bin activates it
   when set (the capture dir is under the already-Landlock-writable `audit_dir`,
   so no sandbox change is needed; the host KEK under `keys_dir` is read-only
   there), and `microvm.rs` auto-attaches an armed capture for the VM via
   `transcript::find_armed_capture` (override: `MVM_TRANSCRIPT_CAPTURE_DIR`).
   `mvm-core` gained `TranscriptWriter::{snapshot_manifest, dir, chunk_count}`
   (live-manifest persistence) + `find_armed_capture`. Verified on the live
   Linux/KVM box: the `cfg(linux)` bin compiles with the tap and the observer +
   transcript tests pass on-target. **Remaining:** the live FC-workload
   end-to-end (arm → real egress → chunks land → export decrypts) — a
   live-validation task, not new code.
4. Add focused tests for:
   - arming and disarming a capture
   - manifest hash verification ✅ (`verify_chunks` tests, slice 1)
   - export refusal on tampering ✅ (slice 1 verifier + slice 2 `export` wiring)
   - bounded capture overflow ✅ (`CaptureBudget` tests, slice 1; writer
     `push` budget test, slice 2)
   - round-trip export of a captured session ✅ (slice 2 `export` round-trip)

## Out of scope

- Always-on payload logging.
- Automatic redaction of captured payload bytes.
- East-west microVM-to-microVM capture.
- Live alerting or detection based on the captured transcript.
- Replacing the existing flow audit or the chain-signed JSONL log.

## Acceptance

This proposal is ready to implement when the repo has:

- a named transcript mode in the audit config,
- a manifest format for sealed transcript chunks,
- a CLI path to arm and export a transcript for a specific workload,
- tests that prove tamper detection and export refusal,
- docs that state transcript capture is opt-in and separate from the default
  flow audit.
