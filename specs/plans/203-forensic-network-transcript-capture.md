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

1. Add the transcript manifest and lifecycle audit kinds.
2. Add the capture sink and the boundary tap.
3. Add the CLI arm/export commands and the transcript verifier.
4. Add focused tests for:
   - arming and disarming a capture
   - manifest hash verification
   - export refusal on tampering
   - bounded capture overflow
   - round-trip export of a captured session

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
