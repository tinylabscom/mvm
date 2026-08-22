# Binary sealed-frame envelope for the control plane

Backing: preview
Validation: none

**Status:** COMPLETE — W1, W2, W3, W5, W6 landed; W4 deferred, see below
**Opened:** 2026-08-21
**Issue:** #2790
**Depends on:** #2784 (derives `MAX_DATA_CHUNK_SIZE`; adds `Session::poison_send`)
**Related:** #2780, ADR-019

## Outcome

The control plane stops JSON-wrapping sealed frames and uses the binary
`SealedFrame::encode` the egress plane already uses. One encoding hop
disappears from every host↔guest control byte.

## Why

`AuthenticatedSession::write` builds an `AuthenticatedFrame` and hands it to
`serde_json`. The sealed ciphertext is a `Vec<u8>`, which serde_json writes as
an array of decimal numbers — a second expansion on top of the one the
`GuestResponse` body already paid.

Measured on one 15872-byte stdout chunk (the cap #2784 derives), release build,
aarch64 macOS, same sealed frame under both encodings:

| | wire bytes | encode | decode |
|---|---|---|---|
| JSON envelope | 184050 | 212 us | 492 us |
| `SealedFrame::encode` | 51664 | 0.9 us | 0.9 us |
| ratio | 3.6x | 244x | 540x |

Bytes are the smaller half. The per-frame serde_json cost is ~705 us, so
900 KB of guest stdout spends about 40 ms of CPU across 57 frames and puts
10.5 MB on the wire rather than 2.9 MB.

The bandwidth estimate that motivated this work was off by two orders of
magnitude in the wrong direction — it predicted the bytes would dominate. The
table above is why this plan leads with a measurement and ends with a committed
benchmark instead of an assertion.

## Non-goals

Hop 1 stays. The inner `GuestResponse` JSON still encodes `chunk: Vec<u8>` as a
number array — 51.5 KB carrying 15.9 KB of content, about 3.3x. Changing the
body representation is a larger change against a wider type surface. Re-measure
after this lands rather than assuming it is still worth doing.

## Workstreams

### W1 — move the control envelope to the binary codec

- [x] `AuthenticatedSession::write` replaces its `AuthenticatedFrame` +
      `write_frame` pair with `mvm_core::net::session::write_sealed_frame`.
      That helper is already generic over `W: Write`, already emits the
      `[u32 BE len][encoded]` framing, and is the one the FlowMux path uses —
      no new framing code.
- [x] `AuthenticatedSession::read` replaces `read_frame::<AuthenticatedFrame>`
      + manual `SealedFrame` reconstruction with `read_sealed_frame`.
- [x] Keep the poison-on-write-failure behaviour #2784 introduced. It is the
      same hazard on the new path: `seal` spends the sequence before
      `write_sealed_frame` can fail.
- [x] Decide the `max_len` passed to `read_sealed_frame`. It bounds the
      *encoded* frame, so it is `MAX_FRAME_SIZE` plus envelope headroom, not
      `MAX_FRAME_SIZE` itself. FlowMux uses `MAX_FRAME_LEN + 512`.

### W2 — re-derive the chunk cap

- [x] `SEALED_ENVELOPE_EXPANSION` drops from `4 * 4` to `4`: content now
      crosses one JSON hop, not two.
- [x] The `const` assertion #2784 added stays and re-derives against the new value.
- [x] The cap moves from 15.5 KiB to 62 KiB (63488 bytes). Take the derived number
      rather than rounding to a familiar one; the point of #2780 was that a
      hand-picked cap is how this went wrong.
- [x] Update the witness `sealed_worst_case_chunk_fits_the_frame_cap` — it
      asserts against the encoded envelope, so it should need no change beyond
      the constant, which is the sign the derivation is doing the work.

### W3 — move the fuzz surface with the ingress

Claim 5 names the vsock framing fuzz targets as its witnesses. The ingress is
changing, so the targets have to change with it or the claim keeps a witness
that no longer covers the parser the guest actually exposes.

- [x] `fuzz_sealed_frame.rs` (renamed from `fuzz_authenticated_frame.rs`) fuzzes
      `serde_json::from_slice::<AuthenticatedFrame>` today. Retarget to
      `SealedFrame::decode`, which is the new untrusted entry point.
- [ ] **Deferred with W4.** `fuzz_authed_path.rs` builds an `AuthenticatedFrame` and drives the
      authenticated path. Rebuild it around the binary envelope.
- [x] Checked against ADR-001's claim-5 row whether either target is named
      there by name, and update the row in the same change if so.
- [x] The existing JSON corpus stops being meaningful input. Note it rather
      than silently carrying it forward.

### W4 — is `AuthenticatedFrame` still load-bearing? — **DEFERRED**

Answered, not acted on. `write_authenticated_frame` /
`read_authenticated_frame` / `verify_authenticated_frame` have **no production
callers**: the only call sites are their own tests in `framing.rs` and the
`fuzz_authed_path` fuzz target. Before this change that mattered less, because
`AuthenticatedFrame` was the shape the control plane really used, so a fuzz
target aimed at it was aimed at something real. It no longer is.

- [x] Establish whether they have a production caller. They do not.
- [ ] **Deferred to its own change.** Deleting them takes `fuzz_authed_path`
      with them, and that target is a claim-5 witness. Rebuilding it around
      `Session::open` — the real post-auth path, covering version, session id,
      replay, signer, signature and decrypt — is worth doing carefully rather
      than as a tail-end of a framing swap. Deleting the legacy path *without*
      rebuilding the target would trade a stale witness for a missing one.

Recorded so the next reader does not re-derive it: after this change,
`fuzz_authed_path` exercises a signature-only path that production does not
take. That is a real gap in claim 5's coverage, and it predates this plan only
in the sense that the path was previously shaped like the live one.

### W5 — a benchmark that keeps the number honest

- [x] Commit a trimmed version of the throwaway probe used above, so the
      encode/decode cost of the control envelope is measurable on demand rather
      than re-derived by hand each time.
- [x] It reports bytes and per-frame encode/decode for a representative
      `ExecEvent::Stdout` chunk. It is not a pass/fail gate — a wall-clock
      assertion in CI is the test shape that passes for the wrong reason.

### W6 — verification

- [x] Full gate list: nightly `cargo fmt --all --check`,
      `clippy --workspace --all-targets -D warnings`,
      `nextest run --workspace`, `test --workspace --doc`, `just check-gated`,
      and every `xtask` gate the workflows reference.
- [x] End-to-end with a rebuilt guest agent on HVF: stdout at 28 KB, 100 KB and
      900 KB returns byte-exact, matching the #2784 verification table.
- [x] Re-run the benchmark on the result and record the delta in the delivery
      note. Measured end-to-end as well: the guest command phase for 900 KB of
      stdout went from ~72 ms to ~34 ms.

## Risks

**A stale guest agent paired with a new host.** The wire changes in both
directions at once. Host and guest are built from the same tree and the OCI
rootfs cache is keyed by guest-agent source hash, so the pairing should follow
automatically — but that is the assumption most likely to be wrong here, and a
mismatch surfaces as a handshake or decode failure rather than anything
self-describing. Check it explicitly in W6 rather than inferring it from the
cache key.

**Claim 5 losing coverage quietly.** W3 is the workstream that matters most and
is the easiest to skip, because nothing fails if a fuzz target keeps building
against a type the control plane no longer parses.

**Stacking.** This branches off #2784, which is in the merge queue. Rebase onto
`main` after it lands and verify by content, not by PR state — a stacked branch
rebased onto a squash-merged base can strand work silently.
