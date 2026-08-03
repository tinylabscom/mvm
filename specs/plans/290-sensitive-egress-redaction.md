# Sensitive egress redaction: make the protected-path promise enforceable

**Status:** In progress. WS1 implementation and host validation are complete on
branch `feat/sensitive-egress`; the Linux builder-VM all-target Clippy gate is
still required before WS1 acceptance.

**Goal:** For every destination whose admitted plan enables sensitive-data
inspection, MVM either obtains bounded plaintext, applies the configured
secret/PII detector set before forwarding, and records metadata-only evidence,
or refuses the request. Owning an encrypted route without owning its plaintext
does not satisfy this goal.

## Current boundary

MVM already owns the default-deny egress decision, selective TLS termination,
declared-secret substitution, one-way secret/PII masking, request-scoped
reversible replacement, and chain-signed audit records. Three gaps prevent a
stronger product statement:

1. the compressed/oversize refusal gate is armed only by entropy or name
   scanning even though the default action also masks curated secrets and PII;
2. the high-confidence scanner misses common credential containers such as
   JWTs, URL userinfo, Azure storage connection strings, Telegram and Discord
   tokens, and only masks a PEM private-key opener rather than the whole block;
3. scanner outputs have no shared byte-span contract, which makes future
   detectors easy to wire into one redaction path but omit from reversible
   replacement.

## Security contract

- The guarantee is scoped to an **admitted protected plaintext path**. Ordinary
  unbound HTTPS remains end-to-end encrypted and is not described as inspected.
- A protected request with `Content-Encoding` or a body over the signed cap is
  refused before forwarding. A scanner error or invalid span is likewise a
  refusal, never pass-through.
- Detection accepts arbitrary bytes. Text-oriented detectors operate only on
  validated UTF-8 islands and preserve invalid bytes without interpreting them.
- Findings contain class, category, and byte offsets only. Raw matched bytes
  stay inside the replacement/redaction operation and never enter logs or audit
  reasons.
- Reversible replacement remains request-scoped, random, exact-token-only and
  HMAC-evidenced. Predictable placeholders and unkeyed hashes are not adopted.

## Workstreams

### WS1 — Validated byte detector and fail-closed baseline

- [x] Add a `SensitiveDetector` contract returning validated byte spans and a
      LeakGuard-backed implementation restricted to high-confidence credential
      types missing from the curated scanner.
- [x] Pin LeakGuard without default features; keep MVM's byte adapter and policy
      semantics as the trust boundary rather than exposing the dependency API.
- [x] Feed the supplemental detector through both one-way redaction and
      reversible replacement so the two paths cannot drift in coverage.
- [x] Treat the default curated secret/PII action as active inspection, making
      compressed and over-cap requests fail closed even when entropy and names
      are off.
- [x] Test invalid UTF-8 islands, invalid spans, overlapping matches, full PEM
      blocks, each new credential family, metadata-only reporting, and default
      compressed/oversize refusal before forwarding.

### WS2 — Structured and streaming bodies

- [ ] Add content-type classification for JSON, form, text, multipart and
      opaque bodies; preserve binary parts while scanning textual fields.
- [ ] Add a bounded carry window for chunked/SSE streams and prove that every
      supported detector produces the same result when its input is split at
      every byte boundary.
- [ ] Refuse protected encodings and content types that cannot be decoded under
      the admitted resource cap; do not silently downgrade to route-only
      enforcement.

### WS3 — Policy and operator surface

- [ ] Complete `mvmctl up --redact HOST[=audit]` lowering into signed
      per-destination policy, including conflicts with L3 opaque transport.
- [ ] Report at admission which hosts are `protected-plaintext`, `route-only`,
      or `denied`, and why.
- [ ] Keep audit events metadata-only: destination, disposition, detector
      categories/counts, body class, and refusal reason.

### WS4 — Claim promotion and adversarial witnesses

- [ ] Add a numbered build-level claim only after every production protected
      path shares the refusal gate and has live witnesses.
- [ ] Witness plaintext redaction, compressed/oversize refusal, supplemental
      secret replacement/reinjection, audit non-disclosure, opaque-L3 admission
      refusal, and backend parity.
- [ ] Correct broad product prose to distinguish ownership of routing from
      ownership of plaintext, then generate `CONFORMANCE.md` from the model.

## Acceptance for WS1

WS1 is complete when focused detector, redaction, reversible replacement and
terminator tests pass on the macOS host; `cargo check --workspace` passes on the
host; and Linux all-target Clippy passes in the builder VM. No new claim is
promoted by WS1 alone.

## WS1 validation

- `cargo test --workspace -- --test-threads=1`: pass. The serial setting avoids
  known process-global/socket interference between unrelated hostd tests.
- `cargo check --workspace`: pass.
- `cargo clippy --workspace --all-targets -- -D warnings`: pass on macOS.
- `cargo deny check`: advisories, bans, licenses and sources pass. LeakGuard
  0.8.0 is pinned with default features disabled and adds no transitive crates.
- `cargo audit`: no vulnerabilities; one existing allowed unmaintained warning
  remains under the Sigstore dependency graph.
- Linux `cargo clippy --workspace --all-targets -- -D warnings` in the builder
  VM remains the outstanding WS1 acceptance gate.
