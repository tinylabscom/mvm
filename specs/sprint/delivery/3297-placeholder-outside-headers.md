# A placeholder outside a header is refused and recorded

Issue #3297, the part left after the scan layer was deleted. Task T17 of
`specs/plans/2026-09-15-agent-sandbox-drive-plane.md`.

`prepare_request` substitutes placeholders in request headers only. A
placeholder in the URL or the body was forwarded unchanged, so the destination
received the host-reserved token instead of a credential and nothing in the
chain said so. The deleted `PlaceholderLeakScan` was meant to be the backstop,
but nothing had called it since the guest NIC went away.

As decided on #3302, a placeholder anywhere but a header is now refused and
recorded, not substituted:

- `prepare_flow` checks the URL and a buffered body before anything is
  forwarded. That covers the typed HTTP flow and the replayed-body path
  (request signing, body replacement).
- The streamed body, which a terminated CONNECT flow uses, is checked one chunk
  at a time by `BodyPlaceholderScan` before the streaming redactor sees the
  chunk. A placeholder split across two chunks is found. The scanner checks
  the chunk and a seam of the previous 58 bytes joined to the chunk's first 58,
  so it never copies a whole chunk. The redactor holds back 64 KiB, far more
  than a placeholder's 59 bytes, so no byte of the placeholder has been
  released when the check fires. The request headers may already have gone
  out; the chain then shows the hand-off, the refusal, and a `request_failed`
  outcome.

Each refusal is `secret.flow_refused` with reason `placeholder_in_url` or
`placeholder_in_body`, and never records the token.

What counts as a placeholder here is narrower than in a header:
`contains_minted_placeholder` in `mvm-contract` matches the reserved prefix
followed by at least 48 hex digits, the shape `mint` produces. A body can
legitimately mention the prefix in source code, logs or documentation, and a
short token such as `mvm-secret-deadbeef` is not one the host minted, so
neither is refused. `SECRET_PLACEHOLDER_HEX_LEN` is now the one definition of
the length, and `mint` sizes its random bytes from it.

Two stale comments are corrected. The prefix's doc credited the deleted leak
scan, and `HttpFlowHead.url` claimed the host resolves placeholders in a URL.
It never did.

## Witnesses

- `a_minted_placeholder_is_found_wherever_it_sits`,
  `a_mention_of_the_prefix_is_not_a_minted_placeholder` (the matcher)
- `a_minted_placeholder_has_the_shape_the_leak_check_matches` (mint and matcher
  agree)
- `a_placeholder_split_at_any_offset_is_found`,
  `a_placeholder_delivered_one_byte_at_a_time_is_found`,
  `a_body_mentioning_the_prefix_is_not_refused` (the chunked scanner)
- `a_placeholder_in_a_request_body_is_refused_and_recorded`,
  `a_placeholder_in_a_url_is_refused_and_recorded`
- `a_placeholder_split_across_streamed_chunks_is_never_sent`: a forward leg
  that records every body byte it receives gets none of the placeholder.
  Disabling the per-chunk check makes it fail.

## Validation

- `cargo nextest run --no-fail-fast -p mvm-hostd -p mvm-contract -p mvm-core`:
  5048 run, 5048 passed.
- `cargo clippy -p mvm-hostd -p mvm-contract -p mvm-core --all-targets -- -D
  warnings`: clean.
