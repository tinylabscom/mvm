# 2790 — the control plane stopped JSON-wrapping sealed frames

`AuthenticatedSession` wrapped every sealed control frame in JSON, which
re-encoded the ciphertext `Vec<u8>` as an array of decimal numbers. The egress
plane already used the compact `SealedFrame::encode` for the same struct;
only the control plane paid for a second encoding.

## The number, and the guess it replaced

The switch was first argued for on bandwidth — roughly 10x amplification, so
maybe 5–10 ms on a large transfer. That reasoning was wrong by two orders of
magnitude, and wrong in the direction that would have made the work look not
worth doing. Measured, one 15872-byte stdout chunk, release, aarch64 macOS:

| | wire bytes | encode | decode |
|---|---|---|---|
| JSON envelope | 184050 | 212 us | 492 us |
| `SealedFrame::encode` | 51664 | 0.9 us | 0.9 us |
| ratio | 3.6x | 244x | 540x |

Bytes were the small half. ~705 us per frame of serde_json was the cost.

End-to-end on HVF, 900 KB of guest stdout, guest command phase, two runs each:

| | run 1 | run 2 |
|---|---|---|
| JSON envelope, 15.5 KiB chunks | 69.6 ms | 75.4 ms |
| binary envelope, 62 KiB chunks | 34.4 ms | 33.3 ms |

Both variables moved together — the chunk cap rises *because* the envelope
changed — so ~38 ms is the combined effect, not the envelope alone.
`crates/mvm-agentd/tests/control_envelope_cost.rs` keeps the per-frame half
re-runnable rather than re-derivable.

## What moved

`write`/`read` use `write_sealed_frame`/`read_sealed_frame`, already generic
over `Write`/`Read` and already carrying the `[u32 BE len]` framing — no new
framing code. Content crosses one JSON hop instead of two, so the chunk cap
re-derives from 15.5 KiB to 62 KiB and the `const` assertion moves with it.

The outbound size check moved earlier and is stricter for it. `write_frame`
enforced the cap *after* sealing, so an oversize frame also spent a sequence
number and poisoned the session on its way to being rejected. The check now
runs on the plaintext before `seal`, so an oversize payload is refused with the
session still usable — and the test asserts the peer is still in step
afterwards, rather than asserting the session died.

That regression was self-inflicted and caught by a test failing for the
opposite reason it was written for: `write_sealed_frame` has no size check, so
the first version of this change silently dropped the outbound cap entirely.

## The fuzz witness moved with the ingress

Claim 5 names the vsock framing targets. `fuzz_authenticated_frame` fuzzed
`serde_json::from_slice::<AuthenticatedFrame>`, which stopped being what the
control plane parses, so it became `fuzz_sealed_frame` against
`SealedFrame::decode`. The rename touched seven coupled files: the fuzz
`Cargo.toml`, `security.yml`, the fuzz README, ADR-001's ledger row *and* its
prose, `CONFORMANCE.md`, and `model/claims.toml`. The last was found by
sweeping for the old name rather than by knowing about it.

## Deliberately not done

`fuzz_authed_path` and the legacy `write_authenticated_frame` /
`read_authenticated_frame` / `verify_authenticated_frame` trio are untouched.
They have **no production callers** — the only call sites are their own tests
and that fuzz target. Before this change that mattered less, because
`AuthenticatedFrame` was the shape the control plane really used. It is not
now, so claim 5 currently has a witness aimed at a path production does not
take.

Deleting the trio takes the target with it, and rebuilding it around
`Session::open` — the real post-auth path, covering version, session id,
replay, signer, signature and decrypt — is worth its own change rather than the
tail end of a framing swap. Deleting without rebuilding would trade a stale
witness for a missing one.
