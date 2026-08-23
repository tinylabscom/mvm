# 2780 — stdout over ~25 KB killed the control session

`mvmctl machine run --image rust -- sh -c "ls -l /usr/bin"` failed with

```
Error: control frame open failed: sequence mismatch: got 2, expected 1
```

Nothing about that message is about stdout, which is what it was about. Any
command whose output exceeded roughly 25 KB in one burst hit it; `echo hi` did
not. Bisected on HVF/macOS 26 aarch64: 24000 bytes passed, 28000 failed.

## Two defects, one visible

**The chunk cap was sized against one JSON encoding, not two.** Content crosses
two nested `Vec<u8>` encodings before it reaches the wire — first the
`GuestResponse` body, then the sealed envelope's ciphertext, which is itself a
`Vec<u8>` in `SignedPayload::payload`. Neither hop is base64, so the worst case
of four characters per byte (`255,`) applies twice and the expansions multiply
to roughly 10x in practice. `MAX_DATA_CHUNK_SIZE` was 48 KiB against a 256 KiB
frame cap; the wire could carry about 25 KB.

The old constant's own doc comment states the single-encoding reasoning
verbatim — "whose worst case is four bytes per input byte (`255,`). Forty-eight
KiB leaves room for the request or response envelope" — so the miss was in the
derivation, not in an edit that drifted from it. `MAX_DATA_CHUNK_SIZE` is now
computed from `MAX_FRAME_SIZE` and a named expansion factor, with a
`const` assertion so neither constant can move without confronting the other.

**A frame that failed to send left the session permanently desynchronized.**
`Session::seal` advances the send counter before the frame can be handed to a
transport, so a `write_frame` failure spent a sequence number on bytes that
never left the guest. `write_response` logged it and carried on. The next chunk
went out as sequence 2 against a host still expecting 1.

The counter cannot be rewound: the AES-GCM nonce derives from
`(session_id, role, sequence)`, so re-sealing different plaintext under a spent
sequence would be nonce reuse. The session therefore fails closed —
`Session::poison_send` records the spent sequence and the original cause, and
every later `seal` and `open` refuses and names it.

This half is not specific to oversize frames. *Any* transport failure on this
path produced the same misleading `sequence mismatch`, several frames later,
with no context — `send_exec_streaming` propagates it bare, so the CLI printed a
one-line error with no hint of what had actually gone wrong.

## What the tests are worth

`oversized_write_is_rejected_before_writing_any_bytes` already existed and
passed throughout. It exercises `write_frame` in isolation, so it proved no
bytes were written and could not see that the session had been left unusable —
the gap was between the two, which is where the bug lived.

The new witnesses were confirmed red before they were green. Reverting the
poison alone fails `a_transport_failure_after_the_seal_does_not_desync_the_peer`
and `a_chunk_above_the_cap_fails_the_write_and_poisons_the_session`;
`without_poisoning_a_dropped_frame_would_desync_the_peer` pins the old
behaviour so a regression reads as the confusing error again;
`sealed_worst_case_chunk_fits_the_frame_cap` seals a full-size chunk of `0xFF`
— the most expensive byte there is under both encodings — through a real
session and asserts the encoded envelope fits.

## Not done here

`AuthenticatedSession::write` JSON-wraps the sealed frame even though
`SealedFrame::encode` already defines a compact binary layout for exactly this.
Using it would remove the ~4x envelope expansion and let chunks go back to
48 KiB. It changes the host↔guest wire format and needs a guest-agent and OCI
rootfs cache rebuild, so it is its own change; recorded on the issue.

`write_response` still returns `()` and still swallows the write error. With the
session poisoned that swallow is now inert by construction rather than by luck —
no wrong-sequence frame can reach the wire afterwards — so threading a `Result`
through its four guest-agent call sites buys nothing but churn. The console
message now names the consequence instead of just the error.
