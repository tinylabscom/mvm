# FlowMux wire contract: framing, opcodes, and the session state machine

Plan 316 Phase 1 (#2370), the first of three changes in that phase. Adds
`mvm-contract::protocol::network_flow` — the one definition of what a FlowMux
frame is, shared by guest and host, `no_std + alloc` and `forbid(unsafe_code)`
like the rest of the crate because the guest side links into the sealed agent.

Four modules, deliberately separable:

- `limits` — the ceilings a hostile peer cannot raise, as consts rather than
  negotiated parameters so a `Hello` cannot talk the host into a larger
  allocation. `MAX_FLOW_CREDIT_BYTES` is *derived* from the flow ceilings and
  the per-stream window rather than restated beside them, so raising a ceiling
  raises the endpoint's memory bound automatically instead of silently
  desynchronising from it.
- `opcode` — all 27 version-1 opcodes with pinned wire discriminants, their
  flow class, which side may send each, and the confirmation relation.
- `frame` — the 20-byte fixed header and a state-independent decoder.
- `state` — the session and per-stream machine.

## Why the decoder and the state machine are separate

The decoder answers "is this a well-formed v1 frame" from bytes alone. The
state machine answers "is this frame legal right now, from this side". A frame
can be perfectly well-formed and still be an attack, and conflating the two
checks is how one of them ends up not really running. Splitting them also means
each is fuzzable on its own: the decoder needs no session, the state machine
needs no bytes.

## Decisions worth recording

**The length field is a `u32`, not the packet tunnel's `u16`.** The plan caps a
frame payload at 64 KiB, which is one byte past what a `u16` can express. A cap
the length field cannot represent is not really enforced at the parse boundary,
so the header grew the field rather than the cap shrinking to fit it.

**Stream-ID reuse is refused by a watermark, not a set.** "Reject reuse after
reset" naively means remembering every ID ever closed — an unbounded allocation
the peer drives, which is the exact shape of bug this protocol exists to avoid.
Each parity carries a high-water mark instead. That is O(1) with no memory
growth, and it additionally refuses re-opening any *lower* ID, which is strictly
stronger than remembering only the ones actually used.

**Stream IDs are parity-split.** Odd is guest-initiated, even non-zero is
host-initiated ingress, zero is the session's. The two sides allocate from
disjoint spaces, so simultaneous-open collisions cannot occur — and a flow frame
claiming stream 0, or a session frame claiming a flow stream, is refused in both
directions so neither can smuggle a frame into the wrong machine.

**`Opened` and `Refused` are shared between TCP and typed HTTP,** because from
the transport's point of view a TCP open and an HTTP open are the same act: the
host connected, or it did not. That sharing is why a confirmation cannot be
checked against the class field alone, and why `Opcode::confirming_classes()`
spells the relation out. A first draft classed `Opened` as TCP-only and a test
caught it.

**Ingress must be backed by a declaration.** An `InboundOpen` names the admitted
mapping it came from; the validator holds the mapping IDs the *signed plan*
declared and refuses anything else, so a listener nobody signed for cannot be
conjured by sending a frame about it. The default validator declares nothing, so
every ingress open fails closed.

**A refused frame moves nothing.** Every rejection path leaves the validator
byte-identical, asserted both by a unit test and continuously by the state fuzz
target. Otherwise a peer could drive state changes with frames it is not allowed
to send.

## Coverage

87 unit tests: round-trip for every opcode empty and with payload, maximal
payload, truncated prefix and body reported as `Incomplete` and never as
anything else, oversized length refused from the prefix alone before the body
arrives, bad magic, every bad version, unknown opcodes, every reserved flag bit,
wrong header length, payload/frame length disagreement, both stream-ID class
violations, back-to-back decode, hand-written golden bytes, explicit
big-endian field placement, and pinned opcode discriminants. On the state side:
the handshake, out-of-order and duplicate handshake frames, post-`GoAway`
silence, every directional opcode from the wrong side, data before open and
before confirmation, duplicate open, reuse after reset, parity violations,
independent parity watermarks, undeclared and missing ingress mappings, credit
consumption and grant, credit exhaustion, window-ceiling and `u32` overflow,
empty grants, per-stream credit isolation, half-close semantics, class
discipline, the class ceilings, fail-closed on every refusal, and 10,000
open/reset cycles that do not grow the validator.

`crates/mvm-contract/fuzz` adds `fuzz_network_flow_decode` and
`fuzz_network_flow_state` with 95 committed seeds — one valid frame per opcode,
the malformed-length family, and one transition sequence per flow class. Both
are wired into `security.yml`'s fuzz lane. The decode target asserts the payload
cap holds, the consumed span stays inside the buffer, a truncation always
reports `Incomplete`, a bumped version is always refused, and — the interesting
one — that a decoded frame re-encodes to exactly the bytes it decoded from, so a
decoder that "helpfully" normalizes a malformed field becomes a fuzz failure
rather than a place where two peers quietly disagree about what they exchanged.
The state target asserts the ceilings, the credit window, that a retired stream
ID is never re-admitted, and that refusals move nothing. Local runs: 18.4M
executions on the decoder and 2.9M on the state machine, both clean.

## Not in this change

`NetworkLimits` (the transport-neutral plan type), the authenticated-session
extraction, and the `xtask network-perf` harness with its Linux x86_64 and
macOS arm64 baselines. Nothing consumes this codec yet — Phase 2 (#2371) is
what wires it to an endpoint.
