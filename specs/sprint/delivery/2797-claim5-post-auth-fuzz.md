# 2797 — claim 5's post-auth witness now watches the path production takes

#2794 moved the control plane to the binary sealed envelope and recorded, but
did not fix, the consequence: `fuzz_authed_path` drove
`verify_authenticated_frame`, a signature-only path over the old JSON envelope
that no production code called any more. Claim 5 kept a witness aimed at code
nothing took.

## The target now drives `Session::open`

Protocol version, session id, sequence, signer identity, Ed25519 signature over
the frame context, AES-GCM decryption — the checks that actually decide whether
a frame's payload is handed back.

## The first version of it was worthless, and the mutation check is what said so

The obvious design perturbs a field of a sealed frame and asserts `Err`. That is
what the first draft did for the sequence and the session id, and it passes for
the wrong reason: the Ed25519 signature covers the frame context, so tampering
any of those fields is refused by the *signature* check. Deleting the sequence
check entirely left the target green through 100,994 runs.

Isolating a check means producing a frame that is validly signed and wrong only
in the one respect:

| scenario | how | isolates |
|---|---|---|
| gap | host seals twice, peer is offered the second | sequence check |
| replay | the same frame delivered twice | sequence check |
| other session | sealed in a second session, same identities | *nothing new* — see below |

With the sequence check deleted, the rebuilt target is caught in under 40
seconds: `a validly signed frame that skipped a sequence was accepted`.

The cross-session scenario does **not** isolate the session-id check, and the
target's comment says so rather than implying otherwise. `derive_session_key`
mixes the session id into the key, so a cross-session frame fails AES-GCM
decryption on its own. That is defence in depth working; it is not a witness
for the session check, and citing it as one would be the same error a level up.

## A gap that had to be closed before the deletion, not after

`Session::open` refuses a frame whose version or `sig_alg` it does not speak.
Nothing tested that. The property had been covered only by the JSON envelope's
serde tests in `mvm-contract` — which were about to be deleted along with the
type. Removing them first would have widened a gap while appearing to tidy one.
`an_unsupported_version_or_sig_alg_is_refused` covers it directly on the sealed
path, mutation-checked before the deletion went ahead.

## What was deleted

`write_authenticated_frame`, `read_authenticated_frame`,
`verify_authenticated_frame`, their seven tests, the `AuthenticatedFrame` type
and its three tests. Verified unused first — including in the `mvmd` sibling
repo, which consumes `mvm-contract` as a path dependency and has zero
references.

Six doc comments described the control plane as JSON-enveloped. All six were
false by the time this branch started; they now name `SealedFrame`.

`paired_sessions_for_test` is the unit tests' own pairing helper, promoted
behind the existing `test-support` feature so the fuzz target can build a
session without a handshake per iteration. It is handed a shared secret rather
than agreeing one, which is exactly why it is feature-gated.
