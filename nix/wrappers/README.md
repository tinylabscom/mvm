# Function-entrypoint wrapper templates

These are the per-language wrappers that get baked into the rootfs at
image build time when `Entrypoint::Function` is declared (ADR-0009 /
plan-0003 phase 4).

| File | Language | Tier | Status |
| --- | --- | --- | --- |
| `python/oneshot.py` | CPython 3.10+ | cold (one call per process) | shipped |
| `python/longrunning.py` | CPython 3.10+ | warm-process (ADR-0011) | shipped |
| `node/oneshot.mjs` | Node 22+ | cold (one call per process) | shipped |
| `node/longrunning.mjs` | Node 22+ | warm-process (ADR-0011) | shipped |

The `oneshot` variants are the cold-tier wrappers: one user-fn call per
process, fresh state every time, dispatched per-call by the substrate
agent. The `longrunning` variants implement ADR-0011's warm-process
tier — the same wrapper handles many sequential calls over a framed
multi-call protocol on stdin/stdout, with bounded recycling enforced
upstream by mvm's worker pool.

## Warm-process protocol (longrunning variants only)

Per call, the framed protocol exchanges one `WorkerCallRequest` →
one `WorkerCallResponse`. Each frame is a 4-byte big-endian length
prefix followed by a JSON body. Schema mirrors
`mvm_agentd::worker_protocol`:

```json
// Request
{ "stdin": "<base64 encoded-args>", "timeout_secs": 60 }

// Response
{ "stdout": "<base64 encoded-return>",
  "stderr": "<base64 user-stderr>",
  "outcome": { "exit": { "code": 0 } } }
// or
{ "stdout": "...", "stderr": "...",
  "outcome": { "error": { "kind": "ValueError", "message": "..." } } }
```

EOF on stdin (agent closed the pipe) → wrapper exits 0 cleanly. Frame
length cap: 256 KiB (matches mvm's substrate cap). Per ADR-0011,
**cross-call state is the user's responsibility** — the longrunning
wrappers do not scrub Python globals, the Node module cache, /tmp,
or anything else between calls.

## Contract

The wrapper reads `[args, kwargs]` from stdin in the IR-declared format,
dispatches `module:function`, and writes the encoded return value on
stdout. On user-code failure, it emits a single-line JSON envelope on
stderr and exits non-zero:

```json
{ "kind": "ValueError", "error_id": "abc-123", "message": "negative input" }
```

The host SDK parses this envelope and raises a structured `RemoteError`
in the caller's language.

## Build-time configuration

The future `mkPythonFunctionService` / `mkNodeFunctionService` Nix
factories on the [`mvm`](https://github.com/auser/mvm) side will write
`/etc/mvm/wrapper.json` at build time:

```json
{
  "module": "adder",
  "function": "add",
  "format": "json",
  "working_dir": "/app",
  "mode": "prod"
}
```

The wrapper reads this on startup. Both fields are baked at build —
nothing about dispatch is decided at call time except the args bytes.

## Modes

- **`prod`** (default): sets `PR_SET_DUMPABLE=0` (Linux), sanitizes error
  envelopes (no traceback, no file paths, no payload bytes in logs), no
  payload contents in operator logs. The full traceback flows through a
  separate operator-log channel (vsock secondary stream → host stderr,
  reachable via `mvmctl logs <vm>`) — never to the SDK caller.
- **`dev`**: prints the full traceback to stderr alongside the envelope.
  Never ship a `mode=dev` artifact to production.

## Decoder hardening

Both wrappers enforce ADR-0009 §Decoder hardening:

- max nesting depth 64 (cuts off recursive payloads)
- reject duplicate keys in JSON objects
- reject non-finite floats (NaN, ±Infinity)
- pinned to stdlib + a single audited msgpack library per language

## Forbidden imports (CI lane)

Phase 1 of plan-0007 wires `just wrapper-forbidden-check` into `just ci`:
the script greps wrapper templates for code-executing serializer
formats and dynamic-execution surfaces (per-language list in
[`scripts/wrapper_forbidden_tokens.json`](../../scripts/wrapper_forbidden_tokens.json),
derived from ADR-0009 §Decision). Lines containing
`# mvm-allow: <reason>` (Python) or `// mvm-allow: <reason>`
(JS/TS) are exempt.

## Threat model

The full threat model — what each defense addresses, where it lives,
and the known limits — is documented in
[`docs/src/content/docs/reference/wrapper-security.md`](../../docs/src/content/docs/reference/wrapper-security.md)
(rendered as **Reference → Wrapper Security & Threat Model** in the
Astro+Starlight docs site).

## When this gets used

mvm currently **does not** invoke these wrappers — the ADR-0007
guest-lib factories `mkPythonFunctionService` / `mkNodeFunctionService`
land on the mvm side, then mvm's `flake.rs` will dispatch to them
when `Entrypoint::Function` is detected. These templates are checked in
ahead of that landing so the contract and threat model can be reviewed
against the actual code that will ship.
