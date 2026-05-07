# Function-entrypoint wrapper templates

These are the per-language wrapper templates that bake into a microVM
rootfs when a workload declares `Entrypoint::Function`
(mvm ADR-007 / mvmforge ADR-0009).

Relocated from `mvmforge/nix/wrappers/` under mvm plan 49
(wrapper-templates-relocation). Canonical home is now
`mvm/nix/wrappers/`; these are the substrate-side reference
implementations.

| File | Language | Status |
| --- | --- | --- |
| `python-runner.py` | CPython 3.10+ | shipped |
| `node-runner.mjs` | Node 22+ | shipped |

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

The current `mvm.lib.<system>.mkPythonFunctionService` /
`mkNodeFunctionService` factories at `nix/lib/factories/` embed the
runner script inline (see those files plus the README there). A
follow-up plan refactors the factories to consume these
file-based wrappers and read config from `/etc/mvm/wrapper.json` at
runtime, eliminating the inline duplication. The future shape:

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
`# mvmforge-allow: <reason>` (Python) or `// mvmforge-allow: <reason>`
(JS/TS) are exempt.

## Threat model

The full threat model — what each defense addresses, where it lives,
and the known limits — is documented in
[`docs/src/content/docs/reference/wrapper-security.md`](../../docs/src/content/docs/reference/wrapper-security.md)
(rendered as **Reference → Wrapper Security & Threat Model** in the
Astro+Starlight docs site).

## When this gets used

The mvm-side factories at `nix/lib/factories/` currently embed their
runner inline; they don't yet consume these file-based templates. A
follow-up plan refactors the factories to drop the inline code and
read these wrappers + a `/etc/mvm/wrapper.json` config from disk,
eliminating the duplication. Until then, **changes to the inline
runners in `nix/lib/factories/mk*FunctionService.nix` must be
mirrored here** so the canonical templates stay accurate.
