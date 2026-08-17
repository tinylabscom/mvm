# Plan 337 — WS-6 increment 1 (Tier C transport + error taxonomy)

**Delivered:** 2026-08-16
**Plan:** `specs/plans/337-sdk-surface-generated-from-rust.md`
**Follows:** WS-7 + WS-8 (`337-ws7-ws8-closeout.md`)

Tier C shipped as the **declared subset** WS-6.1 recommended: implement what is
portable, refuse what is not, and say which is which.

## Why the errors and the transport had to land together

The eight Tier D error types are raised only by Tier C's machinery. WS-5
deliberately left them out for that reason — generating the classes while
TypeScript had no code that could throw them would have exported eight dead
types and cleared eight divergence entries while closing nothing. That is the
same objection WS-2 raised against dead constants. So this change adds the
registry entries and the code that raises them in one step.

`RemoteError` needed one registry extension: structured fields plus a message
format, since it carries `kind` / `error_id` / `message` rather than being a
plain subclass. Every other type is a plain subclass and needed nothing.

## What TypeScript gained

`crates/mvm-sdk/sdks/typescript/src/_remote.ts`:

- real-VM invocation — encode `[args, kwargs]`, feed `mvmctl invoke` over
  stdin, decode stdout;
- the stderr envelope scan, with the same primary marker plus last-line
  fallback shape Python uses;
- `RemoteFunction`, `func`, `workload_ref`, `WorkloadRef` — the last via a
  `Proxy`, where Python uses `__getattr__`;
- the payload cap, invoke timeout and output cap, reading the same environment
  variables and matching Python's silent fallback on a malformed value.

Python's `_remote.py` no longer defines any of the eight error types; it
imports them from the generated module.

## What it refuses, and why that is the feature

`MVM_NO_VM=1` raises `NoVmIntrospectionError` naming the reason. Python derives
that path's argv from the function object — `__module__`, `__name__`,
`inspect.getfile` — and JavaScript cannot ask a function which module defined
it. Falling through to the real-VM path would have been the worse failure: the
caller asked for local dispatch and would have got a microVM.

## Two language differences stated rather than smoothed over

`SecretInArgWarning` moves to `python_only_permanent_by_design`. JavaScript has
no warning type, and `exports_to` refuses to emit a `Warning` into TypeScript,
so this never closes.

`RemoteError.message` differs by necessity. Python sets `str(e)` to the composed
message and `.message` to the raw one; JavaScript has only `.message`, holding
the composed string. The generated TypeScript therefore does not redeclare
`message` as a property.

## Not in this increment

Sessions — `Session`, `session`, `current_session_id`. They are the piece whose
semantics force the `AsyncLocalStorage`-versus-ergonomics choice from WS-6.1,
and they deserve their own change. `_remote.ts` does not consult an active
session yet and says so in its module note. WS-6.5's BDD coverage lands with
them.

## Verification

- `cargo +nightly fmt --all -- --check`, `clippy --workspace --all-targets` — clean
- `check-stubs` — no drift
- Python **223 passed**, with all eight error types now generated
- TypeScript **138 passed**; typecheck and build clean
- BDD **200 scenarios passed**
- Behaviour checked live against the built ESM: `MVM_NO_VM=1` refuses with
  `NoVmIntrospectionError`, the emit guard raises `EmittingContextError`,
  `RemoteError` composes `ValueError: boom (error_id=abc)` while exposing
  `kind` and `error_id`, and `PayloadTooLarge instanceof MvmTransportError`
  holds

## Divergence

`python_only_absent_from_typescript`: **16 → 4** (`Session`, `session`,
`current_session_id`, `current_recording_dict`). Across the whole plan it has
gone 30 → 4, and `typescript_only_absent_from_python` remains 0.
