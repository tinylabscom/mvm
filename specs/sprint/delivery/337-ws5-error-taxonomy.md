# Plan 337 — WS-5 (error taxonomy) and WS-6.1 (Tier C sizing)

**Delivered:** 2026-08-16
**Plan:** `specs/plans/337-sdk-surface-generated-from-rust.md`
**Follows:** the WS-1 + WS-2 delivery in
`specs/sprint/delivery/337-sdk-surface-generated-from-rust.md`

## WS-5 — the error taxonomy is Rust-owned and generated

`crates/mvm-sdk/src/error_taxonomy.rs` declares each error type once — name,
base class, doc, and the `MVM_HSVC_*` status it is raised for. `emit_sdk_errors`
serialises it; `xtask/src/gen_sdk_surface.rs` renders `mvm/_errors/types.py` and
`src/_errors/types.ts`. Both hand-written mirrors are deleted, and the artifact
is drift-gated by the same `check-stubs` that already runs twice.

The status codes are the part worth having. They live in
`crate::host_services_ffi` and were re-declared as literals in **both** SDKs
under a comment reading *"Must match the `MVM_HSVC_* `status codes in the Rust
cdylib"* — a mirror maintained by asking a human. The prose had already
drifted: Rust's `MVM_HSVC_BAD_REQUEST` doc says "audit cap" where the
TypeScript copy said "e.g. the 4 KiB audit cap". Harmless in a comment; the
same drift in a number would have mis-routed a broker failure to the wrong
exception type. `STATUS_OK` is generated too, so nothing of the mirror
survives.

The registry models the hierarchy rather than per-language literals:
`ErrorBase` is `Root` / `Runtime` / `Warning` / `Named`, and each emitter maps
it (`Runtime` → Python `RuntimeError`, TypeScript `Error`). `Warning` has no
JavaScript form at all, so `SdkErrorType::exports_to` refuses to emit one into
TypeScript rather than trusting the declaration — the same enforcement shape
WS-2 used for surfaces.

WS-5.3 ("assert the taxonomy is catchable in both") is satisfied and checked
live: a `RateLimitedError` is caught as `HostServiceError` in Python, and
`instanceof HostServiceError` holds in the built TypeScript ESM.

### The scope correction

Tier D's eight *named* types (`RemoteError`, `MvmTransportError`,
`MsgpackUnavailable`, `PayloadTooLarge`, `NoVmIntrospectionError`,
`SecretInArgError`, `SecretInArgWarning`, `EmittingContextError`) are **not**
generated here, and this plan's workstream ordering is wrong about them.

All eight are raised exclusively by Tier C's machinery in `_remote.py`.
TypeScript has no Tier C, so emitting them now would export eight classes
nothing in TypeScript can throw — the same dead-export dishonesty WS-2 refused
for the `MVM_MACHINE_*` constants, and it would clear eight entries from
`surface_divergence.json` while closing nothing. They land **with WS-6**, which
also turns 6.6 into a real step instead of a retrofit. The registry is built to
absorb them unchanged.

## WS-6.1 — Tier C sized, and it is not a mechanical port

The plan's line count is exact (816 + 349 = 1,165). Its characterisation is
not. Those lines hold **two dispatch paths**, and the second has no faithful
TypeScript form:

1. **`MVM_NO_VM=1` is unportable.** `_prepare_invoke` branches to
   `mvmctl __sdk-no-vm`, deriving argv from the local Python function object
   via `fn.__module__`, `fn.__name__`, `inspect.getfile(fn)`. JavaScript cannot
   ask a function which module defined it; `fn.name` does not survive
   minification; a source path needs `Error().stack` parsing and fails for any
   function received rather than defined. The Rust side already takes
   `--language`, so the substrate is multi-language — the introspection is the
   blocker, and effort does not fix it.
2. **Session scoping is a choice, not a translation.** Python holds the active
   session in a `contextvars.ContextVar` and resets its `Token` in `__exit__`.
   `AsyncLocalStorage` scopes to a callback instead, with no token to return.
   Either `session(id, async () => {…})` (correct isolation, different call
   shape) or `using s = session(id)` over a module global (nicer, but
   concurrent sessions clobber each other). Not both. The safer default is the
   first: the wrong answer here leaks one session's context into another.
3. **The abandonment net weakens.** `weakref.finalize` best-effort stops a
   forgotten session; the `FinalizationRegistry` specification permits
   never running it at all, and it is not run at exit. A dropped TypeScript session leaks the VM until its TTL reaps
   it — tolerable only because the TTL exists, and worth stating rather than
   implying.
4. `WorkloadRef.__getattr__` needs a `Proxy`.
5. The dual sync/async surface has no clean JS form: a promise cannot be
   awaited synchronously.

**Uncounted tail:** those two files read ten further environment variables
(`MVM_EMITTING`, `MVM_ENVELOPE`, `MVM_INVOKE_KILL_GRACE_SEC`,
`MVM_INVOKE_TIMEOUT_SEC`, `MVM_MAX_OUTPUT_BYTES`, `MVM_MAX_PAYLOAD_BYTES`,
`MVM_NO_VM`, `MVM_SESSION_START_TIMEOUT_SEC`, `MVM_SESSION_STOP_TIMEOUT_SEC`,
`MVM_STRICT_SECRETS`), none in the WS-2 registry. They should be budgeted with
WS-6 and declared for TypeScript only once TypeScript reads them.

**Recommendation:** ship TypeScript Tier C as a declared subset — real-VM
invocation yes, `MVM_NO_VM` no, callback-scoped sessions, best-effort finalizer only — recorded in `surface_divergence.json` as permanent-by-design, the
treatment WS-7 gives `derive_schema`. Tier C stays worth doing; budgeting it as
mechanical would produce a TypeScript surface that looks complete and is not.

## Verification

- `cargo +nightly fmt --all -- --check` — clean
- `cargo clippy --workspace --all-targets` — zero warnings
- `cargo nextest run --workspace` — 11,941 passed. Three `mvm-vmm`
  `broker_services_spawn` tests failed under `-j 6` on a cold target dir and
  pass isolated in 0.5s versus 10–19s under load; this change touches no file
  in `mvm-vmm`.
- `check-stubs` — no drift, and proven to exit 1 on a hand-edited generated
  class
- Python: **212 passed, 7 skipped, zero test-file edits**
- TypeScript: 138 passed; `typecheck` and `build` clean
- Catchability checked live in both languages

## Not done

WS-6.2–6.6, WS-3, WS-4, WS-7, WS-8.
