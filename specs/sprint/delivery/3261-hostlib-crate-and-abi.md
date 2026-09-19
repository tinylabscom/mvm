# The host library crate and its versioned ABI

Issue #3261, task 2 of the order set on the issue: the crate skeleton, the
ABI, and the read-only machine methods. WS2 of
`specs/plans/2026-09-15-agent-sandbox-drive-plane.md`.

`crates/mvm-hostlib` builds `libmvm_hostlib`, which the Python and TypeScript
SDKs will load in-process in place of running `mvmctl` once per call. It sits
at the top of the dependency graph and nothing depends on it, so linking
`mvm-client` cannot form a cycle. It follows `mvm-host-services`: one JSON call,
a paired free, `catch_unwind` at the boundary, and an asserted buffer layout.
It adds the versioning that crate lacks.

```c
uint32_t mvm_hostlib_abi_version(void);                       // (major << 16) | minor
int32_t  mvm_hostlib_abi_is_compatible(uint16_t, uint16_t);   // 1 or 0
int32_t  mvm_hostlib_call(method, len, request, len, MvmHostlibBuf *out);
void     mvm_hostlib_free(MvmHostlibBuf);
```

- **Negotiation is enforced.** A call made before
  `mvm_hostlib_abi_is_compatible` has returned 1 is refused with
  `MVM_HOSTLIB_ABI_NOT_NEGOTIATED`. Compatible means the same major and a
  binding minor no newer than the library's.
- **Statuses 1 to 7 mirror `MvmError`** one to one. The error body carries
  `MvmError::code()` and `retryable()`, so a binding needs no table of its own.
  Statuses 8 to 11 are failures of the call: invalid input, not negotiated,
  embedder setup, internal. Registering them in the SDK error taxonomy is task
  3.
- **Methods so far are read-only**: `machine.list`, `machine.inspect`,
  `machine.logs` (base64 bytes, and no `follow`, since one call returns once),
  and `backend.capabilities`. Request types refuse unknown fields. An unknown
  method is refused before any client is built.
- **Embedder declarations.** Before the first call reaches the runtime, the
  library declares the process a library embedder, so every `mvmctl` spawn
  path refuses (the mechanism from #3439). It also declares its own directory,
  found through `dladdr`, as the helper-binary directory, since the release will
  ship them side by side.
- Each call builds a current-thread runtime and drops it before returning, so
  nothing the library starts outlives the call.

## Validation

- `cargo nextest run -p mvm-hostlib`: 26 tests, covering status mapping, every
  method against `MockBackend`, unknown fields and methods, negotiation, the
  entry points' buffer handling, and the embedder path logic.
- `cargo clippy -p mvm-hostlib --all-targets -- -D warnings`: clean.
- In-process from a real foreign host: `python3` with `ctypes` loaded
  `target/debug/libmvm_hostlib.dylib` (with `MVM_HOME` in `/tmp`). A call before
  negotiation was refused (status 9). `abi_is_compatible(2, 0)` returned 0 and
  `(1, 0)` returned 1. `machine.list` answered `[]`, `machine.inspect` for an
  absent id answered status 1 with `NOT_FOUND`, `backend.capabilities` answered
  its report, and an unknown method was refused. No `mvmctl` process was
  involved.
- `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D
  warnings` and `just check-gated` (which covers the Linux build of the `dladdr`
  path): pass.
- `xtask check-all`: the only failure was `check-feature-closure-budget`, at
  485 against 484. That is the new crate itself, since its dependencies were
  already present. The budget is raised to 485 with that justification, in the
  same form the gate recorded for `mvm-mcp`, `mvm-capture` and
  `mvm-host-services`. The default `mvmctl` closure is unchanged at 229.
