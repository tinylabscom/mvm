# The Python SDK loads the host library, and its errors are generated

Issue #3261, tasks 3 and 4 and the foundation of task 8.

**Error codes, one definition.** The stable codes a programmatic caller
branches on (`NOT_FOUND` … `UNAVAILABLE`, plus the host library's own
`INVALID_INPUT`, `ABI_NOT_NEGOTIATED`, `EMBEDDER`, `INTERNAL`) are constants in
`mvm_core::error_codes`. That module is outside the `client` feature, so
`mvm-sdk` can name them. `MvmError::code` and the host library's error bodies
use them.

**Generated error classes.** The SDK error taxonomy gains a host-library
family: a `HostLibraryError` base, and one type per code
(`MachineNotFoundError`, `MachineUnavailableError`, `HostLibraryAbiError`, …).
It is keyed by the `code` an error body carries rather than by status number,
because host-library statuses reuse the host-services numbers. `gen-stubs`
emits a `CODE_ERRORS` map beside `STATUS_ERRORS`, and only for a surface that
has code-keyed types. So Python gets it now, and TypeScript gets it when its
binding raises these.

**The Python loader**, `mvm/_hostlib.py`:
- The library comes from `MVM_HOSTLIB_PATH`, else beside `mvmctl` on `PATH`
  (the binary is located, never run; a symlinked `mvmctl` is followed to its
  real directory too), else `MvmTransportError`. An override naming a missing
  file is refused, not ignored.
- The ABI is negotiated once per process, and a mismatch raises
  `HostLibraryAbiError` naming both versions.
- `call(method, request)` raises the type the error body's `code` names, with
  `code`, `retryable` and `status` set, and the base type for a code the SDK
  does not know.
- A test asserts the module references no process API.

The existing `_LiveTransport` is not switched over here. That needs the
library's launch method, which waits on the admission stack (#3476 onward).

## Validation

- `pytest tests/test_hostlib.py`: 15 passed, including the live test against
  a built `libmvm_hostlib.dylib` (`machine.list` answered, an unknown method
  raised `HostLibraryInputError`). The rest of the Python suite passes, apart
  from 8 `test_schema_derive.py` tests that need the optional `pydantic`
  package, which the local environment lacks.
- Taxonomy tests: every host-library code maps to exactly one type, and no
  type carries both a status and a code. Renderer tests: `CODE_ERRORS` is
  emitted only where it has entries, and a manifest without codes still
  parses.
- `gen-stubs` changed only `schema/sdk-errors-v0.json` and the Python
  `types.py`, with additions only.
