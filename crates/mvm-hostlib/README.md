# mvm-hostlib

`mvm-hostlib` is the host library the language SDKs load in-process to drive
machines, in place of running `mvmctl` once per call. It builds a Rust library
and a `cdylib` (`libmvm_hostlib`) exposing one versioned C ABI over the same
`MvmClient` surface the CLI uses, answered by `mvm-client`'s `LocalBackend`.

## Where it sits

At the top of the dependency graph, beside `mvm-cli`. It links `mvm-client`,
and nothing depends on it, so the cycle that kept the SDK from linking the
local backend (`mvm-client → mvm-hostd → mvm-sdk`) cannot form.

## The ABI

```c
typedef struct { uint8_t *data; size_t len; } MvmHostlibBuf;

uint32_t mvm_hostlib_abi_version(void);                  /* (major << 16) | minor */
int32_t  mvm_hostlib_abi_is_compatible(uint16_t major, uint16_t minor);
int32_t  mvm_hostlib_call(const uint8_t *method, size_t method_len,
                          const uint8_t *request, size_t request_len,
                          MvmHostlibBuf *out);
void     mvm_hostlib_free(MvmHostlibBuf buf);
```

1. A binding calls `mvm_hostlib_abi_is_compatible` with the ABI version it was
   built for. Until that returns 1, every call is refused with
   `MVM_HOSTLIB_ABI_NOT_NEGOTIATED`: a binding and library that disagree about
   the buffer layout would otherwise read and free memory neither described.
2. It calls a dotted method with a JSON request. Request types refuse unknown
   fields.
   - `machine.list`, `machine.inspect`, `machine.logs`,
     `backend.capabilities` go to the `MvmClient`.
   - `guest.proc.{start,list,signal,kill,stdin,wait}` and
     `guest.fs.{read,write,list,stat,mkdir,remove,rename}` go to
     `mvm_client::guest`, the same implementation `mvmctl machine proc`/`fs`
     use, with the same audit entries. They are DevOnly agent verbs, refused
     on a sealed image. Byte payloads cross as base64, and
     `guest.proc.wait` buffers each output stream up to 8 MiB and reports
     `truncated` past that.
3. It gets back a status and a JSON buffer, and releases the buffer with
   `mvm_hostlib_free`. Statuses 1 to 7 mirror `MvmError`, and the error body
   carries the same `code` and `retryable` every other programmatic surface
   reports.

Each call builds a single-threaded runtime and drops it before returning, so
nothing the library starts outlives the call.

## Running inside another program

Loaded into `python3` or `node`, the running executable is the interpreter.
Before its first call reaches the runtime, the library declares the process a
library embedder, so every path that would spawn `mvmctl` refuses. It also
declares its own directory, found through `dladdr`, as the directory holding
the per-VM helper binaries, which ship beside it.

## Tests

`cargo nextest run -p mvm-hostlib` covers the status mapping, every method
against `MockBackend`, unknown fields and methods, ABI negotiation, the entry
points' buffer handling, and the embedder path logic.
