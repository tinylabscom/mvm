# mvm-hostlib

`mvm-hostlib` is the host library the language SDKs load in-process to drive
machines. It builds a Rust library and a `cdylib` (`libmvm_hostlib`) exposing
one versioned C ABI over `mvm-client`: the `MvmClient` surface answered by
`LocalBackend`, the admitted local launch, and the DevOnly guest operations in
`mvm_client::guest`. The SDKs never run `mvmctl`; `xtask check-no-cli-shellout`
fails the build if their source reaches for a process API.

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
   fields. The ABI is 1.2.
3. It gets back a status and a JSON buffer, and releases the buffer with
   `mvm_hostlib_free`. Statuses 1 to 7 mirror `MvmError`, and the error body
   carries the same `code` and `retryable` every other programmatic surface
   reports.

The method registry (`src/registry.rs`) is the source of truth: `cargo xtask
gen-stubs` renders it into `schema/host-abi-v0.json` and
`schema/host-abi-methods-v0.json`, and from those into typed request/reply
classes and method tables for both SDKs.

### Methods

| Family | Methods | Answered by |
|---|---|---|
| Lifecycle | `machine.list`, `machine.inspect`, `machine.logs`, `machine.start`, `machine.stop`, `machine.rm`, `machine.exec`, `machine.inventory`, `backend.capabilities` | the `MvmClient` trait, and `mvm_client::inventory` |
| Launch | `machine.run`, `machine.create` | `LocalBackend::launch` / `create_from_request`, through `LaunchRequest` |
| Guest (DevOnly) | `guest.proc.{start,list,signal,kill,stdin,wait}`, `guest.fs.{read,write,list,stat,mkdir,remove,rename}`, `guest.cp` | `mvm_client::guest` |
| Streams (DevOnly) | `guest.proc.stream.{open,next,close}` | `mvm_client::guest::wait_process`, on a reader thread |

`machine.run` builds a `LaunchRequest`, so every field is validated by the
same builder a Rust caller uses, and the machine is admitted under a signed,
chain-audited plan before it boots. A field the in-process launcher cannot
honour yet (a command override, guest environment) is refused there with its
own reason rather than dropped. Egress targets become the plan's egress
grant, which is what the host egress gate reads. The reply carries the
admitted plan id and the machine's fail-closed `build_mode`.

`machine.exec` is on the client trait so a remote backend can answer it; the
local backend does not, and the SDKs run guest commands through
`guest.proc.*` instead.

The guest methods are DevOnly agent verbs. The agent refuses them on a sealed
image, and that refusal reaches the binding as `BACKEND_ERROR` with the
agent's message. Byte payloads cross as base64.

### Streaming process output

One call returns once, so output that arrives over time is a handle and a
poll, never a callback into the binding:

1. `guest.proc.stream.open {id, token, timeout_secs?}` starts a reader that
   waits on the process and returns `{stream}`.
2. `guest.proc.stream.next {stream, wait_ms?}` returns the chunks that have
   arrived (`{events: [{stream: "stdout"|"stderr", data_b64}], done}`),
   waiting up to `wait_ms` (at most 30 s) for the first one. When the process
   ends, `done` is true, `outcome` says how, and the stream is gone. A failed
   wait is reported as an error on a later `next`, after any output it
   produced.
3. `guest.proc.stream.close {stream}` drops a stream early. Idempotent.

The reader's queue is bounded: a binding that stops polling stalls the reader
and, through it, the guest process's pipe, rather than growing the host
process. A wait already in flight on the guest agent cannot be withdrawn, so
a closed stream's reader lives until the process ends or its wait times out.
At most 256 streams are open at once.

Apart from stream readers, each call builds a single-threaded runtime and
drops it before returning, so nothing else the library starts outlives the
call.

## How the SDKs find the library

In order, the first that exists wins:

1. `MVM_HOSTLIB_PATH`, the library file itself. When set and missing, the
   SDK refuses rather than falling through. `mvmctl run --mode live` sets it
   to the library installed beside itself, so a script it runs drives the
   same build.
2. Packaged with the SDK: `mvm/_native/` inside the Python package, `native/`
   inside the npm package. Building wheels and npm packages that carry the
   library is follow-up work (issue #3724); the loaders already look there.
3. The installed bundle: beside `mvmctl` on `PATH`, and beside the real file
   when `PATH` holds a symlink. The binary is located, never run; the release
   bundle ships the CLI and the library side by side.

Otherwise the SDK raises a transport error naming all three. File names are
`libmvm_hostlib.dylib` on macOS and `libmvm_hostlib.so` on Linux.

## Running inside another program

Loaded into `python3` or `node`, the running executable is the interpreter.
Before its first call reaches the runtime, the library declares the process a
library embedder, so every path that would spawn `mvmctl` refuses. It also
declares its own directory, found through `dladdr`, as the directory holding
the per-VM helper binaries, which ship beside it.

## Tests

`cargo nextest run -p mvm-hostlib` covers the status mapping, every method
against `MockBackend` or `LocalBackend` driving the in-memory mock hypervisor
under an isolated `MVM_HOME`, the stream reader against a scripted guest,
unknown fields and methods, ABI negotiation, the entry points' buffer
handling, and the embedder path logic.
