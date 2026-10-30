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
   fields. The ABI is 1.11.
3. It gets back a status and a JSON buffer, and releases the buffer with
   `mvm_hostlib_free`. Statuses 1 to 7 mirror `MvmError`, and the error body
   carries the same `code` and `retryable` every other programmatic surface
   reports. Status 12 is `RECOVERY_REQUIRED`, with `retryable: false` and
   required `details` containing only `machine_id`, `plan_id`, and `reason`
   strings from the typed error. Existing variants omit `details`.

The same-major negotiation accepts a requested minor no newer than the library.
Legacy-call negotiation is process-global; the last requesting binding never changes an
operation's status. Older bindings may expose status 12 as a generic failure
without typed details, but do not retry it. New bindings validate and expose
immutable typed recovery details. Those values are metadata, not ownership,
callbacks, or a recovery operation.

### Caller-owned contexts

ABI 1.9 adds `mvm_hostlib_context_create`, `context_call`, `context_inspect`,
`context_retry_stop`, `context_close`, and `context_checked_free` (each with
the `mvm_hostlib_` prefix). Their C declarations and pointer contracts are in
`include/mvm_hostlib.h`. Creation independently negotiates the requested
major/minor; the legacy global negotiation latch does not authorize a context.
Existing ordinary stateless methods, status values 0–12, and buffer layout
remain compatible.

The caller owns one serial context. Its invocation owns the actual output
observer before preparation, boot, callbacks, or JSON conversion. Concurrent
or reentrant use returns a conflict. The caller must exclude every concurrent
access during checked destruction, including threads about to begin a call;
a mutex cannot make a dangling pointer safe.

Inspection copies data and has no operational effects. Selectors are
`0=result`, `1=primary`, `2=flush`, `3=stop`, and `4=cleanup`; other values are
invalid. For error selectors, success with an empty buffer means no error in
that slot, **not** successful work or completion. A result can contain a
nonzero exit or typed entrypoint error even when transport succeeded. Native
raw output requires the original terminal event, flush acknowledgement,
original exit proof, and required kernel cleanup—not a caller status.

Explicit close attempts cleanup and retains the entire original group on
failure. Retry-stop acts only on its held original owner and remaining
cleanup, never by replaying work or reconnecting by name. Checked-free is
nonblocking, never stops, and accepts only an empty or successfully closed
context; failure leaves the pointer intact. Keep the shared-library handle
strongly held until checked-free succeeds. There is no unconditional
destructor stop. Abandoning a pointer, interpreter teardown, descriptor close,
or process exit does not establish native stop or preserve usable recovery.

An ordinary compatibility session has one start attempt per context. The
context arms its lifetime before dispatch or reply encoding, validates the
original unique session id, and accepts stop only for that exact binding.
Second starts, unrelated stops, and duplicate binding fields refuse before
dispatch. A missing, malformed, failed, or interrupted start leaves an
unknown-start lifetime; it cannot be closed, freed, or reported stopped just
because no usable id was returned. The original reply/error remains private.
This is ordinary session identity/lifetime retention, **not** native generation
custody or a native terminal proof. Legacy stateless methods remain separate.

The Python and TypeScript SDKs retain the same context and Session on start or
cleanup failure. Body and cleanup errors remain separately inspectable; neither
is suppressed or rendered into the aggregate error text. Successful TypeScript
`Session.id` remains a string; an unbound failed receiver refuses access rather
than supplying a placeholder id.
Every failed explicit `Session.retry_stop()` also carries that same receiver,
original primary error, and actual cleanup error. Its prior cleanup errors stay
held on the Session. The history has a finite 16-failure budget: exhausting it
refuses another cleanup **before effects**, without discarding earlier errors.
Keep the unresolved owner; budget exhaustion is not stop or recovery evidence.
Successful cleanup remains idempotent and does not redispatch stop.

Python asynchronous entry retains its original worker task before waiting.
Cancelling entry does not stop that thread. The raised `CancelledError` subclass
retains the original cancellation as `primary_error` and cause, plus `session`,
`recovery`, and the held worker. Keep that receiver and use
`await error.session.wait_started()` to await **only** its already-held worker,
then `error.session.retry_stop()` if the original binding became available.
Cancelling `wait_started()` also leaves the worker held and shielded. Pending
or unknown starts refuse cleanup/reentry; no retry starts a replacement worker
or guesses an id. Loop/interpreter/process exit is not successful cleanup.

Python asynchronous exit similarly owns and shields its actual cleanup worker.
If the exit wait is cancelled, its `CancelledError` subclass keeps the original
body/primary error, exact cancellation and cause, Session/context, and worker;
the Session retains the cancellation before surfacing it. Subsequent busy or
failed retries carry the same receiver and retained cancellation references.
Use `await error.session.wait_cleanup()` to await **only that held worker**,
then explicit no-argument `retry_stop()` if its operation failed. This wait
never retries cleanup or starts another worker. Its historical worker error
remains observable even if a later explicit retry succeeds.

The finite 16-slot history reserves a worker-outcome slot and a waiter-cancel
slot atomically **before** scheduling asynchronous cleanup. Further pending
waits reserve their own cancellation slot before awaiting. Start waits share
the same bounded machinery. Metadata locks cover only bookkeeping, not FFI,
awaits, or user code; a separate operation lock serializes actual cleanup.
Unused reservations are released, never actual errors. Without capacity a new
await or effect refuses while retaining all original objects. Keep the owning
Session; do not cancel its worker task directly. Cancelling a waiter, a task
completion flag, or interpreter exit is not native stop proof.

Managed native positive entry remains unsupported before launch while
immutable verified rootfs/verity custody is unavailable. A refusal without a
held owner is nonretryable unsupported, not `RECOVERY_REQUIRED`. Repeated
native sessions, second-transport stdin, detached ownership, and CLI cases
without a retained recovery lifetime remain unavailable. Context ownership
does not waive these restrictions or supply a durable handoff.

The method registry (`src/registry.rs`) is the source of truth: `cargo xtask
gen-stubs` renders it into `schema/host-abi-v0.json` and
`schema/host-abi-methods-v0.json`, and from those into typed request/reply
classes and method tables for both SDKs.

### Methods

| Family | Methods | Answered by |
|---|---|---|
| Lifecycle | `machine.list`, `machine.inspect`, `machine.logs`, `machine.start`, `machine.stop`, `machine.rm`, `machine.exec`, `machine.pause`, `machine.resume`, `machine.reconfigure`, `machine.set_ttl`, `machine.inventory`, `backend.capabilities` | the `MvmClient` trait, and `mvm_client::inventory` |
| Launch | `machine.run`, `machine.create` | `LocalBackend::launch` / `create_from_request`, through `LaunchRequest` |
| Guest (DevOnly) | `guest.proc.{start,list,signal,kill,stdin,wait}`, `guest.fs.{read,write,list,stat,mkdir,remove,rename}`, `guest.cp` | `mvm_client::guest` |
| Streams (DevOnly) | `guest.proc.stream.{open,next,close}` | `mvm_client::guest::wait_process`, on a reader thread |
| Log streams | `machine.logs.stream.{open,next,close}` | `mvm_core::stream_client::open_vm_output` (what `mvmctl machine logs --follow` reads), on a reader thread |
| Functions | `entrypoint.call`, `session.{start,call,stop,info}` | `mvm_client::entrypoint`, the dispatch `mvmctl machine run --entrypoint` and `machine session` use |
| Host identity | `attestation.export`, `attestation.verify`, `attestation.status` | bounded `mvm_client::attestation` facade, without machine services |
| Host-local checkpoints | `checkpoint.list`, `checkpoint.remove` | `mvm_client::checkpoint::Checkpoints`, without machine services |
| Image revocations | `image_revocations.update`, `image_revocations.status` | canonical signed revocation store through `mvm_client::image_admin::revocations` |

ABI 1.10 adds `checkpoint.list`, a strict empty-object request returning the
complete canonical `CheckpointMeta` array in ID order, including runtime,
snapshot, grant, session, protection and audit metadata when present. Persisted
serialization and content-address semantics are unchanged; omitted legacy
fields stay omitted. Missing catalogs are empty; malformed or mismatched
metadata, unsafe metadata paths, non-regular metadata files and metadata over
16 MiB refuse the whole operation. Staging and non-checkpoint entries are
ignored. Listing does not open content or verify lineage and grants no restore
authority. The method is `ProdSafe` data access, not authentication or a role
grant, and needs negotiation but no machine service construction.

ABI 1.11 adds `checkpoint.remove`, accepting only `{"id":"checkpoint-id"}` and
returning `{}` after the shared client's guarded removal. Missing directories are
already removed; existing incomplete/unreadable metadata and failed pin or
dependency reads refuse deletion. Session pins and dependent
checkpoints return nonretryable `CONFLICT`; invalid IDs return `INVALID_SPEC`;
read failures return `BACKEND_ERROR` without parser payloads. A visible sibling
directory without metadata refuses removal rather than establishing no dependents.
Read-only listing keeps its incomplete-entry filter. There is no force or root
override, VM stop, guest-agent, MCP, or remote route. This remains host-local
administration under the caller's existing filesystem authority, not a new grant.
The guards are preflight checks, not an atomic transaction with concurrent pin,
lineage or path changes.

These host-local methods are `ProdSafe` data/admin operations under the
registry's guest-tier classification, not authentication or a role grant. They
run after ABI negotiation and before machine service construction. Empty
operations require literal `{}`. Verification requires explicit
`{"kind":"self_identity"}` or
`{"kind":"public_key_file","path":"/trusted/host.pub"}` trust;
embedded keys, inline key bytes, issuer, storage-root and policy overrides are
not accepted. New host-local requests reject duplicate or unknown fields and
return generic parse diagnostics rather than echoing payload bytes.

Export/status and self-identity verification may initialize the local identity.
The v0 report has a zero boot measurement and no hardware measurement: a valid
signature is not measured-boot or native readiness evidence. Report envelope
bytes are JSON integer arrays (0–255), not base64. Status paths describe storage,
not keys or capabilities. Revocation update/status may initialize the private
store directory and lock even on refusal or missing state. That infrastructure
creation is not an applied feed/checkpoint advance. No acquisition, recovery,
audit-prune, or transcript-export route is added.

`machine.pause`, `machine.resume` and `machine.set_ttl` are recorded in the
local audit log by `LocalBackend` itself (`WorkloadSleep`, `WorkloadWake`,
`VmTtlSet`), so a call through the library leaves the same entry as the
matching `mvmctl` verb. `machine.reconfigure` changes CPU count and memory;
the local backend refuses a network policy change it could not enforce.

`machine.run` builds a `LaunchRequest`, so every field is validated by the
same builder a Rust caller uses, and the machine is admitted under a signed,
chain-audited plan before it boots. A persistent machine boots through the
same start the CLI's `machine run -d` and `machine start` use. Egress targets
become the plan's egress grant, which is what the host egress gate reads. The
reply carries the admitted plan id and the machine's fail-closed
`build_mode`.

A launch boots exactly one source:

- `image`: an OCI reference, a rootfs path, or `flake:<ref>#<attr>`.
- `template`: a template built on this host, named by the name its image was
  built under (the `name` its flake gave `mkGuest`). A name no built slot
  carries, or one several do, is refused with how to build it or which
  manifests compete. Boots as a persistent machine.
- `manifest`: a manifest file, the directory holding one, or a built slot's
  64-character address. Boots as a persistent machine.

Nothing is built on a launch: a template or manifest that was never built is
refused rather than built behind the caller's back.

`command` starts once the machine is up, with `env` and `cwd`, and the reply's
`process` is its token for `guest.proc.*`. `env` passes the host's
environment denylist, so a loader, shell or credential variable is refused
before anything boots, and `env` or `cwd` without a `command` is refused
rather than dropped. Starting the command is the guest agent's process start,
a DevOnly verb, so a sealed image refuses it; a machine that booted but whose
command did not start is stopped, and the launch fails. `machine.create`
takes no command: a definition records what boots, not what runs on it.

`entrypoint.call` boots a transient microVM from the built slot that serves a
`workload` (found by the name its image was built under) or a `manifest`,
dispatches one entrypoint call with `payload_b64` as its input, and tears the
machine down: `{exit_code, stdout_b64, stderr_b64, output_truncated, error?}`,
where `error` is the `{kind, error_id, message}` envelope the guest wrote when
the function raised. `session.start` keeps one such machine warm for
`session.call` until `session.stop` or its idle timeout; calls on one session
are serialised in this process. Admission is the one the CLI uses for the same
call, so the plan, the verb grant and the audit entries match. A payload over
one agent frame travels on the streaming input plane for `entrypoint.call`
and is refused as `REJECTED` for `session.call`; nothing is truncated.

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

`machine.logs.stream.{open,next,close}` follow a machine's captured output the
same way. `open {id, follow?, tail_lines?, streams?}` replays the last
`tail_lines` records, then keeps reading as the machine writes when `follow`
is true (the default); `streams` picks among `stdout`, `stderr`, `trace` and
`frame`. `next` is the process stream's `next`, and a log stream's final batch
carries no `outcome`. A machine with no captured output is `NOT_FOUND`. A
handle belongs to its family: a process stream's id means nothing to the log
methods, and the other way round.

Apart from stream readers, each call builds a single-threaded runtime and
drops it before returning, so nothing else the library starts outlives the
call.

## How the SDKs find the library

In order, the first that exists wins:

1. `MVM_HOSTLIB_PATH`, the library file itself. When set and missing, the
   SDK refuses rather than falling through. `mvmctl run --mode live` sets it
   to the library installed beside itself, so a script it runs drives the
   same build.
2. Packaged with the SDK: `mvm/_native/` inside the Python wheel; for npm,
   `native/` under the package root and then the per-host platform package
   (`@runmvm/mvm-<os>-<cpu>[-gnu|-musl]`) that `@runmvm/mvm` installs as an
   optional dependency. Linux wheels and packages are built against glibc
   2.17 (tagged `manylinux2014`) and against dynamic musl (`musllinux_1_2`),
   for x86_64 and aarch64.
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
