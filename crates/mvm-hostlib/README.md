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
   fields. The ABI is 1.8.
3. It gets back a status and a JSON buffer, and releases the buffer with
   `mvm_hostlib_free`. Statuses 1 to 7 mirror `MvmError`, and the error body
   carries the same `code` and `retryable` every other programmatic surface
   reports.

The method registry (`src/registry.rs`) is the source of truth: `cargo xtask
gen-stubs` renders it into `schema/host-abi-v0.json` and
`schema/host-abi-methods-v0.json`, and from those into typed request/reply
classes and method tables for both SDKs.

### Methods

ABI 1.8 extends host-local maintenance with `manifest.remove`,
`manifest.prune`, `manifest.export_oci`, `storage.info`, `storage.gc`, and
`bundle.export`. Like manifest inspection, these are classified `ProdSafe`,
not guest-agent verbs. That classification is not a host privilege grant:
they run with the embedding process's host permissions, may invoke local
helpers, and are not a guest protocol. No runtime driver or private signing
key can be supplied over the ABI.

Requests and reports are the client's types. Removal takes `path` (cwd
discovery when omitted), `force=false`, and `manifest_file=false`, with no
interactive prompt. Prune requires `orphans=true` and defaults to
`dry_run=true`; unlike the CLI, programmatic callers must explicitly apply.
Storage inspection takes `mock=false`; collection takes `apply=false`,
`mock=false`, and `keep_prefix=[]` (matching volume names are retained).
An unavailable pool is represented in the report.

Both exports require `template` and the host output path `out`. Bundle export
also accepts `label`, a host `cmdline` file path, and optional `posture`
(`profile`, `allow_egress`, `allow_volumes`, `allow_unauthenticated`; all allow
flags default false). It signs with the host key, never returns key material,
and reports `path`, `size_bytes`, and `key_id`. OCI export reports `slot_hash`,
`path`, and `size_bytes`. Removal reports slot/source identity and whether the
source was deleted; prune/GC reports identify candidates and actual removals.
Client error chains and opaque report fields are preserved by both SDKs.

The same unreleased ABI 1.8 batch also exposes these host-local families:

| ABI methods | Python / TypeScript namespace | Contract |
|---|---|---|
| `artifact.inspect`, `artifact.validate`, `artifact.configure_firecracker` | `artifact` | Published ID or unique prefix; configuration writing is explicit. |
| `volume.list`, `volume.inspect`, `volume.create`, `volume.unlock`, `volume.lock`, `volume.mount`, `volume.detach`, `volume.attachments`, `volume.snapshot`, `volume.restore` | `volumes` | Client-owned encryption, profile admission, recovery and lease checks; mounting defaults read-only. |
| `workspace.review`, `workspace.apply`, `workspace.undo`, `workspace.redo` | `workspaces` | Registered workspaces only; no caller-assembled plan or global approval handle. |
| `audit.sessions.list`, `audit.sessions.show`, `audit.sessions.verify` | `audit.sessions` | Configured trust context and verified tenant chains; no raw unchecked lines or supplied keys. |
| `posture.inspect` | `posture` | Configured host only; no root or trust-key override. |

Plural `volumes` and `workspaces` distinguish host operations from authored
declarations. Existing `audit.emit` / `emit_batch` (`emitBatch` in TypeScript)
remain the in-guest host-service operations. Session queries are host-library
calls, not additional guest protocol verbs.

`workspace.review` can recover interrupted changes before reviewing: it is not
strictly read-only. Its reply contains `workspace`, `recoveries`, and `review`.
The review status is `unchanged`, `refused` (with safe path/action summary and
refusal reasons), or `ready` (with summary and fingerprint). Mandatory protected
defaults remain enabled; `protected_paths` only adds protection. Apply takes
`{workspace, expected_fingerprint, approved}`; the client freshly reviews,
compares the fingerprint, then immediately revalidates before mutation. The SDK
requires a fingerprint argument and defaults approval to false. Undo/redo also
default approval to false. Recovery reports remain visible on successful calls,
and completed recovery is included in error context if later work fails.

For example, explicit Python approval after reviewing the report:

```python
review = mvm.workspaces.review("worker", volume="source")
print(review["recoveries"], review["review"])
# Only after the application obtains approval for this exact review:
if review["review"]["status"] == "ready":
    result = mvm.workspaces.apply(
        "worker", review["review"]["fingerprint"],
        volume="source", approved=True,
    )
```

Volume creation uses MiB (`capacity_mib` / `capacityMib`) and starts locked.
Unlock delegates to the existing configured key provider; no key bytes cross
the ABI. A host-directory mount delegates to the shared host-snapshot operation,
including host encryption verification. Snapshot and restore retain the client's
locked-state, attached-volume and integrity refusals. Lifecycle reads can also
recover interrupted work.

Audit session queries default to tenant `local`. Date bounds are RFC 3339
strings validated by Rust. A missing chain returns an empty session list with
`ledger: null`, not a claim that a chain was verified. Verification verdicts,
including `NOT_FOUND`, `UNSEALED` and `MISMATCH`, are report data rather than SDK
exceptions. Operational failures retain their complete client error chain.

| Family | Methods | Answered by |
|---|---|---|
| Lifecycle | `machine.list`, `machine.inspect`, `machine.logs`, `machine.start`, `machine.stop`, `machine.rm`, `machine.exec`, `machine.pause`, `machine.resume`, `machine.reconfigure`, `machine.set_ttl`, `machine.inventory`, `backend.capabilities` | the `MvmClient` trait, and `mvm_client::inventory` |
| Launch | `machine.run`, `machine.create` | `LocalBackend::launch` / `create_from_request`, through `LaunchRequest` |
| Guest (DevOnly) | `guest.proc.{start,list,signal,kill,stdin,wait}`, `guest.fs.{read,write,list,stat,mkdir,remove,rename}`, `guest.cp` | `mvm_client::guest` |
| Streams (DevOnly) | `guest.proc.stream.{open,next,close}` | `mvm_client::guest::wait_process`, on a reader thread |
| Log streams | `machine.logs.stream.{open,next,close}` | `mvm_core::stream_client::open_vm_output` (what `mvmctl machine logs --follow` reads), on a reader thread |
| Functions | `entrypoint.call`, `session.{start,call,stop,info}` | `mvm_client::entrypoint`, the dispatch `mvmctl machine run --entrypoint` and `machine session` use |

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
