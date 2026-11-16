# mvm-client

`mvm-client` is the stable machine-control facade for Rust consumers. One
surface covers local in-process machines, remote fleet gateways, deterministic
mocks, workload output streams, volumes, secrets, readiness, and audit records.

## Who uses it

`mvm-cli` uses the facade for commands and its private MCP adapter.
External Rust automation can depend on
this crate instead of the full `mvmctl` facade. `mvm-conformance` tests the
contract. The trait and common DTOs are defined in feature-gated `mvm-core` so
`mvm-sdk` can share them without creating a dependency cycle.

## How it works

`MvmClient` defines backend-neutral operations and capability discovery.
`connect` parses a target and selects an implementation:

- `LocalBackend` invokes the local build, runtime, host daemon, and filesystem
  layers in-process.
- `GatewayBackend`, enabled by `remote`, carries the same DTOs over the remote
  gateway transport.
- `MockBackend` records deterministic requests for tests and embedders.

Before an operation, callers can inspect `ClientOperationCapabilities` instead
of discovering unsupported behavior after mutation. Launch helpers normalize
requests and bind grants, registration, and readiness records. Stream helpers
read captured workload output; the optional tracing bridge republishes it into
a consumer's tracing subscriber.

Local machine list and inspect return a backend error if the name registry cannot
be read or parsed, rather than silently omitting stopped entries or metadata.
A missing registry remains a valid empty initial registry. Bulk-stop target
discovery stays best-effort and excludes registry-only entries.

Detached boot commands use the same canonical
`mvm_hostd::workload_env::workload_egress_env` projection as entrypoint dispatch,
read after guest-agent readiness. Machine names are validated before readiness
probes or per-machine state reads. The resulting process request carries the
runtime-provisioned proxy variables and, when present, egress CA paths and
credential placeholders. Non-runtime caller environment is preserved. An
identical caller value is accepted; replacing a provisioned value is refused
by variable name without reporting either value. Without provisioned egress
environment, caller configuration is unchanged and an empty environment stays
empty.

Plain endpoints use the existing authenticated endpoint-session state as well
as the legacy egress marker to select the canonical proxy environment. An
endpoint PID alone is insufficient. Egress CA paths are merged after proxy
selection, so CA-only state cannot suppress the proxy variables.

This delivers canonical environment to the guest process request; it is not
additional admission, network enforcement, workload readiness, or protected
output evidence. Boot commands remain DevOnly, sealed guests still refuse
them, and the existing environment denylist re-admits no denied variables.

### App-session process stdout/stderr

`guest::ProcessOutputs` owns a bounded observation of an existing process token.
It uses the same capability-checked, authenticated `ProcWait` operation as
`guest::wait_process`; it does not start a command, widen its grant, create a
capture producer or write transcript history. One reader remains owned through
process termination even when its UI is hidden. Following the same machine/token
again reuses that reader, while changing the token retires the previous local
observation without signalling the guest process.

Each reader retains the newest 400 chunks / 1 MiB with source-local sequence,
separate stdout/stderr, dropped-record/byte counters and explicit terminal or
unavailable state. Debug output omits payload bytes. There are at most 32
tracked machines per service; terminal windows can be evicted under pressure,
and a full active set refuses another observation before opening its connection.
Opening/authentication does not hold the service registry lock. Local retirement
shuts down the reader's socket and bounds its worker join to one second; an
unconfirmed join is not reported as confirmed on a later close.

The guest process API consumes output buffers. Competing readers, an evicted
window or a disconnected app cannot recover bytes already consumed. Closing the
local socket does not withdraw an already-dispatched guest wait and never sends
a process-kill or VM-stop request. A transport failure leaves completion unknown
and withholds its old display window. This is app-session observation, not
protected history, original-native-owner custody or off-host provenance.

`input_journal` owns the encrypted machine-exec journal and its per-machine
lock for execution, checkpoint cursors, and replay. An absent journal is an
empty history; an unreadable journal or dangling journal symlink is an error.
An unterminated final record also refuses `machine exec`, checkpoint cursors and
replay; it is preserved for recovery rather than truncated or appended to.
Callers hold the same lock through execution and checkpoint capture. Read entries
contain decrypted arguments and must be handled as sensitive; their `Debug`
representation redacts those arguments. The module adds no guest, MCP, SDK, or
remote operation. It does not journal or block separate interactive shell paths.

`checkpoint::Checkpoints::verify_lineage` owns signed-chain metadata ancestry
verification for the CLI and host library. It uses the configured host's audit
anchor, even with an explicit catalog root. It does not hash snapshot blobs,
check runtime compatibility or authorize a restore. Loading the existing anchor
may initialize the host identity when an audit directory exists.

`checkpoint::Checkpoints::remove` owns host-local checkpoint removal for the CLI
and host library. It refuses incomplete/unreadable metadata, session pins,
dependent checkpoints, and failed guard reads. An absent checkpoint directory is
already removed. Removal also refuses any visible checkpoint directory lacking
metadata: it cannot establish that the directory is not a dependent. Read-only
listing still ignores incomplete directories and staging. These preflight checks
do not serialize concurrent pin, lineage,
or path changes with deletion; they do not grant guest, MCP, or remote authority.

## Prepared OCI reuse

`prepared_image::select(reference, &PreparedImageContext { backend })` selects
an already prepared **development registry OCI** image from the same cache and
resolver used by `mvmctl image pull` and CLI prepared resolution. Supply the
explicit backend that will launch it; MVM derives and checks the actual Linux
platform and guest-runtime identity. The resource profile is separate from
image trust. No public production prepared-selection mode is added.
The platform records MVM's host target, including its architecture variant.
The existing OCI config check verifies OS and architecture; this is not a new
image-variant or index-to-child-manifest verification proof.

Pass the returned untrusted `PreparedOciSelection` to
`LaunchRequest::builder_for(LifecycleMode::Persistent, LaunchSource::PreparedImage { selection })`.
MVM revalidates it at launch rather than trusting the preview. Persistent
definitions retain the expectation without an ordinary image source fallback;
every later Start repeats validation and admission. A changed tag, rootfs,
runtime, platform, backend or semantic guest sidecar refuses, rather than
silently selecting different bytes. Incidental build timestamps are excluded.
Ordinary OCI clients and explicit materialization APIs keep their existing
acquisition behavior.

Prepared-only refuses missing or corrupt preparation, even when cached layers
could repair it. `PreparedImageError` carries a stable `kind`, `code()` and
explicit `remedy()`, preserved on launch as `MvmError::PreparedImage`.
Kernel and prepared guest-runtime checks remain independent. The `prepared_image`
selection/launch path rejects pending or unidentified runtime cache markers as
measured identity. That path never pulls, bootstraps, unpacks, injects a runtime,
materializes, reseals or invokes an online verifier. Adoption of an already-built matching variant may
update the existing cache index. Force replacement and external signed plans
are not supported by this additive mode. Prepared transient requests are refused
before resolution; ordinary transient clients are unchanged.

The manifest/config digests and measured rootfs SHA256 are distinct identities.
The first measurement of an existing development preparation is not proof of
its historical OCI-to-rootfs derivation or publisher authority. Admission binds
the actual selected bytes and development-qualified provenance, not cached
authorization. Launch acceptance is not guest readiness, a workload result,
protected recording, or original-owner quiescence.

`cli_image` is an explicitly delimited **public workspace compatibility
surface** for existing CLI delegation, not a privacy or security boundary.
Its explicit operations can acquire/materialize images, invoke production
verification, update indexes and remove cached images. Documentation hiding
does not restrict access. Embedder prepared launches use `prepared_image`
instead; neither compatibility reports nor caller-authored expected DTOs are
accepted as verified provenance by the prepared admission path.

## Main modules

| Module | Responsibility |
|---|---|
| `connect` | Target parsing and backend selection |
| `local` | In-process local implementation |
| `launch` / `boot` | Request validation and machine startup |
| `prepared_image` | Cache-only development OCI selection and typed refusals |
| `cli_image` | Public workspace compatibility for existing CLI effects; not the embedder prepared-launch API |
| `inventory` / `registration` | Machine discovery and durable identity |
| `checkpoint` | Host-local catalog access and guarded checkpoint removal |
| `input_journal` | Locked encrypted execution input and replay cursors |
| `stream` | Captured output access |
| `volume` | Volume lifecycle, leases, and snapshots |
| `secret` | Secret-reference inputs and audit records |
| `bundle` | Sealing built artifacts into a signed `.mvmpkg`, under the host key or a caller's |
| `builder_bundle` | Building a flake in a builder VM and sealing the result into a `.mvmpkg` |
| `audit` / `grants` / `readiness` | Evidence and lifecycle state |

## Features

The default feature set is local-only. `remote` enables the gateway backend,
`tracing-bridge` enables stream-to-tracing adaptation, and `test-support`
exposes runtime fixtures.

## Developing

Run `cargo test -p mvm-client`. New operations need local, remote DTO, mock,
capability-discovery, and unsupported-operation coverage. Secret-related errors
and debug output must never contain resolved secret material.
