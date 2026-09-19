# Telemetry producer inventory

Backing: shipped-source
Validation: check-telemetry-inventory

`binaries.toml` is the first, deliberately narrow layer of the producer inventory
for [every-VM host-mediated tracing](../plans/2026-09-17-host-mediated-telemetry.md).
It is an inventory of workspace Rust **binary targets**, not a certification of
running subscribers, exported records, image membership, or backend coverage.

Run `cargo run -p xtask -- check-telemetry-inventory`. CI's `check-all` includes
the same gate. Discovery uses offline, locked, no-dependency Cargo metadata, not
a second implementation of Cargo's implicit target or workspace rules. No binary
is executed and no VM is booted. Required-feature targets are inventoried even
when the current host cannot run them or their features are disabled.

## Entry contract

Each target has exactly one package/name entry, a workspace-relative source path,
and its required-feature set. Adding or removing an explicit or implicit binary,
moving its source, or changing its feature requirements requires inventory review.
Duplicate entries, unknown fields and variants, empty evidence, stale paths, and
missing entrypoint anchors are errors. Entrypoint text is a navigation anchor,
not evidence that a subscriber is installed or that a function was exercised.

`runtime-gap` records the runtime owner, host/workload-guest/builder-guest role,
required signal families, startup inspection anchor, missing capture contract,
and the **required future** runtime witness. Signals describe what an adapter
must handle when emitted; they do not claim every helper emits every signal.
The witness field is a requirement, not a test name or a completed test result.
There is deliberately no `covered` variant: adding one requires an independently
validated runtime witness model, not changing a status string.
Future live expectations must be activation-aware: an optional helper that is
not launched is not a missing producer. Image/launcher policy determines which
producers must start; every producer that does start needs its capture witness.

`stdio` means workload output and diagnostic streams, **not** control-protocol
pipes or command return values. The extension provider's MVEX stdout, the runner's
function-return channel, and CLI result output must not be swept into telemetry.
Their diagnostics remain in scope. Detailed stream adapters and source-side
redaction belong in the remaining initialization/launcher inventory and capture
work, before any live collection is enabled.

Guest roles require authenticated encrypted typed vsock delivery to the host;
host roles require host-local collection and authoritative VM/generation
correlation where applicable. Neither role is currently certified by this gate.
The actual backend endpoint/service binding is still implementation work.
Host-local utilities not associated with one VM must not invent a VM identity.

`non-runtime` requires an explicit reason and category (generator, test fixture,
developer tool, or standalone artifact tool). These are exclusions from this
VM-runtime inventory, not claims that their output is captured or harmless.
Review a classification again if a tool becomes part of a runtime image/launcher.

## Source inventory (`sources.toml`)

`sources.toml` extends discovery past binary targets, validated by the same
gate. Four sections, all fail-closed on drift:

- `subscriber_init` — every Rust site that installs a subscriber or other
  process-global diagnostic state. A scan over non-test workspace sources
  (install verbs such as `set_global_default`, logger/panic-hook installs, and
  `tracing_subscriber` builders that `init`) fails the gate when a new site
  appears unregistered. Regions after `#[cfg(test)]` and `tests`/`fuzz`/
  `benches`/`examples` directories are exempt.
- `script_source` — non-Rust producer surfaces: every dispatch wrapper under
  `nix/wrappers/`, and every Python/TypeScript SDK module whose text writes to
  an output or diagnostic stream. New wrappers and newly-emitting SDK modules
  fail the gate until classified.
- `launch_edge` — which launcher starts which guest/builder producer, with an
  activation policy (`always`, `conditional` + named condition, `on-demand`,
  `mediated`, `legacy`, `seed`, `unwired`). Every guest/builder runtime gap in
  `binaries.toml` must carry at least one edge; an edge naming an unknown
  producer is an error. Activation is what makes future live expectations
  activation-aware: an optional helper that is not launched is not a missing
  producer, and `unwired` records a binary no current image launches at all.
- `backend_endpoint` — the telemetry-service provisioning anchors per backend
  (firecracker, libkrun, hvf, qemu, apple-container, wasm, plus the shared
  seam). Every backend must be covered; the wasm row records the honest
  distinction that it has no vsock and needs a separate host adapter.

The startup-witness *model* lives in `mvm-core`'s telemetry protocol module as
an activation-aware ledger (`WitnessLedger`): required producers that never
report startup, degraded or unavailable coverage, and unregistered producers
become deterministic findings, bounded in count. Nothing constructs it at
runtime yet — collector integration is later-workstream work, and neither the
ledger nor any inventory entry certifies runtime capture.

## Scope still open

This inventory does **not** discover arbitrary application instrumentation,
independently built non-workspace artifacts, or a new logging *call* inside an
already-registered file; the subscriber scan sees installation sites, not
emissions. No startup witness is checked at runtime: the ledger is a model
without a collector, and a producer that is registered but never initialized
is still invisible until one exists.

W1 still requires the executable outside-span/detached/capture conformance
harness and repeated hardware-qualified emission/memory/control-latency/
fairness measurements. W2–W7 then implement and certify the actual transport,
capture, collection and rollout. No live tracing or nonblocking guarantee
follows from these gates passing.
