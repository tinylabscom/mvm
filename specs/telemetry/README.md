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

## Scope still open

This inventory does **not** yet discover library-only producer initialization,
language SDK adapters/dispatch scripts, guest init and kernel/early-boot sources,
arbitrary application instrumentation, or independently built non-workspace
artifacts. It cannot detect a new logging call inside an existing binary, a
missing startup witness, or a producer that is registered but never initialized.

W1 still requires those source classes, image/launcher and backend mappings,
the executable outside-span/detached/capture conformance harness, and repeated
hardware-qualified emission/memory/control-latency/fairness measurements.
W2–W7 then implement and certify the actual transport, capture, collection and
rollout. No live tracing or nonblocking guarantee follows from this gate passing.
