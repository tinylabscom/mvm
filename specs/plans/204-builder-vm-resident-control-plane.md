# Plan 204 — Builder VM resident control plane

**Status:** In progress — WS-A protocol wire types + version negotiation landed; daemon skeleton, image wiring, and host client remain
**Sprint:** 56 / product-DX follow-up
**ADR:** [ADR-089](../adrs/089-builder-vm-resident-control-plane.md)
**Depends on:** Plan 199, Plan 200, ADR-046, ADR-057, ADR-071

## Goal

Make the long-term builder architecture match the desired UX and trust boundary:

- users install and run one host CLI;
- normal use does not require host Nix;
- Nix and Linux-only work execute inside the project builder VM;
- the builder VM exposes a resident typed vsock service, not a product-facing
  shell;
- microVM guest images do not install `mvmctl` or the builder daemon.

The target product shape is:

```text
user / SDK
  -> mvmctl on the host
    -> typed BuilderRequest over vsock
      -> mvm-builderd inside the builder VM
        -> Nix / Linux-only build or eval
```

`mvmctl` remains the host control plane. `mvm-builderd` becomes the builder
execution plane.

## Non-goals

- Do not require host Nix for normal builds or runs.
- Do not expose the builder VM as a second user-facing CLI.
- Do not put `mvmctl` or `mvm-builderd` inside workload guest images.
- Do not make generic remote shell execution the stable builder API.
- Do not change the `mkGuest` user image API.
- Do not move microVM runtime commands out of the approved builder boundary.

## Design

### 1. Protocol-first builder service

Add a small protocol crate/module for builder requests and responses.

Initial request families:

- `Handshake`
- `Probe`
- `FlakeCheck`
- `BuildGuestImage`
- `BuildHostTool`
- `PrefetchSource`
- `QueryStorePath`
- `CancelJob`

Initial response families:

- `Accepted`
- `Progress`
- `LogChunk`
- `ArtifactReady`
- `StorePathReady`
- `Failed`
- `Cancelled`

Every request has a schema version and an operation id. Every result is tied
back to the operation id. Error responses carry a stable category so `mvmctl`
can show actionable messages without parsing arbitrary stderr.

### 2. Resident `mvm-builderd`

Add a builder-VM daemon that:

- starts during builder VM boot;
- listens on a dedicated vsock port;
- owns Nix invocations and Linux-only tool execution;
- streams progress/log events;
- writes artifacts to mounted output paths only after validating the request;
- exposes a health/probe endpoint for `mvmctl doctor`.

The daemon is internal to the builder VM. Users do not call it directly.

### 3. Host-side client in `mvmctl`

Add a host-side builder client that:

- starts or reuses the builder VM;
- waits for `mvm-builderd` readiness;
- sends typed requests;
- converts progress events into the existing CLI progress UI;
- preserves existing output locations and cache semantics;
- refuses to fall back to host Nix unless the user explicitly invoked a
  source-checkout Nix install path outside `mvmctl`.

### 4. Compatibility adapter

Keep the existing shell-job mechanism as an internal compatibility adapter while
typed operations land.

Rules:

- new product paths use typed requests when the daemon supports them;
- unsupported typed requests can temporarily route to the compatibility adapter
  only from host-owned code, not from user-supplied shell;
- every compatibility fallback emits a structured diagnostic so the remaining
  shell surface is visible and shrinkable.

### 5. No guest image dependency

Add structural tests that prove:

- `mkGuest` images do not include `mvmctl`; **(landed)**
- `mkGuest` images do not include `mvm-builderd`; **(landed)**
- host packages are separate from guest image outputs;
- the builder daemon package is only part of the builder VM image.

Landed: `xtask check-guest-images-no-builder-tools` is a comment-stripping
source-grep gate over `nix/lib/mk-guest.nix` (the workload + dev-shell
image builder) asserting it bakes neither `mvmctl` nor `mvm-builderd`,
wired into the `ci.yml` Lint job beside `check-guest-agent-in-all-images`.
Source-grep not a build, mirroring the sibling agent gate. `mvm-host-vm-init`
is deliberately excluded — the builder-VM image injects it through mkGuest's
generic `extraFiles` mechanism, a separate intentional consumer. The
affirmative "builder daemon package is only part of the builder VM image"
arm lands with the daemon's image baking (boot-gated).

## Workstreams

### A. Protocol and daemon skeleton

- [x] Add builder request/response wire types with serde roundtrip tests.
      `mvm_build::builderd_protocol` — typed `BuilderRequest`
      (`Handshake`/`Probe`/`FlakeCheck`/`BuildGuestImage`/`BuildHostTool`/
      `PrefetchSource`/`QueryStorePath`/`CancelJob`) + `BuilderResponse`
      (`Accepted`/`Progress`/`LogChunk`/`ArtifactReady`/`StorePathReady`/
      `Completed`/`Failed`/`Cancelled` — `Completed` added in WS-C for ops
      that pass without an artifact), an `OperationId` newtype, and a stable
      `FailureCategory`. Externally-tagged snake_case + `deny_unknown_fields`
      on every variant (fail-closed against an unknown peer field/kind),
      reusing the existing 256 KiB vsock framing. Roundtrip, kind-tag
      stability, and unknown-field/unknown-kind rejection tests (26 tests).
- [x] Add protocol-version negotiation and unsupported-version refusal tests.
      `PROTOCOL_VERSION` + `negotiate()` (exact-match v1, fail-closed) +
      `handshake_reply()` returning `Failed`/`FailureCategory::Version` on an
      unsupported version.
- [~] Add `mvm-builderd` skeleton with `Handshake` and `Probe`.
      Daemon request-handling **core** landed in the library
      (`mvm_build::builderd`): stateless `dispatch()` answers `Handshake`
      (version-negotiated), `Probe` (echoes the op), and `CancelJob` (no-op
      ack); recognized-but-unimplemented build ops fail closed with
      `FailureCategory::Unsupported`. `serve_connection()` runs the
      framed read-dispatch-write loop until clean EOF. Driven from
      `UnixStream` pairs in tests (9 tests) without booting the VM. The
      `[[bin]] mvm-builderd` entrypoint + Linux AF_VSOCK listener landed in
      the boot-wiring slice below.
- [~] Add builder-VM image wiring so the daemon starts on boot (also lands
      the `mvm-builderd` bin entrypoint + AF_VSOCK listener over
      `serve_connection_with_executor`).
      **Code landed; one live boot-validation step pending on-box.**
      `crates/mvm-build/src/bin/mvm-builderd.rs` `#[path]`-includes the
      daemon modules (not `use mvm_build`, so it cross-compiles to static
      `aarch64-unknown-linux-musl` like every builder bin) and runs a
      Linux AF_VSOCK accept loop on `BUILDERD_CONTROL_PORT` (21473),
      serving each connection via `serve_connection_with_executor(&CommandExecutor)`.
      Embedded into the builder/dev VM rootfs at `/sbin/mvm-builderd` via
      `HOST_BINARIES` (`host_binaries/manifest.rs` + `nix/lib/mvm-host-binaries.nix`,
      `check-mvm-host-binaries-sync` green). `mvm-host-vm-init` (PID 1)
      `spawn_builderd()`s it at dispatch-loop entry (non-fatal). The
      persistent libkrun + Vz builder launchers register vsock port 21473
      so the host reaches it at `<vm_state_dir>/vsock-21473.sock` — the
      exact path `doctor` and `BuilderdClient` already use. All of this is
      CI-compiled (incl. the musl zigbuild via embedding); the remaining
      step is a live `mvmctl dev up` → `doctor: builder daemon ready` →
      typed `FlakeCheck` on the builder box. The lifecycle owner (routing
      real `mvmctl` builds through the client instead of the legacy
      channel) is WS-D, still open.
- [x] Add `mvmctl doctor` visibility for builder daemon readiness.
      Host-side readiness probe landed in `mvm_build::builderd`
      (`probe_builderd_readiness` over a `Handshake` →
      `BuilderdReadiness::{Ready,VersionMismatch,NotRunning,Unreachable}`,
      `readiness_summary`, `builderd_control_socket_path` matching the
      `persistent_builder::dispatch_socket_path` convention on the new
      `BUILDERD_CONTROL_PORT` 21473). `mvmctl doctor` gained an
      informational `builder daemon` platform check that scans the
      persistent builder-VM `vms/` root and probes each present control
      socket (always `ok` — absence is the normal "builder VM down" state).
      Probe + summary + doctor-scan tested with a real `UnixListener`
      driving `serve_connection` end-to-end (no VM boot). Doubles as the
      first WS-B host-client leg.

### B. Host client and lifecycle

- [x] Add a host-side builder client that connects over vsock.
      `mvm_build::builderd_client::BuilderdClient` — `connect()` (over the
      shared `connect_with_timeout` + `perform_handshake`, factored out of
      the readiness probe), `run_operation()` (one operation per connection:
      write the request, stream `OperationEvent::{Progress,Log}` to a
      caller sink, return a typed `OperationOutcome::{Artifact,StorePath,
      Failed,Cancelled}`), and `request_cancel()`. Integration-tested end
      to end against the real `serve_connection` daemon core plus
      `UnixStream`-pair tests for every streamed/terminal/error path
      (11 tests).
- [x] Thread operation ids through progress/log rendering.
      The client correlates every response frame to the in-flight
      request's `OperationId` and rejects a mismatched or out-of-band
      frame as `BuilderdClientError::Protocol`; `OperationEvent`s handed to
      the sink are already correlated, so the renderer keys on one op.
- [x] Add timeout, cancellation, and daemon-not-ready error handling.
      Typed `BuilderdClientError::{NotReady,VersionMismatch,Transport,
      Timeout,Protocol}`; a read timeout before the terminal frame maps to
      `Timeout`, a missing/refused socket to `NotReady`, a version refusal
      to `VersionMismatch`. `request_cancel()` writes a `CancelJob` and the
      `Cancelled` terminal flows back through `run_operation`. (Full
      mid-flight async cancellation from a second handle is a transport
      concern that lands with the listener.)
- [ ] Ensure `MVM_DATA_DIR` / cache-dir isolation stays per worktree.
- [ ] Keep all git operations host-side and outside the builder VM.
      (Client is transport-only and starts/stops no VM; the lifecycle
      owner connects it to an already-running socket. Asserted by the
      module contract; revisit when the lifecycle owner lands.)

### C. Typed Nix operations

- [~] Implement `FlakeCheck` for the `nix/` flake.
      Host-testable core landed in `mvm_build::builderd`: `flake_check_argv`
      (`nix flake check --no-build path:<flake>`), `flake_check_outcome`
      classification (clean exit → new `BuilderResponse::Completed`
      terminal; non-zero → `FailureCategory::NixEval`; executor/spawn error
      → retryable `Internal`), an injectable `OpExecutor` seam
      (`CommandExecutor` for the daemon, fakes for tests),
      `dispatch_flake_check` / `dispatch_with_executor`, and
      `serve_connection_with_executor` so the daemon serve loop runs it.
      Fully unit-tested (argv shape, every classification arm, routing,
      over-the-wire serve). The actual `nix` execution inside the builder
      VM is exercised when the daemon bin + boot wiring land on-box.
- [~] Implement `BuildGuestImage`.
      Host-testable core: `nix_build_argv` (`nix build <ref>#<attr> --no-link
      --print-out-paths`), `nix_build_outcome` (clean exit + out-path →
      `ArtifactReady{artifact_path,store_path}`; non-zero → `NixBuild`;
      no out-path → `NixBuild`; spawn error → retryable `Internal`),
      `dispatch_nix_build`, wired into `dispatch_with_executor` +
      `serve_connection_with_executor` (over-the-wire test). `OpExecResult`
      grew a `stdout` field so the store path is read back. The cache
      short-circuit on `fingerprint` is a later addition (handler always
      builds). Live in-VM `nix build` is boot-gated.
- [~] Implement `BuildHostTool` for source-built host packages.
      Shares `dispatch_nix_build` with `BuildGuestImage` (distinct request
      variant for audit separation); same `ArtifactReady` contract, tested.
- [~] Implement `PrefetchSource` / `QueryStorePath` if needed to remove ad hoc
      host-side probing.
      `prefetch_source_argv` (`nix flake prefetch --json`) +
      `dispatch_prefetch_source` (parses `storePath` from JSON →
      `StorePathReady{already_present:false}`; non-zero → retryable `Fetch`);
      `query_store_path_argv` (`nix path-info`) + `dispatch_query_store_path`
      (always `StorePathReady`, `already_present = exit==0`; spawn error →
      `Internal`). All host-tested. Live `nix` exec is boot-gated.
- [ ] Add tests proving normal `mvmctl` flows do not require host Nix.

### D. Compatibility shrink

- [ ] Route current shell-job builder calls through a single adapter module.
- [ ] Emit a diagnostic when the adapter is used.
- [ ] Replace the remaining normal-path shell jobs with typed operations.
- [ ] Gate raw shell execution behind an explicit debug/development flag.
- [ ] Add a lint or structural test that prevents new normal-path shell jobs.

### E. UX and docs

- [~] Update installation docs: host `mvmctl` is required, host Nix is optional.
      Host-Nix-optional is now documented in `guides/builder-vm.md`; the
      `getting-started/installation.md` edit is deferred (a parallel Plan 200
      docs session owns that file) to avoid a collision.
- [x] Update architecture docs with host control plane vs builder execution
      plane. `guides/builder-vm.md` → "Resident builder control plane" section:
      `mvm-builderd` resident daemon, typed allowlisted vsock requests, no
      shell, `mvmctl doctor` "builder daemon" readiness line.
- [x] Update troubleshooting docs for builder-daemon readiness, cancellation,
      and log collection. `guides/troubleshooting.md` → "Builds hang or fail
      with the builder daemon not ready" (doctor readiness probe, recycle,
      host-driven cancellation).
- [x] Document that guest images do not contain `mvmctl` or `mvm-builderd`.
      Covered in the builder-vm.md section ("Guest images stay tool-free").
- [ ] Add a concise "what runs where" table for users and contributors.
      (`guides/builder-vm.md` already carries a "What Runs Where" table.)

## Acceptance

Plan 204 is done when:

- `mvmctl` can drive Nix flake check and at least one guest image build through
  `mvm-builderd` over vsock;
- normal `mvmctl` usage does not require host Nix;
- builder progress and failures are structured, not stderr-only parsing;
- the compatibility shell adapter is not used by normal build/run paths;
- structural tests prove host tools and builder tools are not installed into
  workload guest images;
- docs explain the host/builder/guest split without exposing builder internals
  as user-facing UX.

## Verification

- [x] Protocol serde roundtrip and unknown-field/version refusal tests.
- [x] Builder daemon health/probe tests.
- [x] Host client timeout/cancellation tests.
- [~] Builder-VM integration test for typed `FlakeCheck` — logic tested via
      injectable executor; the live in-VM `nix` run is boot-gated.
- [ ] Builder-VM integration test for typed guest image build.
- [x] Structural tests for no `mvmctl` / no `mvm-builderd` in guest images
      (`xtask check-guest-images-no-builder-tools`, CI-wired).
- [ ] `cargo test --workspace`.
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`.
- [ ] Builder-VM `nix flake check` for the affected flake paths.

## Security Notes

The builder daemon is a new privileged boundary inside the builder VM. It must
therefore be narrower than a shell:

- allowlisted operation kinds only;
- explicit source/output paths;
- no caller-provided shell snippets in the stable API;
- operation ids for auditability and cancellation;
- bounded log streaming with redaction posture;
- fail-closed version negotiation.

This plan changes the builder control plane, not workload guest trust. Workload
guest images remain separate from host and builder tools.

