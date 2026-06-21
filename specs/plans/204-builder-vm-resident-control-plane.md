# Plan 204 — Builder VM resident control plane

**Status:** In progress — WS-A (protocol, daemon core, doctor readiness, boot wiring; daemon boot + reachability live-validated on macOS-26 Vz), WS-B (host client), WS-C (FlakeCheck + build-op handler cores + the no-host-Nix test, landed as `xtask check-no-host-nix`, CI-wired), and WS-E (docs) landed. Open: WS-D's typed routing — the decision seam + compat diagnostic landed (`mvm_build::builder_route` + the `check-builder-shell-job-sites` lint), but the `BuilderdClient`-running half (typed `BuildGuestImage`/`FlakeCheck` from `dev_build`/`pool_build` + the raw-shell debug gate) remains. The typed-operation over-the-wire **transport** is now live-proven (a real `FlakeCheck` round-tripped a typed terminal over vsock-21473 on macOS-26 Vz, which also caught + fixed a missing-experimental-features daemon bug); the remaining proof is a clean `Completed`, gated on the fix reaching a rebuilt image plus WS-D source-staging.
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
      **Code landed; daemon boot + reachability live-validated on-box.**
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
      CI-compiled (incl. the musl zigbuild via embedding). Live proof
      2026-06-20 (macOS-26 Vz): `dev up` → `outcome: started`, then
      `mvmctl doctor` → `builder daemon: OK (mvm-persistent-builder-vz-dev:
      ready (protocol v1))` — a real `Handshake` over vsock 21473 negotiated
      protocol v1. The remaining step is a typed `FlakeCheck` over the wire,
      which needs the WS-D host driver. The lifecycle owner (routing
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
      over-the-wire serve). **Over-the-wire transport live-proven
      2026-06-20 (macOS-26 Vz):** the `builderd-flakecheck` diagnostic
      example (`crates/mvm-build/examples/`, the first `BuilderdClient`
      consumer) connected the host client to the live
      `vsock-21473.sock`, negotiated protocol v1, sent a real
      `FlakeCheck`, and got a typed `Failed{NixEval}` terminal back — so
      request → in-VM `nix` exec → classification → typed terminal all
      round-trip end-to-end, no hang. The live run also surfaced a real
      daemon bug the fake-executor unit tests could not: the builder
      image's `nix.conf` does not enable the `nix-command`/`flakes`
      experimental features, so every daemon `nix` invocation failed
      `error: experimental Nix feature 'nix-command' is disabled`. Fixed
      by having the daemon pass `--extra-experimental-features
      "nix-command flakes"` explicitly on all four Nix argvs
      (`flake_check_argv`/`nix_build_argv`/`prefetch_source_argv`/`query_store_path_argv`
      via a shared `nix_argv` helper) rather than depending on the
      image's global config. The remaining over-the-wire proof is a
      **clean `Completed`**: it needs this fix carried into a rebuilt
      builder image *and* a valid flake staged into a builder-VM-visible
      path, which is the WS-D host-driver/source-staging work.
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
- [x] Add tests proving normal `mvmctl` flows do not require host Nix.
      `xtask check-no-host-nix` (`xtask/src/check_no_host_nix.rs`) flags any
      literal `Command::new("nix")`/`nix-build`/… in `crates/*/src/**/*.rs`,
      proving no normal-path code shells out to a host nix binary — every nix
      invocation routes through the builder VM (`ShellEnvironment::shell_exec*`,
      in-guest) or the in-guest `mvm-builderd` daemon. The single host probe
      (`platform::has_host_nix`, zero normal-path callers) carries an explicit
      `// allow(host-nix): <reason>` marker; any new unannotated host-nix
      Command fails the gate. Wired into the CI Lint lane (ci.yml + ci-full.yml);
      3 unit tests (flag/allow-marker/clean). The daemon's nix execs are dynamic
      `Command::new(&argv[0])` and run in-guest, so they never match.

### D. Compatibility shrink

- [x] Route current shell-job builder calls through a single adapter module.
      `mvm_build::builder_route` is the host-side decision seam: `resolve_route(daemon_reachable, typed_opt_in) -> BuilderRoute::{Typed, LegacyShell}` (pure; typed only when the daemon is reachable **and** the caller opted in), `typed_opt_in(env_getter)` reading `MVM_BUILDERD_TYPED`, and `legacy_shell_diagnostic(job_label)`. The `persistent_builder::submit` dev_build dispatch boundary now resolves the route on every dispatch (3 unit tests; 17 persistent_builder tests stay green).
- [x] Emit a diagnostic when the adapter is used.
      Every legacy shell-job dispatch emits a structured `tracing` diagnostic (`target: "mvm::builder"`) naming the job, so the remaining shell surface stays visible and shrinkable — the runtime counterpart to the static `check-builder-shell-job-sites` allowlist.
- [ ] Replace the remaining normal-path shell jobs with typed operations.
      The opt-in seam is in place (`MVM_BUILDERD_TYPED` + `resolve_route`); the next step is to give `dev_build`/`pool_build` a typed `BuildGuestImage`/`FlakeCheck` path over `BuilderdClient` and flip `resolve_route`'s default per operation once proven over the wire (needs a live builder-VM boot).
- [ ] Gate raw shell execution behind an explicit debug/development flag.
      Blocked on the line above — raw shell stays the default until a typed op replaces it; the gate flips once the typed path is the default.
- [x] Add a lint or structural test that prevents new normal-path shell jobs.
      `xtask check-builder-shell-job-sites` (CI Lint lane) freezes the set of
      `*/src/` files that construct a legacy `HostVmRequest::{Run,Build}` shell
      job to a 4-entry allowlist; a construction in any new file fails the
      gate, and the gate flags an allowlist entry that no longer matches so it
      can be dropped as routing lands. File-level allowlist (like
      `check-guest-images-no-builder-tools`); `bin/` (the in-guest
      `mvm-host-vm-init` parser) and `tests/` are excluded.

#### WS-D routing plan (recon 2026-06-20)

The remaining four items are the actual routing. The host-side dispatch surface
is exactly two prod sites today:

- `crates/mvm-build/src/persistent_builder.rs` `submit()` — `dev_build`'s
  `HostVmRequest::Run` over the persistent-builder dispatch socket
  (`mvm_guest::vsock::write_frame`).
- `crates/mvm-build/src/pipeline/vsock_builder.rs` — `pool_build`'s older
  `HostVmRequest::Build` over the legacy builder-agent port.

`builderd_client::BuilderdClient` has no consumers yet; its typed ops cover the
need (`BuildGuestImage`/`BuildHostTool` for the flake build, `FlakeCheck`,
`PrefetchSource`, `QueryStorePath`). Phased rollout:

1. **Socket resolution.** Add a helper that returns the running builder's
   `builderd` control socket for a build dispatch (libkrun
   `<vm_state_dir>/vsock-21473.sock` vs Vz `<vm_state_dir>/vsock/…`, via the
   existing `builderd_control_socket_candidates`). The persistent-builder
   `SessionRecord` does not record it today — derive it from the session's
   `vm_state_dir` + backend rather than adding a field.
2. **Single adapter module.** The decision + diagnostic half landed as
   `mvm_build::builder_route` (`resolve_route` + `MVM_BUILDERD_TYPED` opt-in +
   `legacy_shell_diagnostic`, wired into `persistent_builder::submit`). The
   remaining half: given a resolved socket, run a build through
   `BuilderdClient::run_operation` and
   map `OperationOutcome::{Artifact,Failed,…}` onto the existing artifact shape;
   on `NotReady`/missing socket it logs one diagnostic and falls back to the
   legacy shell-job channel. Unit-test it against the in-process
   `serve_connection` daemon (as `builderd_client` tests already do).
3. **Opt-in flip, then default.** Wire the two dispatch sites through the
   adapter behind `MVM_BUILDERD_DISPATCH=1` (default off → zero behaviour
   change, mergeable without a live boot), then flip the default after a live
   per-backend boot proves a typed `BuildGuestImage` produces the same artifact
   (libkrun + Vz on macOS; Firecracker on a KVM host).
4. **Gate raw shell + diagnostic.** Once routing is the default, gate the legacy
   channel behind an explicit debug flag and keep the adapter's
   fallback-diagnostic; drop each routed file from the
   `check-builder-shell-job-sites` allowlist as it stops constructing a shell
   job.

Riskiest parts: the daemon-unavailable fallback must be exact, cancellation
must map `request_cancel` onto the legacy signal path, and step 3's default flip
needs live per-backend artifact-equality proof before it lands.

### E. UX and docs

- [x] Update installation docs: host `mvmctl` is required, host Nix is optional.
      Host-Nix-optional is documented in `guides/builder-vm.md`, and
      `getting-started/installation.md` now carries a resident-builder-daemon
      note: builds run through `mvm-builderd` over typed vsock (not a builder
      shell), `mvmctl` is the only command users invoke, and `mvmctl doctor`'s
      "builder daemon" line is the readiness surface — cross-linked to the
      builder-vm control-plane section.
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
- [x] Add a concise "what runs where" table for users and contributors.
      `guides/builder-vm.md` carries a "What Runs Where" table.

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
      injectable executor; the live in-VM `nix` run is boot-gated. The
      `builderd-flakecheck` example drove a real `FlakeCheck` over the live
      vsock-21473 socket on macOS-26 Vz (2026-06-20), proving the transport
      + in-VM exec + typed terminal round-trip and catching the missing
      experimental-features bug. A clean `Completed` still needs the fix in
      a rebuilt image + a staged flake (WS-D).
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

