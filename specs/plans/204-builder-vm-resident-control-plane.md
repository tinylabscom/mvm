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

- `mkGuest` images do not include `mvmctl`;
- `mkGuest` images do not include `mvm-builderd`;
- host packages are separate from guest image outputs;
- the builder daemon package is only part of the builder VM image.

## Workstreams

### A. Protocol and daemon skeleton

- [x] Add builder request/response wire types with serde roundtrip tests.
      `mvm_build::builderd_protocol` — typed `BuilderRequest`
      (`Handshake`/`Probe`/`FlakeCheck`/`BuildGuestImage`/`BuildHostTool`/
      `PrefetchSource`/`QueryStorePath`/`CancelJob`) + `BuilderResponse`
      (`Accepted`/`Progress`/`LogChunk`/`ArtifactReady`/`StorePathReady`/
      `Failed`/`Cancelled`), an `OperationId` newtype, and a stable
      `FailureCategory`. Externally-tagged snake_case + `deny_unknown_fields`
      on every variant (fail-closed against an unknown peer field/kind),
      reusing the existing 256 KiB vsock framing. Roundtrip, kind-tag
      stability, and unknown-field/unknown-kind rejection tests (26 tests).
- [x] Add protocol-version negotiation and unsupported-version refusal tests.
      `PROTOCOL_VERSION` + `negotiate()` (exact-match v1, fail-closed) +
      `handshake_reply()` returning `Failed`/`FailureCategory::Version` on an
      unsupported version.
- [ ] Add `mvm-builderd` skeleton with `Handshake` and `Probe`.
- [ ] Add builder-VM image wiring so the daemon starts on boot.
- [ ] Add `mvmctl doctor` visibility for builder daemon readiness.

### B. Host client and lifecycle

- [ ] Add a host-side builder client that connects over vsock.
- [ ] Thread operation ids through progress/log rendering.
- [ ] Add timeout, cancellation, and daemon-not-ready error handling.
- [ ] Ensure `MVM_DATA_DIR` / cache-dir isolation stays per worktree.
- [ ] Keep all git operations host-side and outside the builder VM.

### C. Typed Nix operations

- [ ] Implement `FlakeCheck` for the `nix/` flake.
- [ ] Implement `BuildGuestImage`.
- [ ] Implement `BuildHostTool` for source-built host packages.
- [ ] Implement `PrefetchSource` / `QueryStorePath` if needed to remove ad hoc
      host-side probing.
- [ ] Add tests proving normal `mvmctl` flows do not require host Nix.

### D. Compatibility shrink

- [ ] Route current shell-job builder calls through a single adapter module.
- [ ] Emit a diagnostic when the adapter is used.
- [ ] Replace the remaining normal-path shell jobs with typed operations.
- [ ] Gate raw shell execution behind an explicit debug/development flag.
- [ ] Add a lint or structural test that prevents new normal-path shell jobs.

### E. UX and docs

- [ ] Update installation docs: host `mvmctl` is required, host Nix is optional.
- [ ] Update architecture docs with host control plane vs builder execution
      plane.
- [ ] Update troubleshooting docs for builder-daemon readiness, cancellation,
      and log collection.
- [ ] Document that guest images do not contain `mvmctl` or `mvm-builderd`.
- [ ] Add a concise "what runs where" table for users and contributors.

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

- [ ] Protocol serde roundtrip and unknown-field/version refusal tests.
- [ ] Builder daemon health/probe tests.
- [ ] Host client timeout/cancellation tests.
- [ ] Builder-VM integration test for typed `FlakeCheck`.
- [ ] Builder-VM integration test for typed guest image build.
- [ ] Structural tests for no `mvmctl` / no `mvm-builderd` in guest images.
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

