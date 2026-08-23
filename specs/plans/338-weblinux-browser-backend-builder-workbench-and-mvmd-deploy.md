# Plan 338 — WebLinux browser backend, builder, workbench, and `mvmd` deployment client

Backing: preview
Validation: none

**Status: IN PROGRESS — Workstream 0 complete, Workstream 1 first slice merged in PR #2776, Workstream 2 engine packaging code landed; `nix build .#qemu-wasm-engine` verified on the aarch64-linux HVF builder VM**
**Opened:** 2026-08-15
**ADR:** `specs/adrs/049-weblinux-browser-backend-and-local-builder.md`
**Numbered against:** `main@0c9ef804db4b3a89fdd72190a987fea87ff9e664`
**Related:** Plans 301 and 329, ADRs 006, 007, 014, 024, 037, and 042

## Outcome

Make the browser one complete, open-source `mvm` workbench and local host:

```text
edit in browser
    -> develop in a WebLinux guest
    -> build in a clean WebLinux builder guest
    -> run the built artifact in a clean WebLinux runtime guest
    -> optionally Deploy on mvmd
```

The browser path must not require an `mvmd` account for local development,
local builds, local runs, artifact export, or local previews.

`mvmd` is the proprietary managed deployment destination. This repository owns
the deployment client, portable contracts, artifact upload protocol, and UX;
it does not implement the private scheduler, fleet reconciler, production
secrets service, billing, or managed ingress.

## Definition of done

The plan is complete when all of the following are true:

1. `WebLinux` is a typed backend kind with honest capabilities and a
   browser-compatible lifecycle service.
2. `WebLinuxBuilderVm` runs a real `BuilderJob` entirely in the browser and
   emits the same logical artifact contract as native builder backends.
3. A user can open the browser workbench, edit a source file, execute a command,
   build a fixture, and boot the resulting artifact without contacting `mvmd`.
4. The browser-built workload artifact can be exported and launched by at least
   one native `mvm` backend without rebuilding.
5. The open-source browser workbench can submit that artifact to an `mvmd`
   deployment-client test double through the versioned deployment contract.
6. The workbench exposes terminal, logs, tasks, tests, source persistence, and
   an isolated local application preview.
7. The backend remains claim-free and cannot be mistaken for a
   hardware-isolated or production-authoritative backend.
8. Native default builds carry no QEMU-Wasm/Emscripten dependency and retain
   their existing performance and security gates.
9. Browser engine, runtime-pack, artifact, and source-build inputs are pinned,
   digest-addressed, and covered by license/SBOM output.
10. The relevant Rust, wasm, browser, Nix, fuzz, documentation, and end-to-end
    gates pass.

## Product boundary

### Open-source `mvm`

This plan includes:

- `WebLinuxBackend`;
- `WebLinuxBuilderVm`;
- browser workbench and editor integration;
- OPFS workspace, CAS, and block storage;
- Nix-built QEMU-Wasm engine and WebLinux runtime packs;
- portable VM/build/artifact/deployment DTOs;
- local terminal, tasks, tests, logs, and preview;
- local artifact signing, inspection, import, and export;
- `mvmctl deploy` and browser **Deploy on mvmd** client flows;
- mock/conformance implementation of the deployment contract.

### Proprietary `mvmd`

This plan does not implement:

- account, organization, or billing systems;
- production scheduler and node placement;
- production backend selection;
- durable reconciliation and rollouts;
- managed public ingress, certificates, or custom domains;
- production secret storage/resolution;
- hosted logs, metrics, traces, audit retention, or SLAs;
- multi-tenant fleet operations.

## Existing code that this work must reuse

The implementation starts by reconciling, not replacing, these existing seams:

- `crates/mvm-contract/src/protocol/vm_backend.rs`
- `crates/mvm-core/src/protocol/vm_backend.rs`
- `crates/mvm-runtime/src/catalog.rs`
- `crates/mvm-runtime/src/wasm_backend.rs`
- `crates/mvm-build/src/builder_vm.rs`
- `crates/mvm-build/src/builder_backend_select.rs`
- `crates/mvm-contract/src/plan/bundle.rs`
- `crates/mvm-core/src/plan/bundle.rs`
- the existing `MvmClient`/gateway contract
- `nix/lib/mk-guest.nix`
- `nix/images/runtime-overlay/flake.nix`
- `web/mvm-demo`
- `web/mvm-demo-guest`
- ADR-042's single flow-aware network path

Do not create a second policy engine, artifact signer, audit format, backend
selector, builder job format, or remote-client abstraction where an existing
one can be extended.

## Proposed architecture

```text
┌────────────────────────────────────────────────────────────────────┐
│ Browser workbench                                                  │
│                                                                    │
│ Code-OSS/VS Code Web-compatible UI                                 │
│   source, SCM, tasks, tests, terminal, logs, preview, deploy       │
│                         │ typed Worker RPC                          │
│                         ▼                                           │
│ mvm web control Worker                                              │
│   plan/artifact verification, admission, CAS, OPFS, audit, quotas   │
│                │                       │                             │
│                │                       └── mvmd deployment client     │
│                ▼                                                     │
│ QEMU-Wasm Worker                                                     │
│   WebLinux runtime pack                                              │
│     Linux kernel + initramfs + runtime overlay + guest agent         │
│     /workspace via shared filesystem                                 │
│     /nix and high-churn caches via OPFS-backed block disks           │
│     control/network/preview over virtio-serial -> MessagePort        │
└────────────────────────────────────────────────────────────────────┘
```

The same workbench may later control native or remote targets, but this plan's
local acceptance path is browser-only and complete.

## Workstream 0 — Reconcile names, ADRs, and repository truth

- [x] 0.1 Add ADR-049 and this plan with `Backing:`/`Validation:` headers.
- [x] 0.2 Update ADR-024:
  - removed the stale statement that no Wasm implementation has landed;
  - retained its direct-WASI claim-free constraints;
  - superseded only its rejection of browser Linux;
  - linked to ADR-049.
- [x] 0.3 Update ADR-006:
  - retained the ban on provider registries and local fleet orchestration;
  - allowed one `mvmctl deploy` client path to authenticated `mvmd`;
  - stated that the client submits artifact/deployment intent and does not
    choose hosts or production backends.
- [x] 0.4 Linked ADR-037 in ADR-049 so production launch authority remains unambiguous.
- [x] 0.5 Renamed browser documentation/plan references from ambiguous
      `BrowserWasmBackend` to `BrowserWasiBackend` where doing so does not break a
      public compatibility surface. No public Rust symbols required renaming.
- [x] 0.6 Registered Plan 338 in `specs/SPRINT.md` and
      `specs/REFACTOR-STATUS.md`. Plan 332 register not applicable on this branch.
- [x] 0.7 Run `check-declared-backing` and all documentation guards.

**Gate:** repository docs describe direct WASI, WebLinux, native backends, and
`mvmd` production authority without contradiction.

## Workstream 1 — Portable backend, builder, and artifact contracts

### 1A. Backend identity and capability dimensions

- [x] 1.1 Add `BackendKind::WebLinux`.
- [x] 1.2 Keep direct WASI as a distinct kind/name; do not repurpose
      `BackendKind::Wasm`.
- [x] 1.3 Add only the capability dimensions required to state WebLinux
      honestly. Candidate dimensions:
  - guest environment (`linux`, `wasi`);
  - CPU execution (`hardware_virtualized`, `software_emulated`,
    `wasm_native`);
  - isolation boundary (`hardware_vm`, `browser_sandbox`, `host_process`);
  - lifecycle scope (`process`, `document`, `durable_node`);
  - artifact-integrity and attestation tiers.
- [ ] 1.4 Move pure backend descriptor metadata to a browser-compilable owner
      if the current native catalog cannot be shared without pulling runtime
      dependencies.
- [ ] 1.5 Retain one generated/typed source of truth for selectors, aliases,
      support surfaces, and capability labels.
- [x] 1.6 Ensure native `AnyBackend` construction either returns a typed
      browser-only unavailability for `WebLinux` or keeps constructors in a
      platform-specific registry without weakening exhaustive kind handling.

### 1B. Portable lifecycle protocol

- [x] 1.7 Define versioned, bounded `BackendRequest` and `BackendResponse`
      DTOs for start/stop/status/logs/stdin/wait/inspect.
- [ ] 1.8 Define progress events for artifact resolution, engine load, engine
      compile, storage preparation, kernel boot, init, workload start, and ready.
- [ ] 1.9 Define browser lifecycle semantics so “detached” never implies
      survival after browser discard.
- [ ] 1.10 Add explicit cancellation and idempotency keys.
- [x] 1.11 Add maximum frame sizes and `deny_unknown_fields`.

### 1C. Portable artifact and build protocol

- [x] 1.12 Introduce digest-addressed `ArtifactRef`/`ArtifactSetRef` values.
- [ ] 1.13 Separate portable start/build input from resolved host `PathBuf`
      forms.
- [ ] 1.14 Define browser-safe `BuildRequest`, `BuildProgress`, and
      `PortableBuilderArtifacts`.
- [ ] 1.15 Keep current native traits through adapters; do not force
      JavaScript/OPFS handles into `VmBackend` or `BuilderVm`.
- [ ] 1.16 Generate schema and language bindings through the repository's
      existing schema/stub pipeline.
- [ ] 1.17 Keep JCS/canonical signed bytes unchanged until a separately
      versioned artifact schema explicitly changes them.

**Gate:** contracts build under `wasm32-unknown-unknown`, native adapters pass
existing behavior tests, unknown fields fail closed, and no string backend
dispatch is introduced.

## Workstream 2 — Reproducible QEMU-Wasm engine feasibility slice

Use these as prior art, not as unreviewed vendored artifacts:

- <https://github.com/ktock/qemu-wasm>
- <https://ktock.github.io/qemu-wasm-demo/alpine-x86_64.html>
- <https://github.com/container2wasm/container2wasm>
- <https://github.com/ktock/vscode-container-wasm>

- [x] 2.1 Pin an exact QEMU source revision, qemu-wasm patch set, Emscripten
      toolchain, and every cross-compiled C dependency. Pinned:
  - `ktock/qemu-wasm` `5a65998d47d78723115d1478a8a40f8d6d497f37` (QEMU 9.2.92-wasm)
  - Emscripten SDK 3.1.50 via nixpkgs `c407032be28ca2236f45c49cfb2b8b3885294f7f`
  - zlib 1.3.1, libffi 3.4.7, pixman 0.44.2, glib 2.84.0, xterm-pty 0.10.1
- [x] 2.2 Build through Nix using the repository's approved builder path; do
      not require a developer-installed Emscripten or Docker daemon.
      Verified inside the aarch64-linux HVF builder VM (`nix build .#qemu-wasm-engine`).
- [ ] 2.3 Keep the engine behind a browser/WebLinux build feature so default
      native workspace builds carry none of it.
- [ ] 2.4 Generate license notices, corresponding-source metadata, and an SBOM.
- [ ] 2.5 Serve a dedicated cross-origin-isolated development page with real
      COOP/COEP headers; do not rely on a service-worker header shim in the
      production design.
- [ ] 2.6 Add a browser capability probe for:
  - secure context;
  - `crossOriginIsolated`;
  - `SharedArrayBuffer`;
  - Wasm threads/atomics/bulk memory;
  - OPFS and synchronous access handles;
  - storage estimate/persistence;
  - Workers;
  - browser/version support.
- [ ] 2.7 Boot the upstream Alpine demo image only as a toolchain smoke test.
- [x] 2.8 Boot an `mvm`-built x86_64 kernel and minimal busybox rootfs under
      headless Chromium. The smoke guest uses `console=ttyS0 root=/dev/vda`
      with busybox `init` + `/etc/inittab`, and the headless-Chromium harness
      reports `SMOKE-RESULT: READY` in ~26 s with a peak RSS of ~2.5 GiB.
- [ ] 2.9 Stream serial output from a dedicated QEMU Worker without blocking
      the editor/main thread.
- [ ] 2.10 Record:
  - engine Wasm/JS/data bytes;
  - engine compile time;
  - kernel-entry time;
  - PID-1 time;
  - shell/agent-ready time;
  - total browser memory and Wasm heap;
  - idle and boot CPU;
  - rootfs read amplification.
- [ ] 2.11 Record a merge/no-merge resource envelope in this plan before
      expanding beyond the spike.

**Gate:** an `mvm` kernel reaches the real `/init` and prints an unambiguous
ready marker in headless Chromium. The plan contains measured resource data,
not an assumed browser SLO.

## Workstream 3 — WebLinux runtime-pack build

- [ ] 3.1 Add Nix outputs for:
  - `weblinux-kernel-x86_64`;
  - `weblinux-initramfs-x86_64`;
  - `weblinux-runtime-overlay-x86_64`;
  - `weblinux-runtime-pack-x86_64`.
- [ ] 3.2 Start from the existing `mkGuest`/runtime-overlay lineage rather than
      a parallel guest image system.
- [ ] 3.3 Build boot-critical drivers into the kernel:
  - 8250 serial console;
  - virtio PCI;
  - virtio block;
  - virtio console/serial;
  - virtio RNG;
  - 9P/virtio-9p for the initial workspace share;
  - ext4, tmpfs, proc, sysfs, devtmpfs;
  - overlayfs if the root composition uses it.
- [ ] 3.4 Avoid boot-critical loadable modules in the first runtime pack.
- [ ] 3.5 Include the same guest-agent/protocol implementation used by native
      workload guests, with a transport adapter rather than a second agent.
- [ ] 3.6 Sign and digest the runtime-pack manifest independently from the
      workload.
- [ ] 3.7 Version the QEMU machine type, CPU model, devices, and engine ABI in
      the runtime pack.
- [ ] 3.8 Add a compatibility refusal when a cached runtime pack and engine ABI
      do not match.

**Gate:** the signed runtime pack boots, mounts its declared devices, starts the
real guest agent, and reports its runtime-pack digest.

## Workstream 4 — OPFS content store and browser block service

### 4A. Content-addressed immutable store

- [ ] 4.1 Store immutable objects by SHA-256 digest.
- [ ] 4.2 Verify on every read, not only on download.
- [ ] 4.3 Support chunk indexes and HTTP range retrieval so boot does not
      require downloading a monolithic archive.
- [ ] 4.4 Deduplicate runtime packs, rootfs chunks, source snapshots, and build
      outputs.
- [ ] 4.5 Add partial-download resume and atomic object promotion.
- [ ] 4.6 Detect corruption, evict the object, and re-fetch rather than using
      damaged bytes.

### 4B. Writable disks

- [ ] 4.7 Add OPFS-backed random-access block files using Worker-only sync
      handles.
- [ ] 4.8 Implement explicit flush/barrier semantics and test them against the
      guest filesystem.
- [ ] 4.9 Enforce a single-writer workspace/volume lease across tabs.
- [ ] 4.10 Add quota preflight, low-storage refusal, usage display, eviction
      controls, and export.
- [ ] 4.11 Separate:
  - source workspace;
  - persistent Nix store;
  - high-churn build cache;
  - clean `/out`;
  - runtime writable overlay.
- [ ] 4.12 Add unclean Worker-termination tests and disk recovery.
- [ ] 4.13 Bound all read-ahead/write-back caches.

**Gate:** a cached runtime pack and writable disk survive reload, corrupted
immutable data is refused, a second tab cannot take the writable lease, and an
unclean stop recovers without losing an acknowledged editor save.

## Workstream 5 — `WebLinuxBackend` lifecycle service

- [ ] 5.1 Add a browser Worker service implementing the portable lifecycle
      protocol.
- [ ] 5.2 Maintain explicit VM state:
      `Resolving`, `Preparing`, `Starting`, `Running`, `Stopping`, `Stopped`,
      `Exited`, `Failed`, `Discarded`.
- [ ] 5.3 Implement start, wait, status, list, logs, stdin, graceful stop, and
      forced termination.
- [ ] 5.4 Map terminal resize and signals.
- [ ] 5.5 Bound console buffers and apply terminal escape-sequence filtering.
- [ ] 5.6 Implement document/workbench-bound detach semantics.
- [ ] 5.7 Support one active VM per workbench in v1; return an actionable
      resource refusal for a second.
- [ ] 5.8 Add page lifecycle handling:
  - checkpoint dirty disks periodically;
  - respond to freeze/visibility transitions;
  - detect discarded reload;
  - never depend on an unload callback for correctness.
- [ ] 5.9 Advertise an entirely claim-free `BackendSecurityProfile`.
- [ ] 5.10 Implement typed refusals for verified-boot claims, hardware
      attestation, durable detached lifetime, unsupported devices, and unsupported
      network shapes.

**Gate:** the shared lifecycle conformance suite passes through the browser
adapter, including cancellation, double-stop, crash, unknown-VM, and bounded-log
cases.

## Workstream 6 — Guest service transport over virtio-serial

- [ ] 6.1 Generalize `GuestChannelInfo` beyond vsock without weakening native
      vsock behavior.
- [ ] 6.2 Map named virtio-serial ports to dedicated `MessagePort`s:
  - control/exec;
  - console;
  - network flow;
  - events/audit;
  - preview;
  - future debugger/language-service channels.
- [ ] 6.3 Reuse the current framed protocol and `GuestService` identities.
- [ ] 6.4 Add version negotiation, channel authentication/capability binding,
      length caps, backpressure, cancellation, and heartbeat/reconnect behavior.
- [ ] 6.5 Keep control, console, and bulk streams from starving one another.
- [ ] 6.6 Run the same malformed-frame and fuzz corpus against vsock and
      virtio-serial transports.

**Gate:** the real guest agent supports exec, terminal, exit reporting, events,
and one no-network control round trip through virtio-serial with the same
logical protocol used by native guests.

## Workstream 7 — Browser-local workspace and source snapshots

- [ ] 7.1 Make OPFS the authoritative browser workspace.
- [ ] 7.2 Share `/workspace` into the development guest through 9P initially.
- [ ] 7.3 Specify and test file semantics required by editors/toolchains:
      rename, locks, symlinks, executable bits, case sensitivity, timestamps,
      fsync, large repositories, and concurrent read/write.
- [ ] 7.4 Do not place `target/`, `node_modules/`, `/nix/store`, or language
      indexes on a naïve file-by-file bridge; put them on block-backed cache disks.
- [ ] 7.5 Create immutable content-addressed `WorkspaceSnapshot`s from editor
      state, preserving executable bits and symlinks while excluding declared
      caches and secrets.
- [ ] 7.6 Ensure a build consumes one immutable snapshot even while editing
      continues.
- [ ] 7.7 Add import/export and Git-backed recovery.
- [ ] 7.8 Add workspace ownership/lease transfer for future local/native/remote
      workbench switching; do not support simultaneous multi-writer workspaces in
      v1.

**Gate:** edit, rename, executable-bit, symlink, Git, and concurrent build
fixtures round-trip correctly between workbench, OPFS, and guest.

## Workstream 8 — `WebLinuxBuilderVm`

- [ ] 8.1 Add explicit `BuilderBackendChoice::WebLinux`.
- [ ] 8.2 Do not add WebLinux to native auto-detection; the browser workbench
      selects it.
- [ ] 8.3 Implement the portable builder service using the existing
      `BuilderJob` variants and result semantics.
- [ ] 8.4 Build a browser builder runtime pack with Nix and the required
      toolchain closure.
- [ ] 8.5 Mount:
  - immutable source snapshot at `/work`;
  - persistent OPFS-backed Nix store/cache;
  - clean output at `/out`;
  - runtime tools read-only.
- [ ] 8.6 Preserve the “no host Nix” rule: every eval/build happens inside the
      guest.
- [ ] 8.7 Implement bounded logs, cancellation, timeout, memory, process, disk,
      and network receipts without claiming an unenforceable host CPU share.
- [ ] 8.8 Emit portable image/install outputs plus structured build metadata.
- [ ] 8.9 Add a browser signing identity flow:
  - no plaintext long-lived key in source or unencrypted OPFS;
  - import/export or hardware/user-authenticated key wrapping;
  - explicit ephemeral-dev-key mode;
  - trust metadata for `mvmd` policy decisions.
- [ ] 8.10 Reuse existing SBOM, scan, dependency-fetch, and artifact-verification
      machinery where it compiles; move pure pieces down rather than porting logic
      independently.
- [ ] 8.11 Keep Stage 0 out of the browser first slice. Ship a signed prebuilt
      builder runtime pack; add a browser self-bootstrap only after the steady-state
      builder works.

**Gate:** a browser-local `BuilderJob::Flake` builds a small repository fixture,
a second build reuses persistent cache, and the output is a verified portable
artifact with a build receipt. No `mvmd` call occurs.

## Workstream 9 — Versioned workload/runtime-pack artifact model

- [ ] 9.1 Design the next `.mvmpkg` schema without breaking existing readers.
- [ ] 9.2 Distinguish guest platform from host platform; emulated `amd64` may run
      on an ARM browser host.
- [ ] 9.3 Split workload artifacts from runtime packs while preserving a
      convenient combined offline archive.
- [ ] 9.4 Add browser-addressable CAS distribution:
      signed manifest + independently retrievable objects/chunks.
- [ ] 9.5 Bind chunk roots, media types, sizes, CPU model requirements,
      entrypoint, user, environment, working directory, and OCI source digest.
- [ ] 9.6 Define direct-root OCI compatibility and typed refusal reasons.
- [ ] 9.7 Add OCI fixtures covering:
      BusyBox, Alpine, Debian, distroless, Python, Node, static Rust, non-root,
      whiteouts, symlinks, hardlinks, gzip/zstd layers, and read-only roots.
- [ ] 9.8 Keep unsupported host-dependent OCI behavior explicit.
- [ ] 9.9 Add artifact lineage:
      workspace snapshot -> build receipt -> workload digest -> local run receipt
      -> deployment intent.
- [ ] 9.10 Add export/import and `mvmctl bundle inspect` support for the new
      schema.

**Gate:** one artifact built in WebLinux runs unchanged under WebLinux and at
least one native backend or native QEMU compatibility lane. The workload digest
is identical across both runs.

## Workstream 10 — Browser workbench

### 10A. Workbench selection

- [ ] 10.1 Evaluate a Code-OSS/VS Code Web-compatible distribution, OpenVSCode
      components, and a narrower Monaco-based shell.
- [ ] 10.2 Record the choice against license, trademark, bundle size,
      extension-host support, offline support, and maintenance cost.
- [ ] 10.3 Do not depend on Microsoft's proprietary marketplace.

### 10B. Initial experience

- [ ] 10.4 Add project/open/import/create flows.
- [ ] 10.5 Add OPFS file explorer/editor and dirty-buffer persistence.
- [ ] 10.6 Add guest-backed terminal, command history, resize, and copy/paste
      safety.
- [ ] 10.7 Add tasks, test results, problem matchers, logs, and build progress.
- [ ] 10.8 Add explicit backend and builder status:
      `WebLinux`, claim-free, document-bound, current runtime-pack digest.
- [ ] 10.9 Add Build, Run Locally, Stop, Export Artifact, and Deploy on mvmd
      actions.
- [ ] 10.10 Add Git HTTPS auth with short-lived credentials and no SSH-key copy
      into the guest.

### 10C. Language and debug services

- [ ] 10.11 Start with selected guest language servers and debugger adapters
      controlled through explicit channels.
- [ ] 10.12 Measure `rust-analyzer`, TypeScript server, and debugger memory.
- [ ] 10.13 Add a guest-side Node workspace-extension host only after the
      measured browser envelope permits it.
- [ ] 10.14 Define extension placement/trust:
      browser extension, guest workspace extension, privileged mvm control
      extension.
- [ ] 10.15 Restrict arbitrary extensions from receiving backend/deploy
      authority.

**Gate:** a user edits a Rust fixture, sees diagnostics, runs a task in the
guest, builds it with `WebLinuxBuilderVm`, boots the artifact, and views logs
without leaving the browser.

## Workstream 11 — Flow-aware browser networking and local preview

### 11A. Egress

- [ ] 11.1 Carry ADR-042 `NetworkFlow` over the virtio-serial transport.
- [ ] 11.2 Share canonical policy, DNS pinning, substitution, rate, and audit
      code from `mvm-contract`; no browser-only policy fork.
- [ ] 11.3 Implement `Off` and typed Fetch/HTTP flows first.
- [ ] 11.4 Add an open relay protocol for opaque TCP/UDP and protocols Fetch
      cannot serve.
- [ ] 11.5 Provide a self-hostable/local `mvm web relay` implementation where it
      fits the open-source boundary; `mvmd` may offer the managed implementation.
- [ ] 11.6 Make transport limitations visible in capability negotiation.
- [ ] 11.7 Support package managers/Nix caches through the strongest available
      flow without widening policy.
- [ ] 11.8 Keep real production secret resolution on the trusted `mvmd` side.
- [ ] 11.9 Add local development secret bindings that are explicit, redacted
      from logs, excluded from artifacts, and labeled non-production.

### 11B. Preview ingress

- [ ] 11.10 Add a separate preview origin and per-VM/port capability.
- [ ] 11.11 Support HTTP request/response streaming, cancellation, redirects,
      cookies, SSE, and WebSockets.
- [ ] 11.12 Never serve guest application content on the trusted workbench
      origin.
- [ ] 11.13 Sandbox preview permissions; deny clipboard, camera, microphone,
      location, popups, and downloads by default.
- [ ] 11.14 Clear preview-origin service workers and storage on teardown.
- [ ] 11.15 Add preview authentication and bounded bandwidth/request sizes.

**Gate:** default-deny egress is observable, an explicitly allowed development
fetch works, an unbound secret placeholder is refused, and a guest HTTP/WebSocket
fixture is previewed on an isolated origin.

## Workstream 12 — Open-source `mvmd` deployment client

This workstream implements only the public client and contract.

- [ ] 12.1 Add versioned deployment DTOs to the appropriate open contract:
  - artifact inventory;
  - missing-object negotiation;
  - deployment intent;
  - secret references;
  - ingress/scale/region intent;
  - accepted/refused response;
  - deployment status/events.
- [ ] 12.2 Decide whether the existing `MvmClient::Gateway` surface can be
      extended cleanly. Extend it rather than adding a second remote client unless
      the current trait cannot represent deployment semantics without distortion.
- [ ] 12.3 Add `mvmctl deploy` with no provider registry and no production
      backend selector.
- [ ] 12.4 Add browser **Deploy on mvmd** using the same client contract.
- [ ] 12.5 Upload the signed manifest first; let the server request only
      missing CAS objects.
- [ ] 12.6 Re-hash every uploaded object and bind deployment to the immutable
      workload digest.
- [ ] 12.7 Send production secret references, never production secret values.
- [ ] 12.8 Stream accepted/refused/status/log events.
- [ ] 12.9 Add a local mock/conformance server used by Rust and browser tests.
- [ ] 12.10 Do not add scheduler, placement, billing, production secret-store,
      or managed-ingress code to this repository.
- [ ] 12.11 Document that authenticated `mvmd` origin is what converts the
      request into a production launch under ADR-037.

**Gate:** a browser-built artifact is submitted to the conformance server,
missing objects are uploaded once, a deployment status reaches `Ready`, and
the request contains no production secret value or backend placement decision.

## Workstream 13 — Security hardening and threat model

- [ ] 13.1 Add a WebLinux-specific threat model covering:
  - malicious Linux guest;
  - QEMU device/parser bugs;
  - browser/workbench XSS;
  - malicious extension;
  - hostile terminal output;
  - hostile preview application;
  - OPFS rollback/corruption;
  - cross-tab races;
  - relay compromise;
  - artifact/signing-key theft;
  - browser suspension/discard.
- [ ] 13.2 Serve workbench, execution runtime, artifacts, and previews from
      deliberately separated origins/capabilities.
- [ ] 13.3 Add strict CSP. Permit only the minimum Wasm compilation capability
      required by the engine; avoid broad JavaScript eval.
- [ ] 13.4 Require HTTPS and cross-origin isolation.
- [ ] 13.5 Pin and integrity-check every engine/runtime asset.
- [ ] 13.6 Fuzz:
  - portable request/response frames;
  - virtio-serial framing;
  - block callbacks/chunk indexes;
  - OCI manifests/layers/whiteouts;
  - deployment DTOs;
  - terminal and preview metadata.
- [ ] 13.7 Apply hard message, log, file, process, storage, network, and
      wall-clock limits.
- [ ] 13.8 Keep local audit evidence distinguished from externally witnessed
      or hardware-attested evidence.
- [ ] 13.9 Add optional remote audit-head witnessing without making it required
      for local use.
- [ ] 13.10 Add dependency/CVE review and QEMU patch-update procedure.

**Gate:** security tests cover every new trust boundary, and public/docs copy
does not attribute hardware or production claims to WebLinux.

## Workstream 14 — Performance, compatibility, and release gates

### 14A. Performance

- [ ] 14.1 Establish measured budgets after WS-2 for:
      engine bytes/compile, boot milestones, peak memory, disk latency, workspace
      operations, Nix eval/build, `cargo check`, language-server indexing, preview
      latency, and cached restart.
- [ ] 14.2 Gate bundle and runtime-pack size.
- [ ] 14.3 Gate main-thread responsiveness.
- [ ] 14.4 Gate memory admission and friendly OOM refusal.
- [ ] 14.5 Confirm WebLinux feature work does not alter native 200 ms goals or
      native dependency graphs.

### 14B. Browser/device matrix

- [ ] 14.6 Support desktop Chromium first with explicit minimum capabilities.
- [ ] 14.7 Record Firefox and Safari behavior without claiming support before
      conformance passes.
- [ ] 14.8 Add private-browsing, storage-denied, low-quota, hidden-tab,
      discarded-tab, offline, and browser-update scenarios.
- [ ] 14.9 Add one-VM admission first; measure before allowing concurrent VMs.

### 14C. Workload/build matrix

- [ ] 14.10 Run shell, Git, SQLite, Rust, Node, Python, Nix, HTTP, WebSocket, and
      large-file fixtures.
- [ ] 14.11 Compare local browser output and native output for deterministic
      fixtures.
- [ ] 14.12 Add cold-cache and warm-cache CI lanes.
- [ ] 14.13 Add a nightly browser build-to-run-to-deploy-conformance lane.

**Gate:** the documented support matrix is generated from passing tests, and
unsupported browsers/workloads fail with actionable capability errors.

## Workstream 15 — Closeout

- [ ] 15.1 Update platform-support, architecture, CLI, build, artifact, browser,
      and deployment documentation.
- [ ] 15.2 Add user-facing language:
  - Build anywhere with `mvm`.
  - Run locally on an `mvm` backend.
  - Deploy on `mvmd`.
- [ ] 15.3 Update `specs/SPRINT.md`, `specs/REFACTOR-STATUS.md`, Plan 332, and
      relevant claim/support matrices.
- [ ] 15.4 Record all deferred work explicitly:
      multi-VM, mobile, additional architectures, full extension host, memory
      snapshots, live migration, broader browsers.
- [ ] 15.5 Run full repository gates and browser E2E.
- [ ] 15.6 Publish engine source/patches, notices, SBOM, and reproducible build
      instructions required by shipped licenses.
- [ ] 15.7 Write a delivery note containing measured limits rather than
      aspirational claims.

## Sequencing

The critical path is:

```text
WS-0 docs/reconciliation
  -> WS-1 portable contracts
  -> WS-2 QEMU-Wasm go/no-go
  -> WS-3 runtime pack
  -> WS-4 storage/block service
  -> WS-5 lifecycle
  -> WS-6 guest transport
  -> WS-7 workspace
  -> WS-8 builder
  -> WS-9 portable artifact
  -> WS-10 workbench
  -> WS-11 network/preview
  -> WS-12 deployment client
  -> WS-13/14 hardening and release
```

Parallel work that does not weaken the gates:

- WS-9 schema design can begin after WS-1 while the engine spike runs.
- The deployment-contract test double in WS-12 can begin after WS-1/WS-9.
- Workbench selection in WS-10 can be researched during WS-2, but full
  integration waits for a working lifecycle and workspace.
- Threat modeling begins with WS-1 and is finalized in WS-13.

Do not build the full IDE before WS-2 determines whether the engine and guest fit a
credible browser resource envelope.

## First implementation wave

The kickoff session should own a narrow compiled vertical slice:

1. WS-0 documentation reconciliation.
2. WS-1 backend identity and minimal portable protocol skeleton.
3. WS-2 reproducible QEMU-Wasm/browser capability spike.
4. Enough WS-3 to boot the existing `mvm` kernel/rootfs and stream serial.
5. Tests, build recipes, measurements, and an updated plan.

It should not attempt the full workbench, builder, OCI matrix, network relay, or
`mvmd` deployment client in the first change.

## Required validation by phase

At minimum, use the repository's current equivalents of:

```text
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo nextest run --workspace
cargo test --doc --workspace
cargo run -p xtask -- check-declared-backing --self-test
cargo run -p xtask -- check-declared-backing
cargo run -p xtask -- check-no-string-backend-dispatch
cargo run -p xtask -- check-stubs
wasm32-unknown-unknown contract build/tests
browser unit tests
Playwright/headless-Chromium WebLinux E2E
approved Nix builder path for QEMU-Wasm/runtime-pack outputs
```

Do not claim a gate passed unless its command actually ran successfully in the
current checkout.

## Principal risks

| Risk                                                 | Required response                                                                                                                        |
| ---------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| QEMU-Wasm memory is too high for a useful IDE        | Keep WS-2 as a real stop/re-scope gate; test smaller guest profiles, TCG cache bounds, or narrower supported workloads before proceeding |
| Browser block I/O corrupts guest filesystems         | Make flush/crash tests merge gates; use single-writer leases and disk-only recovery before memory snapshots                              |
| Portable DTO extraction destabilizes native backends | Add adapters and golden behavior tests; move pure data before changing behavior                                                          |
| Browser networking becomes a second policy path      | Reuse ADR-042 logical flow service and canonical policy; make transport limitations capabilities                                         |
| Workbench XSS or extension compromise owns the guest | Separate origins, strict CSP, extension placement/trust, narrow MessagePorts, no broad authenticated fetch capability                    |
| Local artifact keys are stolen from OPFS             | Encrypt/wrap long-lived keys, support ephemeral dev identity, exclude production secrets, make trust policy explicit                     |
| `.mvmpkg` changes break deployed tooling             | Version schema, retain old readers, separate combined offline archive from CAS distribution                                              |
| `mvm deploy` grows into a cloud control plane        | Keep one client contract; no provider registry, placement, scheduler, billing, or proprietary server implementation                      |
| Browser implementation weakens native goals          | Feature-gate engine dependencies and run native dependency/performance regression checks                                                 |
| Experimental fork becomes unmaintainable             | Pin patch series, publish source, automate rebase/CVE review, version engine ABI                                                         |

## Deliberate non-goals

- Hardware-isolation or remote-attestation claims for WebLinux.
- Production launch initiated by the local browser or CLI.
- `mvmd` server implementation in this repository.
- Provider registry or production backend placement in `mvm`.
- Docker daemon, Docker-in-Docker, or nested KVM in the browser guest.
- Live migration of browser VM memory to another backend.
- Simultaneous multi-writer workspace synchronization.
- Multiple active browser Linux VMs in v1.
- Mobile browser support in v1.
- Full Safari/Firefox support before conformance.
- GPU/device passthrough.
- Memory snapshots before disk persistence and engine-ABI compatibility are
  mature.
- Replacing the direct-WASI backend.
