# Plan 144 — `wasm-sandbox` backend (portable browser/WASM sandbox)

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:executing-plans /
> subagent-driven-development. Checkbox (`- [ ]`) steps track progress.

**Goal:** Ship an initial `wasm-sandbox` backend — a portable, honest
sandbox/demo backend for browser-like and WASI-like environments. It runs a
simple workload against an in-memory virtual filesystem, captures stdout,
supports logical snapshot/restore, and is selectable from the CLI as
`--hypervisor wasm-sandbox` (alias `browser`). It MUST NOT claim real microVM
isolation: it reports `kvm=false`, `real_linux_kernel=false`,
`tap_networking=false`, `virtio=false`, `vsock=false`, and fails closed with an
explicit error when a microVM-only feature (kernel image, TAP, vsock, block
passthrough, host mount) is requested.

**Architecture / framing:** mvm already separates *what to run* from *how to
isolate it*. The isolation seam is `VmBackend`
(`crates/mvm-core/src/protocol/vm_backend.rs`), dispatched through `AnyBackend`
(`crates/mvm-backend/src/backend.rs`) and described by the `MicrovmBackend` +
`BackendCompat` matrix (`crates/mvm-backend/src/compat.rs`). This plan adds one
more `VmBackend` impl and one `BackendCompat` row — no new trait, no rewrite of
the existing backends. The honest capability matrix is a *new* declarative
`BackendCapabilities` descriptor, distinct from the 5-field runtime
`VmCapabilities`, surfaced through a new `mvmctl backend capabilities` command.
The control plane reuses the `VsockTransport` seam
(`crates/mvm/src/vsock_transport.rs`) with an in-memory shim; vsock-only
transports are rejected.

**Dependency / sequencing (this is a follow-up to the rearchitecture):**
- Prerequisite: **Plan 120** green — `core_demo_e2e` is the regression guard the
  whole Stage C line gates on.
- Prerequisite: **Plan 121** landed — crate consolidation, the 17-crate names are
  frozen (the wasm backend lands in the frozen `mvm-backend` home).
- Prerequisite: **Plan 134** landed — `GuestArch` / `KernelFormat` /
  `BackendCompat` / `ArtifactManifest` are the seam this backend plugs a row into.
- Trait contracts: **ADR-066** (target architecture; `VmBackend` seam is locked).
- Companion: **ADR-069** (this backend's security boundary + honest-capability
  posture). Authored in the same change.

This plan runs **after** 120/121/134 land — it must not perturb the
rearchitecture's regression guard.

**Tech stack:** Rust (existing workspace), serde + `toml` (existing), no new
heavy deps in slice 1 (see "Considered and rejected": `wasmtime` is deferred).

**Out of scope / deferred:**
- Real WASI/WASM execution (wasmtime, WASI preview). Slice 1 runs a *mocked
  command workload* — see "deferred follow-ups".
- Real browser/worker `MessageChannel` and `websocket` transports as live wire
  protocols (the enum variants exist + are validated; only `in_memory` is wired).
- Persisting the virtual fs across host process restarts (snapshot is in-memory
  serialize/restore only).
- Any security claim promotion in ADR-002. The wasm-sandbox is explicitly a
  *non-production* tier; ADR-069 states it provides none of the ADR-002 claims.

---

## Task 1 — Backend identity, selection, honest capabilities *(smallest first commit)*

**Files:**
- Create: `crates/mvm-backend/src/wasm_sandbox/mod.rs` (`WasmSandboxBackend`)
- Create: `crates/mvm-core/src/protocol/backend_caps.rs` (`BackendCapabilities`,
  `NetworkMode`)
- Modify: `crates/mvm-backend/src/backend.rs` (`AnyBackend` variant +
  `from_hypervisor` + `tier` + `inner`)
- Modify: `crates/mvm-backend/src/compat.rs` (`MicrovmBackend::WasmSandbox` +
  `BackendCompat` row)

- [ ] **Step 1 (red):** add `BackendCapabilities` to
  `crates/mvm-core/src/protocol/backend_caps.rs` with the honest fields
  (`hardware_virtualization`, `real_linux_kernel`, `kvm`, `tap_networking`,
  `virtio`, `vsock`, `virtual_filesystem`, `logical_snapshots`,
  `browser_compatible`, `wasi_compatible`, `network_mode: NetworkMode`) + a
  `NetworkMode { ProxyOnly, HostBridged, None }` enum; serde + `Default`. Write a
  serde-roundtrip test and a test asserting the wasm matrix has `kvm=false,
  real_linux_kernel=false, tap_networking=false, virtio=false, vsock=false,
  virtual_filesystem=true, logical_snapshots=true, browser_compatible=true,
  network_mode=ProxyOnly`. `cargo test -p mvm-core backend_caps::` → FAIL.
- [ ] **Step 2 (green):** implement the type; re-run → PASS.
- [ ] **Step 3 (red):** add `MicrovmBackend::WasmSandbox` to the enum in
  `compat.rs` and a `BackendCompat` row: `guest_arches: &[]` (no real arch),
  `kernel_formats: &[]` (accepts no kernel format), `rootfs_formats: &[]`,
  `required_boot_args: &[]`, `supports_snapshots: true` (logical),
  `supports_jailer: false`, `networking: NetworkingModel::ProxyOnly` (add this
  variant if absent). Add a test that `compat(MicrovmBackend::WasmSandbox)` has an
  empty `kernel_formats`. FAIL.
- [ ] **Step 4 (green):** create `WasmSandboxBackend` implementing `VmBackend`
  with `name() == "wasm-sandbox"`, `capabilities()` returning the all-false
  microVM `VmCapabilities` (`pause_resume:false, snapshots:true, vsock:false,
  tap_networking:false, balloon:false`), plus a `fn honest_capabilities(&self) ->
  BackendCapabilities` returning the matrix from Step 1. Stub `start/stop/...` to
  the typed errors landed in Task 2 (temporarily `unimplemented!`-free: return
  `WasmSandboxError::NotYetImplemented`). Add `AnyBackend::WasmSandbox` +
  `from_hypervisor("wasm-sandbox" | "browser")` + `tier()` (a new
  `BackendTier::PortableSandbox`, *not* a microVM tier) + `inner()`. FAIL→PASS.
- [ ] **Step 5 (guard):** unit test `from_hypervisor("browser")` and
  `from_hypervisor("wasm-sandbox")` both resolve to the wasm variant; test
  `auto_select()` NEVER returns wasm (it is opt-in only). `cargo test -p
  mvm-backend` PASS.
- [ ] **Step 6:** commit.

## Task 2 — Typed errors: fail closed on microVM-only features

**Files:**
- Create: `crates/mvm-backend/src/wasm_sandbox/error.rs` (`WasmSandboxError`)

- [ ] **Step 1 (red):** define `WasmSandboxError` (thiserror) with variants:
  `KernelImageUnsupported`, `TapNetworkingUnsupported`, `VsockUnsupported`,
  `BlockPassthroughUnsupported`, `HostMountUnsupported`, `NotYetImplemented`.
  Each message is explicit and points at the alternative, e.g.
  `"the wasm-sandbox backend cannot provide real vsock. Use control_plane =
  \"in_memory\" / \"websocket\" or choose a host-virtualization backend"`. Tests
  assert each `Display` string contains the alternative phrase.
- [ ] **Step 2 (green):** in `WasmSandboxBackend::start`, inspect the incoming
  `VmStartConfig` (`crates/mvm-core/src/protocol/vm_backend.rs`): if
  `kernel_path.is_some()` → `KernelImageUnsupported`; if any volume requests a
  raw block device / host mount → the matching error; if the resolved transport
  is vsock → `VsockUnsupported`. Map to `anyhow::Error` at the `VmBackend`
  boundary so the CLI prints them. Tests: a `VmStartConfig` with `kernel_path`
  set is rejected with the kernel message.
- [ ] **Step 3 (guard):** validator parity — extend the `compat.rs`
  static-validator path so an artifact carrying a non-empty `kernel_formats`
  requirement for `WasmSandbox` is rejected via
  `ArtifactError::IncompatibleKernelFormat`
  (`crates/mvm-backend/src/artifacts/traits.rs`). Test the rejection.
- [ ] **Step 4:** commit.

## Task 3 — Virtual filesystem (`VirtualFs`) + logical snapshot/restore

**Files:**
- Create: `crates/mvm-backend/src/wasm_sandbox/vfs.rs`

- [ ] **Step 1 (red):** define `VirtualFs` trait (`read`, `write`, `exists`,
  `list -> Vec<VirtualDirEntry>`, `snapshot -> Vec<u8>`, `restore(&[u8])`) and an
  in-memory `MemFs` impl backed by `BTreeMap<String, Vec<u8>>`. Snapshot
  serializes via serde (prefer an in-tree codec — `serde_json` bytes — to avoid a
  new dependency). Tests: write→read roundtrip, `exists`, `list` of a dir
  prefix, missing-path error, snapshot→mutate→restore reproduces the
  pre-mutation state byte-for-byte. FAIL.
- [ ] **Step 2 (green):** implement `MemFs`; re-run → PASS.
- [ ] **Step 3 (guard):** tamper test — a truncated/garbled snapshot blob is
  rejected by `restore` with a typed error, not a panic.
- [ ] **Step 4:** commit.

## Task 4 — Workload lifecycle (mocked command runner)

**Files:**
- Create: `crates/mvm-backend/src/wasm_sandbox/runner.rs`

- [ ] **Step 1 (red):** define the lifecycle over the `VmBackend` surface:
  `start` materializes a `WasmInstance { id, vfs: MemFs, status, stdout }`,
  registered in an in-process registry keyed by `VmId`. The mocked runner
  executes a deterministic "command workload": writes a line to stdout, writes a
  file into the vfs, and exits with code 0. `status()` transitions
  `Starting → Running → Stopped`. `logs()` returns captured stdout. `stop()`
  marks `Stopped`. Tests cover the full transition sequence + stdout capture +
  the vfs side effect. FAIL.
- [ ] **Step 2 (green):** implement the registry + runner; re-run → PASS.
- [ ] **Step 3 (red):** logical snapshot of a running instance =
  `vfs.snapshot()` + status; `restore` rebuilds an instance from the blob. Test
  snapshot→restore yields an instance whose vfs matches. FAIL→green.
- [ ] **Step 4 (guard):** assert the runner NEVER shells out to the host / spawns
  a process / touches a real path outside a tempdir — a test that runs the
  workload and asserts no host-side artifact is created.
- [ ] **Step 5:** commit.

## Task 5 — Control-plane shim selection

**Files:**
- Create: `crates/mvm-backend/src/wasm_sandbox/control.rs`
- Reference: `crates/mvm/src/vsock_transport.rs` (`VsockTransport` seam)

- [ ] **Step 1 (red):** add a `ControlPlane` enum `{ Vsock, Websocket,
  MessageChannel, InMemory, Stdio }` with serde. The wasm backend's
  `select_control_plane(requested)` accepts only `Websocket | MessageChannel |
  InMemory`; `Vsock` → `WasmSandboxError::VsockUnsupported`; others map to a
  clear error. In slice 1 only `InMemory` is *wired* (an in-process channel
  implementing the transport role); `Websocket`/`MessageChannel` validate-and-
  accept but return `NotYetImplemented` on connect. Tests: vsock rejected,
  in_memory selected, websocket accepted-but-not-wired. FAIL.
- [ ] **Step 2 (green):** implement; re-run → PASS.
- [ ] **Step 3:** commit.

## Task 6 — Config support

**Files:**
- Modify: `crates/mvm-core/src/user_config.rs` (`MvmConfig`)

- [ ] **Step 1 (red):** add a `[backend.wasm_sandbox]` (or `[target.browser]`,
  matching the existing `[security]` nesting style) section parsed into a
  `WasmSandboxConfig { network: NetworkMode, filesystem: FsMode, control_plane:
  ControlPlane, snapshots: SnapshotMode }`. `#[serde(default)]` so existing
  configs keep parsing. Tests: a TOML snippet parses; an unknown/unsupported
  combination (e.g. `control_plane = "vsock"`) is rejected at load with a clear
  message; absent section → sane defaults (proxy-only, virtual, in_memory,
  logical). FAIL.
- [ ] **Step 2 (green):** implement; re-run → PASS.
- [ ] **Step 3:** commit.

## Task 7 — CLI: `backend capabilities` + `--hypervisor wasm-sandbox`

**Files:**
- Create: `crates/mvm-cli/src/commands/ops/backend.rs`
- Modify: `crates/mvm-cli/src/commands/mod.rs` (`Commands` enum + dispatch)

- [ ] **Step 1 (red):** add a `Backend(ops::backend::Args)` subcommand with a
  `Capabilities { name: String, #[arg(long)] json: bool }` variant. `mvmctl
  backend capabilities wasm-sandbox` prints the `BackendCapabilities` matrix
  (human + `--json`). Clap-parse unit tests in
  `crates/mvm-cli/src/commands/tests.rs` (mirror the existing `test_cleanup_*`
  pattern). FAIL.
- [ ] **Step 2 (green):** implement `run()`; resolve the named backend via
  `AnyBackend::from_hypervisor`, print `honest_capabilities()`. Re-run → PASS.
- [ ] **Step 3 (guard):** integration assertion in `tests/cli.rs` — the help text
  lists `wasm-sandbox`/`browser` as accepted `--hypervisor` values and `backend
  capabilities wasm-sandbox` exits 0 and reports `kvm: false`, `vsock: false`.
- [ ] **Step 4:** confirm `mvmctl run --hypervisor wasm-sandbox
  examples/hello-wasm` reaches the wasm backend and (slice 1) runs the mocked
  workload to completion with captured stdout. Commit.

## Task 8 — `examples/hello-wasm/` + docs

**Files:**
- Create: `examples/hello-wasm/` (minimal workload manifest the mocked runner
  accepts; a README stating it is a sandbox demo, not a microVM)
- Modify: `public/src/content/docs/reference/cli-commands.md` (document `backend
  capabilities` + the `wasm-sandbox`/`browser` selector and its honest limits)

- [ ] **Step 1:** add the example + doc note. The doc explicitly states the
  backend provides no ADR-002 security claims and links ADR-069.
- [ ] **Step 2:** commit.

## Task 9 — ADR-069 (security boundary) + deferred follow-ups

**Files:**
- Create: `specs/adrs/069-wasm-sandbox-backend.md` (authored alongside this plan)

- [ ] **Step 1:** confirm ADR-069 records: why this is NOT a real microVM
  backend; what it does/doesn't guarantee; how it differs from
  Firecracker/Vz/Cloud Hypervisor; intended uses (browser demo, docs playground,
  deterministic repros, lightweight plugin sandbox, offline-ish dev) and explicit
  non-uses (production tenant isolation, untrusted multi-tenant compute, real
  kernel/network testing). States it sits *outside* the ADR-002 claim set.
- [ ] **Step 2:** keep the `### deferred follow-ups` section below current as
  slices land.
- [ ] **Step 3:** commit.

### deferred follow-ups

- [ ] Real WASI execution via `wasmtime` (WASI preview), replacing the mocked
  command runner — gated behind a dependency-budget review.
- [ ] Live `websocket` and `MessageChannel` control-plane transports (browser /
  worker wire protocols), beyond the slice-1 `in_memory` shim.
- [ ] A `wasm32-*` build target so the backend ships as an actual browser bundle.
- [ ] Persist the virtual filesystem across host process restarts (today
  snapshot/restore is in-memory only).

## Acceptance (Plan 144 is done when)

- [ ] `mvmctl --hypervisor wasm-sandbox …` (and `browser`) selects the backend.
- [ ] `mvmctl backend capabilities wasm-sandbox` reports `kvm:false`,
  `real_linux_kernel:false`, `tap_networking:false`, `virtio:false`,
  `vsock:false`, `virtual_filesystem:true`, `logical_snapshots:true`,
  `network_mode:ProxyOnly`.
- [ ] Requesting a kernel image / TAP / vsock / block passthrough / host mount
  fails with an explicit typed error naming the alternative.
- [ ] A simple workload starts, emits stdout, stops, and reports status.
- [ ] The virtual filesystem round-trips read/write/list and snapshot→restore.
- [ ] `auto_select()` never returns wasm-sandbox (opt-in only).
- [ ] ADR-069 exists and states the backend provides none of the ADR-002 claims.
- [ ] `just lint` + `cargo test --workspace` green; no new heavy dependency added.

## Considered and rejected

| Option | Verdict |
|---|---|
| Bundle `wasmtime` + WASI in slice 1 | Rejected for now — violates "limit dependencies"; a mocked runner proves the API. Tracked as a deferred follow-up. |
| Extend the 5-field `VmCapabilities` with the honest matrix | Rejected — would touch all 8 backends' runtime gate. A separate declarative `BackendCapabilities` is additive and honest. |
| Let `auto_select()` consider wasm-sandbox | Rejected — it is a demo/non-prod tier; must be explicit opt-in only. |
| A parallel control-plane system | Rejected — extend the existing `VsockTransport` seam + a `ControlPlane` enum instead. |
| New crate `mvm-wasm-sandbox` | Rejected for slice 1 — lands as a module under the (frozen, post-Plan-121) `mvm-backend` home; promote to a crate only if it grows. |

## Self-review

Real symbols only — every path/type below was read during research:
`VmBackend`/`VmCapabilities`/`VmStartConfig` (`mvm-core/src/protocol/vm_backend.rs`),
`AnyBackend`/`from_hypervisor`/`tier`/`inner` (`mvm-backend/src/backend.rs`),
`MicrovmBackend`/`BackendCompat`/`NetworkingModel` (`mvm-backend/src/compat.rs`),
`ArtifactError` (`mvm-backend/src/artifacts/traits.rs`),
`GuestArch`/`KernelFormat` (`mvm-core/src/arch.rs`, `mvm-core/src/kernel_format.rs`),
`VsockTransport` (`mvm/src/vsock_transport.rs`), `MvmConfig`
(`mvm-core/src/user_config.rs`), CLI `Commands` (`mvm-cli/src/commands/mod.rs`),
Clap-parse tests (`mvm-cli/src/commands/tests.rs`). `NetworkingModel::ProxyOnly`
and `BackendTier::PortableSandbox` are NEW variants this plan adds (flagged as
such in Tasks 1/3).
