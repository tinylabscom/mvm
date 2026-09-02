# Plan 329: Browser-tier `BrowserWasiBackend` demo

## Status

**In progress.** Core browser-tier backend implemented and E2E-green; remote node bridge (Slice 5) remains open. Implements a browser-tier backend that conforms to the same
`VmBackend` contract the host uses, so the `/demo` page can "launch a microVM"
inside a WebAssembly container with constraints defined by mvm.

Companion to [Plan 320](320-wasm-browser-demo.md) (shipped governance demo) and
[ADR-024](../adrs/024-wasm-sandbox-backend.md). Adds no numbered security claim.

## Context

The existing `/demo` page (Plan 320) exercises the governance seam from
`mvm-contract`: it parses a `NetworkPolicy`, canonicalizes it, decides egress,
substitutes placeholders, and signs audit entries. What it does **not** do is
present a coherent VM lifecycle: there is no `VmStartConfig`, no boot sequence,
no console, and no workload that the visitor controls.

We already have a `VmBackend` trait in
`crates/mvm-core/src/protocol/vm_backend.rs` and a host `WasmBackend` in
`crates/mvm-runtime/src/wasm_backend.rs`. The browser cannot run host
`wasmtime`, but it can implement the same trait *semantics* using the browser's
own WebAssembly runtime plus a WASI Preview 1 host shim.

## Goal

Make `/demo` feel like a developer launching their own microVM from the
browser:

1. The visitor edits a workload manifest (`VmStartConfig` subset), a
   `NetworkPolicy`, and an authority/public key.
2. They click **Launch microVM**.
3. The browser validates admission using `mvm-contract`, instantiates a
   `wasm32-wasip1` guest, prints a boot sequence to a console, and drops to a
   shell prompt.
4. Every command the guest runs is subject to mvm-defined constraints:
   filesystem isolation, network allow/deny, secret binding, and audit.
5. If a remote mvm node is configured, the same UI can delegate the launch to
   real hardware; otherwise the browser-tier backend is the default.

The page must be honest: *“Browser-tier microVM — same admission and policy as
mvm, running in a WebAssembly sandbox instead of a hardware hypervisor.”*

## Non-goals

- Do not claim this is a hardware-virtualized microVM.
- Do not run KVM/HVF/libkrun/Firecracker inside the browser tab.
- Do not add browser-only APIs to the in-workspace `VmBackend` trait; the
trait stays host-focused. The browser backend mirrors its semantics through a
wasm-bindgen shim.
- Do not implement warm start, snapshots, pause/resume, balloon, or virtio
for the browser tier.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  Browser page  /demo                                             │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  UI: VmStartConfig form, policy editor, authority key     │  │
│  │  Console: boot output + interactive shell                 │  │
│  └───────────────────────────────────────────────────────────┘  │
│                         │                                       │
│  ┌──────────────────────▼────────────────────────────────────┐  │
│  │  Web Worker                                                │  │
│  │  ┌────────────────────┐  ┌──────────────────────────────┐ │  │
│  │  │ mvm-demo core      │  │ BrowserWasiBackend state     │ │  │
│  │  │ (wasm-bindgen)     │  │ • VmId → instance map        │ │  │
│  │  │ • mvm-contract     │  │ • virtual rootfs (MemFS)     │ │  │
│  │  │ • policy decision  │  │ • console ring buffer        │ │  │
│  │  │ • audit signing    │  │ • mvm:egress host import     │ │  │
│  │  └────────────────────┘  └──────────────────────────────┘ │  │
│  └──────────────────────┬─────────────────────────────────────┘  │
│                         │                                         │
│  ┌──────────────────────▼────────────────────────────────────┐  │
│  │  WASM engine (browser native)                              │  │
│  │  ┌──────────────────────────────────────────────────────┐ │  │
│  │  │ web/mvm-demo-guest (wasm32-wasip1)                   │ │  │
│  │  │ • init: print boot messages, mount /etc/policy       │ │  │
│  │  │ • shell: ls, cat, echo, fetch, exit                  │ │  │
│  │  │ • fetch calls mvm:egress host import                 │ │  │
│  │  └──────────────────────────────────────────────────────┘ │  │
│  └────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### Mapping to `VmBackend`

The browser backend is not a literal `impl VmBackend` (the trait requires
`Send + Sync` and `anyhow`, neither of which compile to wasm32-unknown-unknown
via wasm-bindgen). Instead, the Worker implements the same semantic surface:

| `VmBackend` method | Browser-tier behavior |
|---|---|
| `name()` | `"browser-wasm"` |
| `kind()` | `BackendKind::Wasm` |
| `capabilities()` | Same as host `WasmBackend`: `kernel_boot: false`, `vsock: false`, `tap: false`, `verified_boot: false`, `snapshot: None`, `pause_resume: false`, `balloon: false`, `cpu_fuel: true` only. |
| `security_profile()` | Claim-free / Tier 3, same honest profile as host `WasmBackend`. |
| `start_with_mode(config, mode)` | Validate `VmStartConfig` with `mvm-contract`; instantiate guest; return `VmId`. |
| `stop(id)` / `stop_all()` | Drop the `WebAssembly.Instance` and free the virtual FS. |
| `status(id)` | `Running` / `Stopped` / `Exited(code)`. |
| `logs(id, lines, hypervisor)` | Return guest console ring buffer; hypervisor logs are synthetic. |
| `guest_channel_info(id)` | Return the Worker MessageChannel port used for stdin/stdout. |
| `network_info(id)` | Error — browser-tier has no NIC. |

### Policy enforcement

The browser host intercepts every guest egress attempt:

1. Guest calls `mvm:egress(host, port, body)`.
2. Host parses `VmStartConfig.network_policy` with `mvm-contract`.
3. Host canonicalizes against demo DNS pins.
4. `CanonicalEgress::permits(&Proto::Tcp, ip, port)` decides allow/deny.
5. If denied, return `EACCES` and emit a deny audit entry.
6. If allowed, perform `fetch()` with placeholder substitution, return response,
   emit an allow audit entry.

Filesystem isolation is enforced by the WASI host: preopened directories are
virtual (`/etc`, `/bin`, `/tmp` backed by in-memory maps), and absolute paths
outside the guest root are rejected.

## Implementation plan

### Slice 0 — Decision: WASI host strategy

- [x] **0.1** Evaluate `@wasmer/wasi` vs `jco` vs a custom minimal WASI host for
      the browser.
  - Criteria: bundle size, maintenance burden, WASI preview 1 coverage needed,
    ability to inject custom imports (`mvm:egress`), license compatibility.
  - Decision record in this plan file.
- [x] **0.2** Prototype guest `fd_write` + `proc_exit` through the chosen host in
      a throwaway script; confirm it runs in the Worker.

### Slice 1 — Guest workload: `web/mvm-demo-guest`

- [x] **1.1** Create `web/mvm-demo-guest/Cargo.toml` as a workspace-excluded
      `wasm32-wasip1` binary crate.
  - No `wasm-bindgen`; this is a plain WASI command.
  - `#![no_main]` with `fn main(args: &[&str])` style via `wasi` crate.
- [x] **1.2** Implement boot sequence printed to stdout:
  ```
  mvm: loading workload from VmStartConfig
  mvm: mounting virtual rootfs
  mvm: applying NetworkPolicy: allowlist 1 rule(s)
  mvm: starting /bin/init
  ```
- [x] **1.3** Write `/etc/policy` and `/etc/authority` from the host-provided
      preopens at start-up so `cat /etc/policy` works.
- [x] **1.4** Implement minimal shell loop reading stdin line-by-line:
  - `help` — list commands.
  - `ls [path]` — list virtual files.
  - `cat <path>` — read a virtual file.
  - `echo <text>` — print text.
  - `fetch <host> <port>` — call `mvm:egress` host import.
  - `exit` — exit with code 0.
- [x] **1.5** Add unit tests for shell command parsing in the guest crate.
- [x] **1.6** Add a build helper script `web/mvm-demo-guest/build.sh` that
      compiles to `wasm32-wasip1` and runs `wasm-opt -Oz`.

### Slice 2 — Extend `web/mvm-demo` with `BrowserWasiBackend`

- [x] **2.1** Add a new module `src/browser_backend.rs` (compiled into the same
      wasm-bindgen crate) exposing:
  - `BrowserVmState` — map of `VmId` to instance + console buffer + virtual FS.
  - `browser_backend_start(config_json: &str) -> String` (JSON result with
    `vm_id` or `error`).
  - `browser_backend_stop(vm_id: &str) -> String`.
  - `browser_backend_status(vm_id: &str) -> String`.
  - `browser_backend_logs(vm_id: &str, lines: u32) -> String`.
  - `browser_backend_stdin(vm_id: &str, line: &str) -> String`.
- [x] **2.2** Implement `VmStartConfig` JSON parsing/validation using
      `mvm-contract` types:
  - Deserialize `NetworkPolicy`.
  - Validate mandatory-deny ranges never appear in allowlist.
  - Verify `plan_json` signature if an authority key is provided (fail-closed:
    if key given and signature invalid, refuse to start).
- [x] **2.3** Integrate the chosen WASI host to instantiate the guest module:
  - Preopen virtual `/etc`, `/bin`, `/tmp`.
  - Provide `args_get` with `["init", "--policy", <json>]`.
  - Capture stdout/stderr into the console ring buffer.
- [x] **2.4** Implement `mvm:egress` host import:
  - Decode host/port/body from linear memory.
  - Run `decide_egress_core` from existing `mvm-contract` logic.
  - If denied, return WASI error `EACCES` and emit deny audit.
  - If allowed, call `fetch()` via JS promise bridge, substitute placeholder,
    return response bytes.
- [x] **2.5** Emit audit entries for start, stop, allow, deny, and bind-check
      failures, signed with the demo Ed25519 key.
- [ ] **2.6** Add wasm-bindgen tests for the backend lifecycle using
      `wasm-bindgen-test`.

### Slice 3 — Worker and console UI

- [x] **3.1** Rewrite `web/mvm-demo/worker.js` to load the guest module and
      expose a message protocol:
  - `{type: "launch", config_json}` → `{ok, vm_id, error}`
  - `{type: "stdin", vm_id, line}`
  - `{type: "logs", vm_id, lines}` → console output
  - `{type: "stop", vm_id}`
  - Console output streamed as `{type: "console", vm_id, chunk}`.
- [x] **3.2** Rewrite `web/mvm-demo/demo.js` to render:
  - A `VmStartConfig` form (name, memory, cpus, workload image, policy JSON,
    authority pubkey).
  - A terminal-style `<pre>` console with autoscroll.
  - An input prompt `root@mvm:~#` that sends lines to the Worker.
- [x] **3.3** Add keyboard handling: Enter sends line, Ctrl+C sends interrupt,
  Ctrl+L clears screen.
- [x] **3.4** Render the capability notice and security profile on the page,
    pulled from the wasm core.
  - **Follow-up UX pass:** terminal-style console now supports click-to-focus,
    command history (↑/↓), Tab completion, Ctrl+C interrupt, and Ctrl+L
    clear-screen. The guest shell implements a curated Linux-like command set
    (`ls`, `cat`, `cd`, `pwd`, `env`, `ps`, `df`, `free`, `uptime`, `history`,
    etc.) so the demo feels like a real emulated terminal.

### Slice 4 — Build integration

- [x] **4.1** Update `web/mvm-demo/build.sh` to:
  - Build `web/mvm-demo-guest`.
  - Stage `mvm-demo-guest.wasm` into `public/public/demo/guest/`.
  - Keep existing `pkg/` staging.
- [x] **4.2** Update `public/public/.gitignore` to ignore the new `guest/`
      artifacts.
- [x] **4.3** Add a root-level `just` recipe (e.g. `just demo-build`) that runs
      both guest and demo builds in order.
- [x] **4.4** Ensure `pnpm build` in `public/` still succeeds with no console
      errors.

### Slice 5 — Remote node bridge (Tier C, optional but stubbed)

- [ ] **5.1** Add an optional `MVM_DEMO_NODE_URL` env/config to the page.
- [ ] **5.2** When a node URL is present, show a **Launch on hardware**
      secondary button.
- [ ] **5.3** Stub the node protocol: POST `VmStartConfig` JSON, open WebSocket
      for console streaming. Fail gracefully with a helpful message if the node
      is unreachable.
- [ ] **5.4** Keep the browser tier as the default; the remote node is an
      explicit opt-in.

### Slice 6 — Testing

- [x] **6.1** Add a Playwright test that:
  - Opens `/demo`.
  - Launches the browser-tier microVM.
  - Waits for the prompt.
  - Types `cat /etc/policy` and sees the policy JSON.
  - Types `fetch api.openai.com 443` and sees an allow result.
  - Changes policy to deny and retries `fetch`; sees a deny result.
- [x] **6.2** Add a Playwright console scan to the landing page and demo page
      that asserts zero warnings/errors.
- [x] **6.3** Run `pnpm check:tokens`, `pnpm check:samples`, and `cargo clippy`
      on touched crates.

### Slice 7 — Documentation and spec updates

- [x] **7.1** Update this plan with actual decisions from Slice 0.
- [ ] **7.2** Update `specs/SPRINT.md` to reflect the new workstream.
- [ ] **7.3** Update `specs/REFACTOR-STATUS.md` if this plan lands or descopes
      any existing wasm workstream.
- [ ] **7.4** Add a short ADR or note explaining why the browser backend is not
      a literal `impl VmBackend` (trait bounds + wasm-bindgen).
- [x] **7.5** Update the `/demo` page copy to clearly distinguish browser tier
      from hardware tier.

## Testing strategy

- **Unit:** guest shell parsing, policy decision helpers, audit entry
  construction.
- **WASM integration:** `wasm-bindgen-test` for backend start/stop/logs in a
  headless browser environment.
- **E2E:** Playwright drives the real `/demo` page through launch → shell →
  allow → deny.
- **Build:** `just demo-build`, `just docs-build`, and CI `pages.yml` must pass.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| WASI host dependency is heavy or license-incompatible | Decide in Slice 0; prefer a custom minimal host if either issue arises. |
| Guest `.wasm` size balloons | Use `wasm-opt -Oz`, size budget in build script, strip panic messages. |
| Fetch in Web Worker cannot reach some origins | Document that egress is subject to CORS; the policy decision still runs regardless. |
| Remote node bridge becomes a security footgun | Always fail closed; never auto-fallback to remote; require explicit user action. |
| Visitors confuse browser tier with real microVM | Copy, capability notice, and security profile must explicitly say “browser sandbox, no hypervisor.” |

## Definition of done

- `just demo-build` succeeds and produces a working `/demo` page.
- Playwright E2E test launches the browser-tier microVM and exercises allow/deny.
- `cargo clippy` and `pnpm check:*` pass with no warnings.
- The page clearly explains that the browser tier is mvm-defined but not
  hardware-isolated.
