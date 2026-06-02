# Plan 125 — CLI surface + SDK derivation engine + the imperative DX

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the surface usable. Collapse the **52 flat `mvmctl` verbs** into a `≤15`-group nested tree; keep the SDK as the one derivation engine (the four authoring surfaces → one Workload IR → one build); and finish the win-on-DX work — the imperative one-call `Sandbox` (the existing class), typed helpers, async + sync, copy/ports, and Node parity. Production lens throughout: live-exec is dev-tier; prod is the signed-`ExecutionPlan` path.

**Architecture:** The CLI is a thin shell over the libraries (ADR-066 §1: "no logic in `mvm-cli`"). Today it has 52 top-level commands (`Artifact`, `Attest`, `Audit`, `Bench`, … `Volume`, `Wait`); this groups them. The SDK already has the four surfaces (decorator, runtime/record, `mvm.toml`, flake) and the dual-mode `Sandbox` (`sdks/python/mvm/_sandbox.py`: `start`, `commands`, record-mode, `SandboxDevOnly`); this plan completes the imperative ergonomics on top and mirrors them in TS. **The data types + the RPC client surface are generated** from the one schema (124 Phase D, `xtask gen-sdk` → `sdks/*/_generated/`), so this plan's SDK work is the **thin idiomatic veneer over that generated core** (the `Sandbox` mode logic, the decorator hooks, the typed helpers) — ergonomics improve without re-introducing drift. The `--secret` binding ties to 129; the per-backend tradeoff table ties to 123's `snapshot_capability`.

**Tech Stack:** Rust/clap (`mvm-cli`), `mvm-sdk` (Python via PyO3, TS via napi), the existing `Sandbox`. No new third-party crates.

**Prereqs:** 121 (the `mvm-cli`/`mvm-sdk` homes), 120 (the minimal `Sandbox.exec` headline — this completes it). Ties to 129 (`--secret`) and 123 (`doctor` capability table).

**Constraint:** no back-compat shims (first version — hard rename). The 52→nested move is a clean break; the most-used verbs stay reachable as real top-level entries, not alias stubs.

---

## Phase A — CLI: 52 flat verbs → `≤15` nested groups

### Task A1: design the nested tree + the old→new map

**Files:** `crates/mvm-cli/src/commands/mod.rs` (the `Commands` enum); `tests/cli.rs`.

- [ ] **Step 1:** Audit the 52 and group them. Proposed ≤15 top-level groups (each a clap subcommand enum):
  - `sandbox` — run, up, exec, console, invoke, ls, logs, pause, resume, snapshot, wait, down, set-ttl, forward, cp, proc, fs (the VM lifecycle + interaction — the bulk)
  - `image` — pull, build, compile, catalog, diff
  - `secret` — set, ls, rm (129)
  - `dev` — up, down, shell, status
  - `volume` — create, ls, snapshot, rm (storage 123)
  - `network` — create, ls, rm, forward (123)
  - `trust` — attest, audit, bundle, receipt, manifest, validate, verify (provenance/claims)
  - `deps` — inspect, audit (claim 11)
  - `doctor` — (folds bench, metrics, boot-report as `doctor --bench` / sub-flags)
  - `config` — init, bootstrap, update, uninstall, shell-init, cache, cleanup
  - `mcp` — serve
  - keep top-level conveniences (real verbs, not shims): `run`, `up`, `exec` — the 90%-of-use path stays one token deep.
- [ ] **Step 2:** Write the old→new table (all 52) into the plan/docs; it's the migration map + the CHANGELOG entry.

### Task A2: implement the nested tree

- [ ] **Step 1:** Failing `tests/cli.rs` cases — `mvmctl sandbox run --help`, `mvmctl secret set --help`, `mvmctl trust audit --help` parse; the removed flat verbs (`mvmctl attest`) error with a clap "did you mean `trust attest`" (clap's suggestion, not a hand-written shim).
- [ ] **Step 2:** Restructure `Commands` into the group enums; move each verb's `run()` under its group (the command *modules* don't move, only the clap wiring). Update `tests/cli.rs` help-text assertions. `cargo test -p mvm-cli` green.
- [ ] **Step 3:** Update `public/.../reference/cli-commands.md` in the same commit (ADR-066 §9: docs change with the CLI). Commit.

## Phase B — the imperative `Sandbox` (complete the DX)

120 shipped the minimal `Sandbox.exec`. Finish the surface on the same class.

**Files:** `sdks/python/mvm/_sandbox.py`; tests `sdks/python/tests/`.

- [ ] **Task B1 — copy + ports.** Failing tests: `sb.copy_in(host, guest)` / `sb.copy_out(guest, host)` round-trip a file (over the agent `fs_rpc`); `sb.forward(host_port, guest_port)` exposes a port. Implement over the existing fs/forward RPC. Commit.
- [ ] **Task B2 — async surface.** Failing test: `async with Sandbox.create(image=…) as sb: r = await sb.exec(...)` works; the sync surface (greenlet or thread-bridged) stays for `Sandbox.create(...).exec(...)`. Implement `__aenter__`/`__aexit__` + `async def exec` alongside the sync ones (one impl, two faces). Keep `SandboxDevOnly` on both. Commit.
- [ ] **Task B3 — lifecycle polish.** `info()`, `id`, context-manager teardown, the one-live-process invariant (already in `_sandbox.py`). Tests for double-create refusal + clean teardown. Commit.

## Phase C — typed helpers

Thin wrappers over `Sandbox`; big perceived surface, small code.

**Files:** `sdks/python/mvm/{_code.py,_browser.py}` (new), re-exported from `mvm`.

- [ ] **Task C1 — code-runner.** `CodeSandbox(image="python:slim")` with `run(code)->stdout`, `run_script(path)`, `install_package(pkg)`. Failing test: `run("print(2+2)")=="4"`. Implement over `Sandbox.exec`. Commit.
- [ ] **Task C2 — browser/desktop presets.** `BrowserSandbox(browser="chromium")` = a `Sandbox` with a baked browser image + a forwarded CDP port + an `endpoint()` returning the ws URL. Just image + port presets; no new mechanism. Failing test: `endpoint()` returns a reachable URL (gated). Commit.

## Phase D — Node / TS parity

**Files:** `sdks/typescript/` — mirror `Sandbox` + the helpers.

- [ ] **Task D1:** Failing test (TS) — `const sb = await Sandbox.create({image}); const r = await sb.exec("python","-c","print(2+2)")` returns `{stdout:"4\n",exitCode:0}`. Implement against the same protocol (Phase-124 codegen makes the client match the agent). Commit. (Go / C are scope calls — note them deferred, don't stub.)

## Phase E — cross-cutting CLI/SDK polish

- [ ] **Task E1 — four surfaces, one IR (coherence).** Failing test — the *same* hello-app expressed as decorator, runtime-record, `mvm.toml`, and flake all lower to an equal `Workload` IR (canonicalized). This is the "one derivation engine" guarantee made testable. Commit.
- [ ] **Task E2 — `--secret NAME:host`.** The terse CLI binding from 129: `mvmctl run … --secret openai:api.openai.com` adds a `SecretRef`. Failing test parses it to `{name:"openai", allowed_hosts:["api.openai.com"], auth_type:bearer-default}`. Commit. (Implementation of the substitution is 129; this is the CLI surface.)
- [ ] **Task E3 — `doctor` capability table.** Surface 123's per-backend `snapshot_capability` + the network/storage/mount disposition + the boot-latency tier as a table (`doctor` already reports the builder backend — extend it). Failing test on the table rows. Commit.
- [ ] **Task E4 — named security profiles.** `--profile <name>` selects a named capability matrix over the seams (seccomp tier, egress posture, snapshot allowance). Failing test: a profile resolves to the expected per-seam dispositions; an unknown profile errors. Commit.

- [ ] **Task E5 — host-services SDK surface (the workload calls the broker).** The host exposes broker services over vsock — **`host.audit.v1`** (workload-emitted audit entries: the handler forces `category: workload_audit`, stamps the host-authoritative IDs, rate/size-caps, and chain-signs via `mvm-audit-signer` — claim 8 preserved), plus `host.time.v1` / `host.cost.v1`. **The host side is built (Plan 104); the workload-facing client + ergonomic is the gap** (no guest-side broker caller exists in `mvm-guest`/`mvm-sdk` today). Failing test — `mvm.audit.emit({...})` from inside a `Sandbox` lands a `workload_audit` entry in the chain (`mvmctl audit verify` shows it, marked workload-originated + host-stamped); a >4 KiB record is refused (`BadRequest`); the 20/s rate limit trips; a workload can **never** write a host-category entry (the handler forces `workload_audit`). Implement in three layers: **(1) the guest-side broker client** — the SDK-runtime transport that opens the broker's vsock UDS, frames the `ServiceCall` envelope over `core::framing`'s authenticated frame, and carries the plan-bound session (claim 12). **None exists today** (`mvm-guest`/`mvm-sdk` have no broker caller) — this is the foundational piece all broker services ride on. Lives in `mvm-sdk`'s runtime (exposed to Python/TS via PyO3/napi). **(2) the typed service methods** — generated from 124 D's `gen-sdk` (`host.audit.v1`/`host.time.v1`/`host.cost.v1`), sitting on the transport. **(3) the SDK veneer** — `mvm.audit.emit/emit_batch`, `mvm.host.time()`, `mvm.host.cost()`. Binding-gated dispatch + no-payload-in-errors are gated in 128 (claims 12/13). Commit.

## Acceptance

- [ ] A workload can append to the chain-signed audit log via `mvm.audit.emit` (`host.audit.v1`); the entry is `workload_audit`-categorized, host-stamped, and visible in `mvmctl audit verify`; oversize/rate-limit refused; no host-category spoofing.
- [ ] `mvmctl` is `≤15` top-level groups; all 52 old verbs reachable via the nested tree (the old→new map is in the docs); `tests/cli.rs` + the CLI reference doc updated; no alias shims.
- [ ] `Sandbox` has the full imperative surface — `create`/`exec`/`copy_in`/`copy_out`/`forward`/`info`, **async and sync**, dev-tier-gated (`SandboxDevOnly` in prod); the quickstart leads with it.
- [ ] Typed helpers (code-runner, browser preset) work over `Sandbox`; TS `Sandbox` reaches parity on `create`/`exec`.
- [ ] The four authoring surfaces lower to an equal canonical `Workload` IR (coherence test).
- [ ] `--secret NAME:host` parses to a `SecretRef`; `doctor` shows the per-backend capability table; `--profile` selects a named matrix.
- [ ] `cargo test --workspace` + the SDK test suites + clippy + fmt green; no new dependency.

### deferred follow-ups

- [ ] Go / C SDK parity (scope call).
- [ ] Desktop/interactive-terminal helpers beyond the browser preset.

## Self-review

- **Spec coverage (brief 125):** ≤15 nested CLI (Phase A), 4-surfaces→1-IR (E1), `--secret NAME:host` (E2), per-backend tradeoff table (E3), named-profile UX (E4); the win-on-DX surface — imperative `Sandbox` + async/sync + copy/ports (Phase B), typed helpers (Phase C), Node parity (Phase D). All present.
- **Grounding:** the 52-verb count is real (`commands/mod.rs`); `Sandbox` already exists with `start`/`commands`/`SandboxDevOnly` (`_sandbox.py`) — B completes, doesn't rebuild. The coherence test (E1) makes the "one engine" claim falsifiable.
- **Production lens:** dev-tier gating on the imperative surface restated (B2); prod stays signed-plan.
- **Voice:** comments mark the non-obvious (why one impl backs both async/sync faces, why clap's own suggestion replaces a shim), not the calls.
