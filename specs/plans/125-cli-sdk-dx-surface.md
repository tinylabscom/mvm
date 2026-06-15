# Plan 125 — CLI surface + SDK derivation engine + the imperative DX

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the surface usable. Collapse the **52 flat `mvmctl` verbs** into a `≤15`-group nested tree; keep the SDK as the one derivation engine (the four authoring surfaces → one Workload IR → one build); and finish the win-on-DX work — the imperative one-call `Sandbox` (the existing class), typed helpers, async + sync, copy/ports, and Node parity. Production lens throughout: live-exec is dev-tier; prod is the signed-`ExecutionPlan` path.

**Architecture:** The CLI is a thin shell over the libraries (ADR-066 §1: "no logic in `mvm-cli`"). Today it has 52 top-level commands (`Artifact`, `Attest`, `Audit`, `Bench`, … `Volume`, `Wait`); this groups them. The SDK already has the four surfaces (decorator, runtime/record, `mvm.toml`, flake) and the dual-mode `Sandbox` (`sdks/python/mvm/_sandbox.py`: `start`, `commands`, record-mode, `SandboxDevOnly`); this plan completes the imperative ergonomics on top and mirrors them in TS. **The data types + the RPC client surface are generated** from the one schema (124 Phase D, `xtask gen-sdk` → `sdks/*/_generated/`), so this plan's SDK work is the **thin idiomatic veneer over that generated core** (the `Sandbox` mode logic, the decorator hooks, the typed helpers) — ergonomics improve without re-introducing drift. The `--secret` binding ties to 129; the per-backend tradeoff table ties to 123's `snapshot_capability`.

**Tech Stack:** Rust/clap (`mvm-cli`), `mvm-sdk` (Python via PyO3, TS via napi), the existing `Sandbox`. No new third-party crates.

**Prereqs:** 121 (the `mvm-cli`/`mvm-sdk` homes), 120 (the minimal `Sandbox.exec` headline — this completes it). Ties to 129 (`--secret`) and 123 (`doctor` capability table).

**Constraint:** no back-compat shims (first version — hard rename). The 52→nested move is a clean break; the most-used verbs stay reachable as real top-level entries, not alias stubs.

> **Priority update 2026-06-15:** Plan 200 is now the product-facing beginner
> CLI owner. Do not prioritize this plan's broad 52→nested CLI regrouping ahead
> of `mvmctl machine run/create/start/exec/shell/stop/pack`. The completed
> `Sandbox` work remains useful substrate; future SDK lifecycle work should
> feed Plan 200's machine wrappers rather than create a competing beginner
> vocabulary.

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

**Files:** `sdks/python/mvm/_sandbox.py` **and `sdks/typescript/src/_sandbox.ts`** (the two SDKs are mirrors and must stay in lockstep — the capability lives in `mvmctl`, both are thin wrappers; build both per task, not Python-then-TS-later).

- [x] **Task B1a — copy (both SDKs).** `sb.copy_in(host, guest)` / `sb.copy_out(guest, host)` (Python) + `sb.copyIn` / `sb.copyOut` (TS) shell `mvmctl cp <host> <vm>:<guest>` / `mvmctl cp <vm>:<guest> <host>` — the existing `mvmctl cp` already round-trips a file host↔guest over the agent fs RPC, so the SDKs are thin wrappers (`_LiveTransport.cp` / `LiveTransport.cp`). Live-mode only (like `exec`): record mode raises `SandboxModeError` (declarative staging uses `files.write`). Tests via the fixture-`mvmctl` harness assert the shelled argv + failure propagation + record-mode refusal — Python (4 tests, full suite 138 green) + TS (4 tests, full suite 71 green, `tsc`/typecheck clean).
- [x] **Task B1b — ports/forward (both SDKs).** `sb.forward(host_port, guest_port)` (Python) + `sb.forward(hostPort, guestPort)` (TS) spawn `mvmctl forward <vm> --port <host>:<guest>` (the CLI port spec is `HOST:GUEST`). Because **`mvmctl forward` blocks** (spawns socat proxies, waits until Ctrl-C — `forward.rs`), the SDK launches it **detached** (`subprocess.Popen` / `child.spawn`) and **tracks the handle** on the transport (`_forwards` / `forwards`); `_LiveTransport.kill()` / `LiveTransport.kill()` **terminate every forwarder before `mvmctl down`**, so a proxy never outlives the VM (wired into `Sandbox.kill`/`__exit__`/`[Symbol.dispose]`). Live-mode only like `exec`/`copy` (record mode raises `SandboxModeError`; declarative ports use `mvm.network(ports=...)`). TDD via the fixture-`mvmctl` harness (an optional blocking `sleep` in the `forward` case lets a test prove teardown): Python 3 new tests incl. a **terminated-on-kill** witness (suite 141 green, ruff-clean on the new code) + TS 3 new tests incl. the same teardown witness (suite 74 green, `tsc` build + `typecheck` clean).
- [x] **Task B2 — async surface (both SDKs).** Python: `async with Sandbox.create(...) as sb: r = await sb.aexec(...)`. Added `__aenter__`/`__aexit__` (async context manager; `__aexit__` tears down via `asyncio.to_thread(self.kill)`) + `async def aexec(*argv, …)`. **One impl, two faces:** `aexec` is `await asyncio.to_thread(self.exec, …)` — it runs the existing blocking `exec` in a worker thread (the codebase's established `to_thread` pattern, as in `_session.py`), so `SandboxDevOnly` / `SandboxModeError` / the captured `ExecResult` are identical across both faces; the sync `exec` + `with` are untouched. **Naming note:** the async method is `aexec`, not `exec` — one Python method can't be both sync and async, so the plan's `await sb.exec(...)` is realized as `await sb.aexec(...)` (a-prefix, the idiomatic async-variant convention); the same class carries both `with`/`async with`. TS: the async-usage parity is `[Symbol.asyncDispose]` (`await using sb = Sandbox.create(...)` — the counterpart to Python's `async with`); `await sb.exec(...)` already works (exec is sync, awaiting a non-promise is a passthrough). A *non-blocking* (spawn-based) TS exec is a noted follow-up — `spawnSync`-in-a-promise gives no real benefit, and a true async exec is a second impl, not a thin wrapper. TDD: Python 4 new tests via the fixture harness (its `proc` case now answers `wait`) — aexec-returns-result, async-CM-kills-on-exit, aexec-dev-only, aexec-record-mode-refusal (suite 145 green, new code ruff-clean) + TS 2 new tests — `await sb.exec` + `[Symbol.asyncDispose]` teardown (suite 81 green, `tsc` build + `typecheck` clean).
- [x] **Task B3 — lifecycle polish (both SDKs).** Added `sb.id` (the live VM id when live, else the workload id) + `sb.info() -> SandboxInfo { id, workload_id, build_mode, live }` — a local identity/mode snapshot (no VM round-trip; `build_mode` is `"dev"`/`"prod"` when live, `None`/`null` in record mode). `SandboxInfo` is a frozen dataclass (Python) / exported interface (TS). The other B3 items were already in place — the one-live-process invariant (`Sandbox.create` raises on a second active sandbox) and context-manager teardown (`__exit__`/`__aexit__`/`[Symbol.dispose]`/`[Symbol.asyncDispose]` → `kill` → `mvmctl down`) already have tests (double-create-refusal, sync + async CM-kills-on-exit). 4 new Python tests + 2 new TS tests (id/info, live + record) — Python suite 149 green (new code ruff-clean), TS suite 83 green (`tsc` build + `typecheck` clean). **This completes Phase B** (the imperative `Sandbox` surface: create / exec / copy / forward / id / info, sync + async, dev-tier-gated).

## Phase C — typed helpers

Thin wrappers over `Sandbox`; big perceived surface, small code.

**Files:** `sdks/python/mvm/{_code.py,_browser.py}` (new), re-exported from `mvm`.

- [ ] **Task C1 — code-runner.** `CodeSandbox(image="python:slim")` with `run(code)->stdout`, `run_script(path)`, `install_package(pkg)`. Failing test: `run("print(2+2)")=="4"`. Implement over `Sandbox.exec`. Commit.
- [ ] **Task C2 — browser/desktop presets.** `BrowserSandbox(browser="chromium")` = a `Sandbox` with a baked browser image + a forwarded CDP port + an `endpoint()` returning the ws URL. Just image + port presets; no new mechanism. Failing test: `endpoint()` returns a reachable URL (gated). Commit.

## Phase D — Node / TS parity

**Files:** `sdks/typescript/` — mirror `Sandbox` + the helpers.

- [x] **Task D1 — TS `exec` parity.** The TS `Sandbox` previously had only `create`/`kill`/`commands`/`files`; Python's top-level `exec` had no TS counterpart. Added `sb.exec(argv, { env?, timeout?, cwd? }): ExecResult` (+ exported `ExecResult`/`SandboxExecOptions`), mirroring Python's `commands_exec`: dev-only gate (prod template → `SandboxDevOnly`, claim 4, **before** any shell), then `mvmctl proc start … -- argv` → pid_token → `mvmctl proc wait <token>` capturing `{ exitCode, stdout, stderr }`. Live-mode only (record mode → `SandboxModeError`). The `-e KEY=VAL` env encoding (literals only; secrets rejected) is now a shared `encodeEnvFlags` helper used by both `commandsStart` and `commandsExec` (de-duped, not forked). 5 new TS tests via the fixture harness (extended its `proc` case to answer `wait` with configurable stdout/exit): captured-output, non-zero-exit, env-forwarding, prod-`SandboxDevOnly`-with-no-proc-traffic, record-mode-refusal — suite 79 green, `tsc` build + `typecheck` clean. **Note:** `exec` is **synchronous** here (mirrors Python's current sync `exec`); the `await`-able async surface is Task B2 (one impl, two faces). The plan's "Phase-124 codegen makes the client match the agent" framing is superseded — the SDK shells to `mvmctl` (it doesn't speak vsock), which speaks the contract-checked client. Go / C SDK parity stays a deferred scope call.

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
