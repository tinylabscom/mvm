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

- [x] **Task C1 — code-runner (both SDKs).** `CodeSandbox(image="python:slim")` with `run(code)->stdout`, `run_script(host_path)` (copy_in + run), `install_package(pkg)` — a thin typed preset over the imperative `Sandbox` (`exec`/`copy_in`), no new mechanism. Picks the runner from the image (`node*` → `node`/`-e`/`npm install`, else `python`/`-c`/`pip install`); raises a typed `CodeError` (carrying exit_code/stdout/stderr) on a non-zero exit. Lives in new `sdks/python/mvm/_helpers.py` + `sdks/typescript/src/_helpers.ts` (where C2's `BrowserSandbox` will join), exported from each package. Context-manager / `kill` delegate to the underlying Sandbox. 5 new Python tests + 5 new TS tests via the fixture harness (run-returns-stdout, raises-on-nonzero, install_package, run_script-copies-then-execs, node-runner) — Python suite 154 green (new file ruff-clean), TS suite 88 green (`tsc` build + `typecheck` clean). `sdks/`-only.
- [x] **Task C2 — browser preset (both SDKs) — completes Phase C.** `BrowserSandbox(browser="chromium")` = a `Sandbox` on a baked browser image with its CDP port (9222) forwarded to the host via `Sandbox.forward`; `endpoint()` returns the host-side CDP HTTP base (`http://localhost:<host_port>`) — pass it to a CDP client (Playwright/Puppeteer `connectOverCDP`/`browserURL`), which discovers the per-session ws URL from `/json/version`. Image + port preset only, no new mechanism. Optional `host_port` override (defaults to the CDP port); unknown browser raises `ValueError`/`RangeError`. Joins `CodeSandbox` in `_helpers.{py,ts}`, exported per package. The reachable-URL test is the E2E-gated leg; the unit tests cover the wiring: 3 new Python + 3 new TS (forwards-the-CDP-port + endpoint URL, custom-host-port, unknown-browser-raises) — Python suite 157 green (ruff-clean), TS suite 91 green (`tsc` build + `typecheck` clean). **Phase C complete** (`CodeSandbox` + `BrowserSandbox`). `sdks/`-only.

## Phase D — Node / TS parity

**Files:** `sdks/typescript/` — mirror `Sandbox` + the helpers.

- [x] **Task D1 — TS `exec` parity.** The TS `Sandbox` previously had only `create`/`kill`/`commands`/`files`; Python's top-level `exec` had no TS counterpart. Added `sb.exec(argv, { env?, timeout?, cwd? }): ExecResult` (+ exported `ExecResult`/`SandboxExecOptions`), mirroring Python's `commands_exec`: dev-only gate (prod template → `SandboxDevOnly`, claim 4, **before** any shell), then `mvmctl proc start … -- argv` → pid_token → `mvmctl proc wait <token>` capturing `{ exitCode, stdout, stderr }`. Live-mode only (record mode → `SandboxModeError`). The `-e KEY=VAL` env encoding (literals only; secrets rejected) is now a shared `encodeEnvFlags` helper used by both `commandsStart` and `commandsExec` (de-duped, not forked). 5 new TS tests via the fixture harness (extended its `proc` case to answer `wait` with configurable stdout/exit): captured-output, non-zero-exit, env-forwarding, prod-`SandboxDevOnly`-with-no-proc-traffic, record-mode-refusal — suite 79 green, `tsc` build + `typecheck` clean. **Note:** `exec` is **synchronous** here (mirrors Python's current sync `exec`); the `await`-able async surface is Task B2 (one impl, two faces). The plan's "Phase-124 codegen makes the client match the agent" framing is superseded — the SDK shells to `mvmctl` (it doesn't speak vsock), which speaks the contract-checked client. Go / C SDK parity stays a deferred scope call.

## Phase E — cross-cutting CLI/SDK polish

- [x] **Task E1 — one IR, two front-ends (coherence).** Landed as the Python⇔TypeScript decorator coherence test (`crates/mvm-sdk/src/decorator/coherence.rs`): the *same* hello-app (name, `python_image`, resources, bridge network+ports, env literal + `secret` binding), declared identically in both languages, lowers to an **equal canonical `Workload`** — the *sole* divergence is the entrypoint shim `language` (`python` vs `node`, per-SDK by construction; even `app.source` is the identical project root `.`). A non-vacuous `assert_ne` on the raw IRs proves they genuinely differ, then equality holds after normalizing only that one field; verified the test catches drift (perturbing a shared field fails it). **Reframe (the plan's four-surface premise was stale):** only the decorator is a `Workload` authoring surface, and it is the one with two language front-ends — so the honest "one derivation engine" guarantee is the SDK mirror. `mvm.toml` is the build-sizing manifest (explicit boundary: no role/network/deps — points at a flake, never lowers to a `Workload`), the flake is the derivation the *one engine emits* (`compile::flake::build_flake_nix`, IR→Nix, not Nix→IR), and runtime-record observes argv → a `Command` entrypoint that cannot equal a decorator's `Function`. Building flake→IR and toml→IR parsers just to satisfy the literal wording would be dead speculative code. 2 tests; `cargo test -p mvm-sdk` 256 green, clippy + nightly fmt + spec-ref clean, `cargo check --workspace --all-targets` green. Commit.
- [x] **Task E2 — `--secret NAME:host`.** `mvmctl up … --secret openai:api.openai.com` adds a `SecretRef` to the workload. `parse_secret_binding(spec) -> SecretRef` (in `commands/shared/parse.rs`, alongside `clap_port_spec`/`parse_volume_spec`): splits `NAME:HOST[,HOST...]`, defaults `auth_type = Bearer` + env-var mount `NAME`, requires ≥1 host (claim-12 binding). Wired as a repeatable `--secret` flag on `up`: the parsed `SecretRef`s inject into the loaded workload IR's first-app env (`EnvValue::SecretRef`) *before* `lower_workload_secrets`, so they ride the same lowering → `plan.secrets` → admission path as baked secrets; `--secret` with no workload (`--flake`/`--from-workload-ir`) errors. Richer bindings (sigv4/hmac, file mount, custom var) stay with `mvmctl secret set`. 6 parser unit tests (the headline parse + comma-hosts + missing-colon/empty-name/empty-hosts/parse-many errors). Verified: `cargo test -p mvm-cli` (up suite 49 + parser 7 green — injection is behavior-preserving for no-`--secret`), clippy + nightly fmt + `check-no-spec-refs-in-comments` clean, `cargo check --workspace --all-targets` green. (The substitution itself is the secrets subsystem; this is the CLI surface only.)
- [x] **Task E3 — `doctor` capability table.** Landed: `mvmctl doctor` now renders a **Backend capability matrix (per backend)** — one row per real backend (firecracker/libkrun/qemu/vz; the Tier 3 `mock` double excluded) consolidating `snapshot_capability` tier (live-memory/save-restore/disk-only), the network disposition (`tap-net` + `vsock`), the storage disposition (`fs-checkpoint`), `balloon`, and the boot-latency axis (`standby-pool`). `collect_capability_table()` reads every field straight off `VmBackend` (via the catalog's `warm_start_support_descriptors()` set + `capabilities()` + `snapshot_capability()` + `supports_standby_pool()`), so the table is runtime truth, not a hand-maintained copy; `BackendCapabilityRow` rides `doctor --json` under `capability_table`. Row-assertion test pins firecracker=live-memory/tap/vsock/balloon, libkrun=disk-only/no-tap/standby-pool, qemu=disk-only/slirp, and vz=vsock (host-gated fields left platform-robust) — RED-first (symbols absent), then green; a serde test pins the JSON field. `cargo test -p mvm-cli` 943 lib green + 72 doctor tests, clippy + nightly fmt + spec-ref clean. Commit.
- [x] **Task E4 — named security profiles.** `resolve_security_profile(name)` in `mvm-core::policy::security_profile` maps a name to a `SecurityProfile { seccomp: SeccompTier, egress: NetworkPreset, snapshot_allowed, deployable }` matrix. The model is **binary, production-vs-development**, not a strictness gradient: **`production` is the default** — the production-ready posture with the highest practical security (seccomp `standard` floor + deny-all egress + no snapshot) and **the only deployable profile**; **`dev`** is a development-only convenience (unrestricted seccomp + open egress + snapshots) carrying `deployable = false`, so it **can never reach production** — which is precisely why it is allowed to be loose. The invariant `every deployable profile is_bounded()` (keeps a seccomp filter + non-open egress) is asserted in a test, so a one-word profile can never silently un-sandbox a *deployable* workload. Aliases `prod`/`production`, `dev`/`development`; unknown name fails closed, listing valid names. Surface: a `--security-profile <name>` flag on `up` (`--profile` was already the flake profile) defaults to `production`, supplies the defaults for `--seccomp` + the egress preset, and explicit `--seccomp`/`--network-preset` still win; the production default is **byte-identical to today's seams** (seccomp `standard`, deny-all egress). The prod build path (`--prod`) **refuses a non-deployable profile** via `enforce_profile_deployable` (extracted + unit-tested). RED-first: 6 resolver tests in mvm-core + 4 precedence/deploy-guard tests + 1 CLI-parse test in mvm-cli. `cargo test -p mvm-core/-p mvm-cli` green (954 cli lib), clippy + nightly fmt + spec-ref + `check-core-runtime-free` + `cargo check --workspace --all-targets` clean. (Deep snapshot-allowance enforcement is a follow-up — `up` exposes no snapshot flag today; the resolver carries the disposition.) Commit.

- [ ] **Task E5 — host-services SDK surface (the workload calls the broker).** The host exposes broker services over vsock — **`host.audit.v1`** (workload-emitted audit entries: the handler forces `category: workload_audit`, stamps the host-authoritative IDs, rate/size-caps, and chain-signs via `mvm-audit-signer` — claim 8 preserved), plus `host.time.v1` / `host.cost.v1`. **The host side is built (Plan 104); the workload-facing client + ergonomic is the gap** (no guest-side broker caller exists in `mvm-guest`/`mvm-sdk` today). Failing test — `mvm.audit.emit({...})` from inside a `Sandbox` lands a `workload_audit` entry in the chain (`mvmctl audit verify` shows it, marked workload-originated + host-stamped); a >4 KiB record is refused (`BadRequest`); the 20/s rate limit trips; a workload can **never** write a host-category entry (the handler forces `workload_audit`). Implement in three layers: **(1) the guest-side broker client** — the SDK-runtime transport that opens the broker's vsock UDS, frames the `ServiceCall` envelope over `core::framing`'s authenticated frame, and carries the plan-bound session (claim 12). **None exists today** (`mvm-guest`/`mvm-sdk` have no broker caller) — this is the foundational piece all broker services ride on. Lives in `mvm-sdk`'s runtime (exposed to Python/TS via PyO3/napi). **(2) the typed service methods** — generated from 124 D's `gen-sdk` (`host.audit.v1`/`host.time.v1`/`host.cost.v1`), sitting on the transport. **(3) the SDK veneer** — `mvm.audit.emit/emit_batch`, `mvm.host.time()`, `mvm.host.cost()`. Binding-gated dispatch + no-payload-in-errors are gated in 128 (claims 12/13). Commit.

  Sliced for delivery (each its own PR, TDD RED-first). Resolved scope:
  - Layer 1 homes in **`mvm-guest`** (`broker_client.rs`), sibling to
    `substitution_client.rs` — that is the in-guest crate baked into the
    image, already carrying the vsock + framing primitives and the
    `mvm-core` broker types; `mvm-sdk` has neither as a runtime dep. The
    broker path carries a **bare `ServiceCall`, not an authenticated
    frame**: session binding is enforced host-side from the connection
    identity (the supervisor builds `ServiceCallCtx`), so the guest client
    holds no key/secret and is advisory-only — every gate (binding, audit
    category-forcing, size/rate caps, correlation-id assignment) is
    host-side. Guest-facing port = `BROKER_PORT` (5300), admitted via the
    host `host_listen_ports` allowlist like `SUBSTITUTION_PORT`.
  - [x] **E5.1** — Layer 1 transport in `mvm-guest::broker_client`
    (`call`/`broker_call` over `mvm_guest::vsock`): framed `ServiceCall`
    out, `ServiceResponse` back, typed `BrokerError`. Mock-I/O unit tests:
    Ok-payload roundtrip + exact-envelope, `Err`→typed error, oversize
    frame, truncated frame, malformed body.
  - [x] **E5.2** — typed `host.audit.v1` methods in `mvm-guest::host_audit`
    (`emit`/`emit_batch` + `_on` stream variants), reusing the shared
    `mvm-core::protocol::host_audit` wire types. The host handler is already
    built + tested (`mvm-hostd` `HostAuditV1Handler`), so this is the guest
    half: build the `ServiceCall`, map the host's typed `ServiceErrorCode`
    onto `AuditError` (`RateLimited` / `BadRequest` / `Unavailable` /
    `Service` / `Transport`). Claim 8 is structural here — `EmitRequest`
    carries no `category`, so the guest cannot express a host category, and
    the host stamps `workload_audit` regardless. 4 KiB cap + 20/s rate
    limit stay host-enforced; the client only surfaces them. 7 RED-first
    unit tests. (Host-side log-injection + covert-egress seam — claim 10 /
    Plan 111-A — is the host handler's concern; the guest record is opaque
    workload bytes.)
  - **E5.3** split on grounding — the live path needs the broker-services
    subprocess lifecycle, which is unbuilt (nothing spawns `mvm-broker` /
    `mvm-audit-signer` per VM; both proxies + the broker `serve` are
    test-only today). That's a large, security-critical workstream, so:
    - [x] **E5.3a** — reserve `BROKER_PORT` (5300) in `host_listen_ports`
      on both workload backends (libkrun + vz), the fail-closed staging
      `SUBSTITUTION_PORT` uses (nothing binds the UDS until E5.3b spawns the
      broker → stray dial `ECONNREFUSED`). Disjoint-union assertion tests.
    - **E5.3b** — the broker-services subprocess lifecycle: spawn +
      supervise `mvm-audit-signer` + `mvm-broker` per VM, bind
      `vm_vsock_port_socket(name, BROKER_PORT)`, enrich `ServiceCallCtx`
      (correlation rewrite / profile / session), the spawn process-moat
      hardening, the PyO3/napi veneer, and the live-VM E2E (box). Scoped in
      `specs/notes/plan-125-e5-3b-broker-services-lifecycle-scoping.md`;
      tracked as its own workstream (process-moat, not SDK DX).
      **Chain-format decision (open-question 4 → Option A, per-VM):** the
      `mvm-audit-signer` writes `OnDiskEntry`/JCS — a different format + signing
      scheme from the shipped claim-8 `SignedEnvelope`/`AuditEntry` chain
      `mvmctl audit verify` reads (`AuditEntry` is plan-bound with string-only
      labels + `deny_unknown_fields`, can't carry a workload record's
      `category` + JSON `fields`). So workload audit is a **separate, per-VM**
      chain `<tenant>.<vm>.workload.jsonl`, host-key-signed (one trust root),
      verified additively. **Per-VM, not per-tenant**, because that signer's
      `Chain` is single-writer (in-memory head, `O_APPEND`, no flock) — two VMs
      of one tenant must not co-write one file. The naming convention lives in
      `mvm-core::config` (`workload_audit_path` / `workload_audit_vm_name`) so
      the writer (backend spawn) and verifier can't drift.
      - [x] **E5.3b-0** — workload-chain verifier: `verify_workload_chain`
        (`mvm-hostd::audit_signer::verify`) for the `OnDiskEntry`/JCS format
        (re-derive `entry_hash`, check the `prev_hash` link, re-canonicalize to
        confirm JCS, verify the Ed25519 sig over the canonical bytes, gate the
        category allow-list, reject non-Ed25519 `sig_alg`), wired into
        `mvmctl audit verify` so it verifies the per-tenant lifecycle chain
        **and** every `<tenant>.<vm>.workload.jsonl` against the host pubkey.
        Shared `compute_entry_hash` extracted so writer + verifier can't drift;
        per-VM path convention in `mvm-core::config`. 10 RED-first verifier
        tests + 2 path-helper tests.
      - [x] **E5.3b-1** — per-VM `mvm-audit-signer` spawn + chain wiring.
        New `mvm-backend::audit_signer_spawn` (one impl for libkrun + vz — the
        signer has no backend-shaped fields, always a host UDS): resolve the
        binary (`MVM_AUDIT_SIGNER_PATH` → sibling → `target/`), hand-build the
        `SubprocessConfig` JSON on stdin (mvm-backend sits below mvm-hostd, can't
        import the type — same pattern substitution uses), detach via `setsid`,
        wait for the UDS to bind (the bin writes no handshake → poll), persist a
        PID. `software_chain_key_path` = `compute_audit_substrate().signing_key_path`
        (host signer → one trust root), `audit_jsonl_path` =
        `workload_audit_path(tenant, vm)`, UDS under `<state>/services/`. Gated
        on a tenant (admitted plan); a no-tenant VM is a defused no-op.
        Fail-closed: spawn errors roll the launch back, and `AuditSignerGuard`
        reaps on early-return (mirrors the substitution `EndpointGuard`). Wired
        into `LibkrunBackend::start`/`stop` + the vz start/stop next to the
        substitution spawn. 5 unit tests (no-op guard, config has exactly the 6
        `SubprocessConfig` keys, services-dir paths, bad-env-override reject,
        reap idempotency); the live spawn round-trip is E5.3b-4.
      - [x] **E5.3b-2** — per-VM `mvm-broker` spawn. New
        `mvm-backend::broker_spawn` + a shared `mvm-backend::service_spawn` core
        (resolve binary → `setsid`-detach → pipe config → wait UDS bind → PID →
        reap + `ServiceGuard`) that the audit-signer (E5.3b-1) was refactored
        onto (reuse-first, no drift). The broker binds the backend-shaped
        vsock-port socket the VMM bridges the guest's
        `connect_host_vsock(BROKER_PORT)` to — `vm_vsock_port_socket` (libkrun,
        direct-bind) / `vm_vz_vsock_port_socket` (vz, supervisor-splice) — passed
        by the caller; its config carries `audit_signer_uds_path` =
        `audit_signer_uds_path(state_dir)` (so it forwards `host.audit.v1` to the
        E5.3b-1 signer) + the host signer **public** key path. Gated on a tenant,
        spawned after the audit-signer, fail-closed via `ServiceGuard`, wired into
        both backends' start/stop. **This unblocks the guest→broker→signer
        round-trip** (the broker registers `HostAuditV1Handler` when
        `audit_signer_uds_path` is set). 10 spawn-module unit tests.
      - [ ] **E5.3b-2b** — `ServiceCallCtx` enrichment: `broker/server.rs` builds
        a stub ctx today (`session_id: "w1a-stub-session"`, `profile: Dev`).
        Thread the real session/profile (from the admitted plan) into the broker
        config + the host-authoritative correlation-id rewrite at ingress. The
        round-trip works without it (the entry just records the stub session);
        this is the recorded-entry correctness pass. (The claim-12 binding-gated
        dispatch stays Plan 128.)
      - [ ] **E5.3b-3** — PyO3/napi veneer.
      - [ ] **E5.3b-4** — live-VM E2E on the dev-kvm box.
  - [x] **E5.4** — `host.time.v1` / `host.cost.v1` typed methods in
    `mvm-guest::host_time` + `mvm-guest::host_cost` (`now` / `workload` +
    `tenant`, each with an `_on` stream variant), riding the same
    `broker_client` transport as E5.2. The host handlers are not built yet
    (only `HostAuditV1Handler` exists; the time/cost scaffolds land later),
    so the wire contract is established here in `mvm-core::protocol::host_time`
    (`TimeNowResponse { wall_ms }`) + `mvm-core::protocol::host_cost`
    (`CostReport { spent_micros_usd }`) — int-only money/clock per the broker
    contract, `deny_unknown_fields`; the future host handler reuses these
    types unchanged. Each method maps the host's typed `ServiceErrorCode`
    onto a typed `TimeError` / `CostError` (`NotBound` / `Unavailable` /
    `Service` / `Transport`, plus `NotImplemented` for the mvmd-delegated
    `host.cost.v1::tenant` verb). The scope is the verb, so the request body
    is empty — a workload cannot ask for another scope's spend. 18 RED-first
    unit tests (4 core serde + 14 guest mock-I/O). The PyO3/napi veneer for
    all three services rides E5.3b-3 (the veneer for `host.audit.v1` +
    `host.time.v1`/`host.cost.v1` lands together there).

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
- [ ] Ship the `mvm-audit-signer` **and `mvm-broker`** binaries beside `mvmctl` in the release artifacts (the E5.3b-1/-2 `service_spawn` resolver looks for a sibling binary, like `mvm-substitution-endpoint`; dev uses `target/`). Without them, an admitted-plan VM fails closed at start in release.
- [ ] Spawn process-moat hardening for the per-VM `mvm-audit-signer` (+ `mvm-broker`): seccomp + setpriv `--bounding-set=-all --no-new-privs` + per-workload cgroup + `pdeathsig`, cosign verify-then-exec (`binary_integrity`), and the signed config envelope (`config_signer` — the signer parses unsigned config today). Rides E5.3b-2 / Plan 128.
- [ ] Single-physical-writer consolidation (route the lifecycle `plan.*` emissions through a subprocess too) — deferred moat hardening; not a correctness prereq since the per-VM workload chains and the flock'd lifecycle chain don't co-write one file.

## Self-review

- **Spec coverage (brief 125):** ≤15 nested CLI (Phase A), 4-surfaces→1-IR (E1), `--secret NAME:host` (E2), per-backend tradeoff table (E3), named-profile UX (E4); the win-on-DX surface — imperative `Sandbox` + async/sync + copy/ports (Phase B), typed helpers (Phase C), Node parity (Phase D). All present.
- **Grounding:** the 52-verb count is real (`commands/mod.rs`); `Sandbox` already exists with `start`/`commands`/`SandboxDevOnly` (`_sandbox.py`) — B completes, doesn't rebuild. The coherence test (E1) makes the "one engine" claim falsifiable.
- **Production lens:** dev-tier gating on the imperative surface restated (B2); prod stays signed-plan.
- **Voice:** comments mark the non-obvious (why one impl backs both async/sync faces, why clap's own suggestion replaces a shim), not the calls.
