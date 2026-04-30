---
title: "Plan 32 — Adopt-from-the-Nix-agent-ecosystem (MCP + LLM-agent VM + local-LLM defaults + egress policy)"
status: Approved
date: 2026-04-30
related: ADR-002 (microVM security posture); plan 25 (microVM hardening); plan 33 (hosted MCP transport — mvmd cross-repo)
new_adrs: 003-local-mcp-server.md (Proposal A); 004-hypervisor-egress-policy.md (Proposal D)
---

## Context

Five external resources were evaluated for adoption: jail-nix
(bubblewrap wrapper), nixai (Ollama-default Nix CLI), andersonjoseph's
DEV-community jail.nix recipe, numtide/llm-agents.nix (curated agent
catalog), and SecBear/nix-sandbox-mcp (MCP server with single-tool
design and a planned microvm.nix backend). The most relevant finding:
**nix-sandbox-mcp explicitly lists "microvm.nix backend" as future work**
because microVMs are "the right choice for running untrusted code from
the internet." mvm already has that backend. The gap is on the
agent-ergonomics side — mvm has zero MCP integration, no curated
LLM-agent example flake, and an OpenAI-default scaffolding LLM in a
world that's moved local-first.

This plan covers four concrete, scoped changes plus one follow-up:

- **A**: `mvmctl mcp` server — exposes mvm as an MCP sandbox surface
  for LLMs.
- **A.2**: MCP session semantics — additive within `mvm-mcp` after A.
- **B**: `nix/images/examples/llm-agent/` — showcase flake running
  claude-code inside a microVM, importable as an MCP env from A.
- **C**: Local-LLM-default flip for `mvmctl template init --prompt`.
- **D**: Hypervisor egress policy with domain-pinning.

Hosted-MCP transport (HTTP/SSE) is documented separately in plan 33 as
an mvmd cross-repo handoff.

Things explicitly **declined**: host-side bubblewrap (weaker than mvm's
hypervisor; Linux-only), macOS sandbox-exec at any layer (deprecated by
Apple; strictly weaker than Apple Container which mvm already uses on
macOS 26+; the dev shell is a trusted build machine in ADR-002 so adding
a sandbox there would be a layering violation; if a user wants
sandbox-exec ergonomics, `archie-judd/agent-sandbox.nix` already
provides it standalone), re-packaging agent binaries (numtide already
does this with a binary cache).

## Comparative summary (one paragraph each)

- **jail-nix** (alexdav.id): Nix lib wrapping derivations in bubblewrap
  with a combinator permission system. Linux-only. Mechanism strictly
  weaker than mvm's hypervisor. *Borrowable: combinator-style permission
  declarations in `mkGuest` example flakes.*
- **nixai**: Archived AI CLI for NixOS, Ollama-default. *Borrowable: the
  local-Ollama-first default — Proposal C.*
- **andersonjoseph (DEV)**: Practical jail.nix recipe shipping
  `jailed-crush` / `jailed-opencode` from a flake. *Borrowable: the
  user-facing shape (flake builds named agents) — Proposal B.*
- **numtide/llm-agents.nix**: Curated catalog of ~90 AI agents as Nix
  packages with a binary cache at `cache.numtide.com`. *Borrowable:
  import it as a flake input in Proposal B.*
- **SecBear/nix-sandbox-mcp**: MCP server, single `run` tool with `env`
  parameter, ~420 fixed token cost, planned microvm.nix backend.
  *Borrowable: the entire single-tool design — Proposal A.*

---

# Proposal A — `mvmctl mcp` server

## Why

mvm has stronger isolation than nix-sandbox-mcp's current bubblewrap
backend (full microVM vs namespaces). Adding an MCP server lets LLM
clients (Claude Code, opencode, etc.) drive mvm as a sandbox without
shelling out to the CLI. The single-tool design from nix-sandbox-mcp
keeps the LLM context-window cost flat (~420 tok) regardless of how many
templates the user registers.

## Design

**Tool surface:** one tool, `run`, with parameters:

| field          | type    | required | semantics                                                                           |
| -------------- | ------- | -------- | ----------------------------------------------------------------------------------- |
| `env`          | string  | yes      | name of a built `mvmctl template`, e.g. `python`, `shell`, `claude-code-vm`         |
| `code`         | string  | yes      | program text passed to the env's interpreter (or argv joined if `interpreter=raw`)  |
| `session`      | string  | no       | reserved for A.2; v1 always boots a fresh transient VM via `crate::exec::run()`     |
| `timeout_secs` | integer | no       | per-call timeout; default 60; bounded `[1, 600]`                                    |

**Wire protocol:** JSON-RPC 2.0 over stdio (the MCP standard). Three
methods: `initialize`, `tools/list`, `tools/call`. Hand-rolled to avoid
adding a new `rmcp` external dep that would need to clear ADR-002's
supply-chain bar.

**Dispatch:** `tools/call run` with `env=X, code=Y` →
`crate::exec::run(ExecRequest { image: ImageSource::Template(X), target:
ExecTarget::Inline { argv: shell_argv_for(env, code) }, … })`. Stdout
and stderr captured into the MCP response.

**Env registry:** the registry is just `mvmctl template list`. Any
template the user has built becomes an `env`. We ship a curated set
(via Proposal B) and document a recipe for users to register their own.

**Token budget evidence we should reproduce:**
- tool schema (~75 tok)
- server instructions (~160 tok)
- per-param descriptions (~80 tok)
- **target: ≤ 500 tok fixed cost.** Verified by a unit test asserting
  the serialized `tools/list` response is under the budget.

**Threat model:** the MCP server is host-local stdio. No new attacker
surface beyond ADR-002:
- The `env` param is matched against the existing `mvmctl template list`
  — no shell interpolation, no arbitrary path access.
- `code` lives entirely inside the (already-isolated) microVM.
- `timeout_secs` is bounded `[1, 600]` to prevent client-side runaway.
- ADR-003 (new) documents this and references ADR-002.

## Files

**New crate:** `crates/mvm-mcp/`

```
crates/mvm-mcp/
├── Cargo.toml          # features: protocol-only (no I/O), stdio (default).
│                       # Default deps: mvm-core, serde, serde_json, anyhow.
│                       # stdio-only deps: mvm-cli (for crate::exec).
├── src/
│   ├── lib.rs          # public API: Dispatcher trait + run_stdio() entrypoint (gated on `stdio`)
│   ├── protocol.rs     # JSON-RPC 2.0 frames                                 [protocol-only]
│   ├── tools/
│   │   ├── mod.rs      # ToolSchema, RunParams, RunResult                    [protocol-only]
│   │   └── run.rs      # the single `run` tool: schema + handler             [stdio]
│   ├── server.rs       # initialize/tools/list/tools/call dispatch loop      [stdio]
│   └── env.rs          # template-list discovery; validates `env` param      [stdio]
└── tests/
    ├── protocol_smoke.rs  # mock stdio; assert tools/list shape, dispatch
    ├── budget.rs           # asserts tools/list serialized tokens < 500
    └── protocol_only.rs    # asserts cargo build --no-default-features --features protocol-only produces no I/O symbols
```

The `protocol-only` feature is **mandatory from day one** (not deferred):
plan 33 (`specs/plans/33-hosted-mcp-transport.md`) requires mvmd to be
able to consume the wire types and `Dispatcher` trait without dragging
in mvm-cli or stdio I/O. Adding the feature retroactively after mvmd
starts depending on `mvm-mcp` would force a coordinated bump; doing it
day one is free.

**Wiring:**

- `Cargo.toml` (workspace) — add `mvm-mcp = { path = "crates/mvm-mcp",
  version = "0.13.0" }` to `[workspace.dependencies]` and `members`.
- `crates/mvm-cli/Cargo.toml` — add `mvm-mcp.workspace = true`.
- `crates/mvm-cli/src/commands/mod.rs:107` — register a new
  `Mcp(ops::mcp::Args)` variant on `Commands`. Add to the dispatch
  match at line 174-203.
- `crates/mvm-cli/src/commands/ops/mcp.rs` (new) — thin `run()` that
  calls `mvm_mcp::run_stdio(stdin, stdout)`.

**Refactor needed in `mvm-cli/src/exec.rs`:** the MCP handler needs to
capture stdout/stderr instead of streaming them to the user's terminal.
Add a `capture: bool` flag to `ExecRequest` (default false to preserve
existing CLI behavior); when true, return captured bytes in
`ExecResult { exit_code, stdout, stderr }`. The CLI path keeps streaming;
the MCP path captures. ~30 LoC change.

## CI gate (✅ shipped on `feat/mcp-server-smoke`)

The `mcp-server-smoke` job in `.github/workflows/ci.yml` runs
`scripts/test-mcp-roundtrip.sh`, which spawns `mvmctl mcp stdio` as
a child process and asserts five things in one real JSON-RPC
roundtrip:

1. `initialize` returns the pinned protocol version + serverInfo
   (`name=mvm`) + `capabilities.tools.listChanged=false`.
2. `tools/list` returns exactly one tool named `run` with the
   expected schema fields (`env`, `code`, `session`, `close`,
   `timeout_secs`).
3. `tools/call run` against an unregistered env returns a
   structured `ToolResult { is_error: true }` whose text mentions
   the rejected env name — *not* a JSON-RPC error frame (LLM
   clients tend to retry those).
4. Every line on stdout parses as JSON (the stdout-only-JSON-RPC
   discipline contract from cross-cutting "A: stdout-only").
5. Under `RUST_LOG=trace`, the sentinel `mvm-mcp stdio loop ready`
   info line lands on stderr — verifying that
   `init_stderr_tracing` is wired AND that
   `commands/mod.rs::run` correctly skips the parent
   `logging::init` for the `mcp` subcommand. Without that skip,
   the parent's stdout-writing subscriber would corrupt JSON-RPC
   framing on any tracing event.

The roundtrip script is shell + `jq`, no Node/Python deps. CI
installs jq via apt; locally `brew install jq`.

## Verification

- `cargo test -p mvm-mcp` — unit tests for protocol parse/serialize,
  tools/list shape, error paths.
- `cargo test --workspace` — green.
- `cargo clippy --workspace -- -D warnings` — green.
- Manual: `echo '{"jsonrpc":"2.0","id":1,"method":"tools/list",
  "params":{}}' | mvmctl mcp --stdio | jq .` returns the single `run`
  tool.
- End-to-end: configure Claude Code's MCP client with
  `command=mvmctl, args=[mcp, --stdio]`, ask it to run
  `python -c 'print(2+2)'` in the `python` env.

## Critical files to read before implementing

- `crates/mvm-cli/src/exec.rs` — `ExecRequest`/`ExecResult`/`run()`.
- `crates/mvm-cli/src/commands/vm/exec.rs` — how the CLI builds
  `ExecRequest`.
- `crates/mvm-runtime/src/vm/template/lifecycle.rs:81-97` —
  `template_list()`, used to populate the `env` allowlist.
- `specs/adrs/002-microvm-security-posture.md` — ADR-003 must compose.

---

# Proposal B — `nix/images/examples/llm-agent/` showcase flake

## Why

A concrete demo that mvm boots an LLM agent inside a microVM. Until A
lands, this is the answer to "can mvm do that?". After A lands, this
becomes the canonical `claude-code-vm` env in the MCP server. Imports
`numtide/llm-agents.nix` so we don't repackage agents.

## Design

A flake under `nix/images/examples/llm-agent/` that:

1. Imports `numtide/llm-agents.nix` for `claude-code` packages —
   pre-built via `cache.numtide.com`.
2. Calls `mkGuest` from the parent `nix/flake.nix` with:
   - `rootfsType = "ext4"` (agents write state).
   - one service `claude-code` running as uid 1100 (per-service uid per
     ADR-002 §W2.1) under setpriv with seccomp tier `network`.
   - virtiofs-shared workdir at `/workspace`, read-write.
   - secrets file at `/run/secrets/anthropic-api-key` (mode 0400, owner
     uid 1100), populated from host `~/.config/mvm/secrets/anthropic`.
3. README documenting build + run + share-workdir recipe.

## Files

**New:**

```
nix/images/examples/llm-agent/
├── flake.nix          # imports llm-agents.nix; mkGuest with claude-code service
├── flake.lock         # generated by `nix flake lock`
├── service.nix        # claude-code service: setpriv, seccomp=network, secrets path
└── README.md          # build + run + share-workdir recipe
```

**Edits:**

- `public/src/content/docs/guides/nix-flakes.md` — add a "Running an
  LLM agent inside a microVM" section pointing at the new example.
- `crates/mvm-cli/src/commands/build/image.rs` (or wherever the example
  list lives) — surface the new example in `mvmctl image list`.

## Security composition with ADR-002

- Agent service runs as uid 1100, not the guest agent's uid 901 (W4.5).
- Seccomp tier `network` (W2.4) — allows socket/connect/sendto, blocks
  ptrace/keyctl/etc.
- Anthropic API key lives in `/run/secrets/anthropic-api-key` mode
  0400 owned by uid 1100. The guest agent doesn't read it.
- Verified boot is exempt for development (per ADR-002 §3); the
  showcase docs say so explicitly.
- Network egress is unrestricted at the hypervisor level today; this
  is what Proposal D fixes.

## Verification

- `nix flake check ./nix/images/examples/llm-agent` succeeds.
- `mvmctl template build claude-code-vm` produces a rootfs.
- Boot the VM; `mvmctl console claude-code-vm-0001` shows `claude` in
  PATH; `claude --version` prints a version string.
- Smoke: `mvmctl run --template claude-code-vm --add-dir
  /tmp/empty-workspace:/workspace:rw` boots, the workspace mount is
  writable as uid 1100, the agent prompts for input.
- CI: add to the existing nix-flake-check matrix.

## Critical files to read before implementing

- `nix/flake.nix` — `mkGuest` API.
- `nix/images/examples/hello/flake.nix` — closest existing example.
- `nix/images/examples/hello-python/flake.nix` — `mkPythonService`
  pattern.
- `nix/lib/minimal-init/default.nix:71-196` — per-service uid
  derivation.
- ADR-002 §W2.4 — seccomp tier `network` semantics.

---

# Proposal C — Local-LLM-default for `mvmctl template init --prompt`

## Why

`template init --prompt` currently prefers OpenAI when `OPENAI_API_KEY`
is set, and falls back to a local LocalAI-shaped endpoint only if
`MVM_TEMPLATE_LOCAL_BASE_URL` (or `LOCALAI_BASE_URL`) is set. nixai's
pattern (and the broader local-first trend) is the opposite: try local
first, fall back to hosted. Cost and privacy both improve; an OpenAI key
in env is a configuration leak we shouldn't penalize users for.

## Design

In `auto` mode (the default), probe a local OpenAI-compatible endpoint
on `http://127.0.0.1:11434/v1` (Ollama) and `http://127.0.0.1:8080/v1`
(LocalAI / llama.cpp server). If either responds to `GET /v1/models`
within 200ms, pick it. Only fall through to OpenAI if no local endpoint
is reachable.

`MVM_TEMPLATE_PROVIDER=openai` and `=local` keep their explicit
semantics (unchanged). Only `auto` (default) flips order.

## Files

**Edit only:** `crates/mvm-cli/src/template_cmd.rs:545-570`
(`llm_generation_config_from_env`).

```rust
"auto" => {
    if let Some(config) = local_generation_config_from_env_with_probe() {
        Ok(Some(config))
    } else if let Some(config) = openai_generation_config_from_env() {
        Ok(Some(config))
    } else {
        Ok(None)
    }
}
```

New helper `local_generation_config_from_env_with_probe()`:

- Honor explicit `MVM_TEMPLATE_LOCAL_BASE_URL` if set.
- Otherwise probe `127.0.0.1:11434` then `127.0.0.1:8080`. First
  responding `GET /v1/models` within 200ms wins.
- Default model: `qwen2.5-coder-7b-instruct`.
- Skip probe entirely when `MVM_TEMPLATE_NO_LOCAL_PROBE=1`.

~30 LoC change.

## Tests

- `test_auto_prefers_local_when_reachable`: spin a local server on a
  random port, override the probe target, assert `LlmProvider::Local`.
- `test_auto_falls_through_to_openai_when_no_local`: probe target
  unreachable, `OPENAI_API_KEY=k`, assert `LlmProvider::OpenAi`.
- `test_explicit_openai_skips_probe`: `MVM_TEMPLATE_PROVIDER=openai`,
  no probe attempted.
- `test_no_local_probe_env_var`: `MVM_TEMPLATE_NO_LOCAL_PROBE=1` skips
  the probe even with a server running.

## Verification

- `cargo test -p mvm-cli template_cmd::tests::auto_prefers_local`.
- Manual with Ollama running locally: verbose log prints
  `provider=local model=qwen2.5-coder-7b-instruct`.
- Docs: update
  `public/src/content/docs/reference/cli-commands.md:327-330`.

## Critical files to read before implementing

- `crates/mvm-cli/src/template_cmd.rs:443-604` — full LLM config layer.

---

# Proposal D — Hypervisor egress policy with domain-pinning

**Status (v1):** L3 tier shipped — `NetworkPreset::Agent` added in
`mvm-core::policy::network_policy`; ADR-004
(`specs/adrs/004-hypervisor-egress-policy.md`) documents the
three-layer model and the v1 reduction. L7 HTTPS-proxy + DNS-answer
pinning are deferred follow-ups (see ADR-004 §"The three-layer
model"). The `nix/images/examples/llm-agent/` README now recommends
`mvmctl up --network-preset agent` as the recommended posture, with
the deferred limits documented honestly. The L3 tier composes with
the existing `apply_network_policy` + `cleanup_network_policy`
infrastructure already shipped in W7.

## Why

Belongs in mvm: mvm owns the host network surface (TAP, NAT iptables,
the bridge `br-mvm`). Users want domain-pinning ("agent can reach
api.anthropic.com only"). agent-sandbox.nix proves the pattern works.
ADR-002 §"explicit non-goals" flagged this as out of scope for v1
hardening; this proposal moves it on-roadmap.

## Design

Three layers, mvm picks the right one per VM:

1. **L7 HTTP/HTTPS proxy** (default for `network_policy.domains`):
   `mitmproxy`-style egress proxy on the host bound to a private CIDR
   the guest can reach. Guest is configured with `HTTPS_PROXY` /
   `HTTP_PROXY` env vars and the proxy's CA cert in
   `/etc/ssl/certs/mvm-egress.crt`. Proxy enforces the allowlist by
   SNI for HTTPS and Host header for HTTP. CONNECT to disallowed
   domains returns 403.
2. **L3 iptables egress** on the host: at TAP attach time, install
   `OUTPUT`/`FORWARD` rules in the `MVMEGRESS-<vm>` chain that DNAT
   only to resolved IPs from the allowlist. DNS for the guest goes
   through a stub resolver on the host (`dnsmasq`) that only resolves
   allowlisted domains and pins the answer for the iptables ruleset
   for the answer's TTL.
3. **Stack both** for "agents on the public internet" mode (the
   default for Proposal B's `claude-code-vm`): proxy for HTTP, iptables
   denying everything else.

`mvm-core::network_policy::NetworkPolicy` already has the field
`domains: Vec<String>`; today it's read by seccomp tier selection only.
Wire it to TAP setup so allowlist enforcement happens at attach time.

## Files

**Edit:**

- `crates/mvm-core/src/network_policy.rs` — extend `NetworkPolicy` with
  `egress_mode: EgressMode { Off, Open, AllowDomains, AllowDomainsStrict }`.
- `crates/mvm-runtime/src/vm/network.rs` — `tap_create()` honors the
  policy: spawns the egress proxy on a per-VM port, installs iptables
  rules in `MVMEGRESS-<vm>` chain, tears down on `tap_destroy()`.
- `crates/mvm-runtime/src/vm/microvm.rs` — pass `HTTPS_PROXY` and
  `MVM_EGRESS_CA_PATH` into the guest via existing env injection.
- New: `crates/mvm-runtime/src/vm/egress_proxy.rs` — wrapper around
  `mitmdump` from nixpkgs; surfaced via `mvmctl doctor`.
- `nix/lib/minimal-init/default.nix` — install the mvm CA cert at boot
  if `/run/mvm-egress.crt` is mounted.
- `specs/adrs/004-hypervisor-egress-policy.md` (new) — three-layer
  model, named limits (DNS rotation, certificate pinning by guest
  apps, performance overhead).

## Verification

- `cargo test -p mvm-runtime egress` — unit tests for iptables rule
  generation, allowlist parsing.
- Integration: build `claude-code-vm` (Proposal B) with
  `network_policy.egress_mode = AllowDomainsStrict` + `domains =
  ["api.anthropic.com"]`. Boot, `curl https://api.anthropic.com/` →
  200; `curl https://google.com/` → blocked.
- `mvmctl doctor` reports egress-proxy availability.

## Sequence

D is independent of A, B, C but most useful *with* B (gives the
`claude-code-vm` example real teeth). Estimate ~1 sprint.

---

# Proposal A.2 — MCP session semantics (mvm follow-up to A)

**Status (v1 shipped — bookkeeping; v2 deferred — warm-VM materialisation):**

v1 (shipped on `feat/mcp-session-semantics`):
- Wire schema in `mvm_mcp::tools` accepts `session: Option<String>`
  and `close: Option<bool>` with full JSON-Schema descriptions.
- `mvm_mcp::session` ships a protocol-only `SessionMap` + `Reaper`
  trait + `SessionConfig` (idle / max from `MVM_MCP_SESSION_IDLE` /
  `MVM_MCP_SESSION_MAX`). Pure unit tests cover create / touch /
  idle-reap / max-lifetime / close / drain transitions.
- `ExecDispatcher` (mvm-cli) holds the map, spawns a 30 s-tick
  reaper thread at startup, drains on `Drop` (clean shutdown),
  and emits `LocalAuditKind::McpSessionStarted` /
  `McpSessionClosed` events with the close reason (`idle` /
  `max_lifetime` / `closed` / `shutdown`).

v2 (deferred):
- The map's `vm_name: Option<String>` is always `None` in v1
  because `crate::exec::run_captured` is still cold-boot per call.
  v2 will refactor exec.rs to expose
  `boot_session_vm` / `dispatch_in_session` / `tear_down_session`
  primitives, set `vm_name = Some(...)` on first boot, and skip
  the cold-boot path on subsequent calls in the same session. The
  `ExecDispatcher` already holds the map under
  `Arc<Mutex<SessionMap>>` so v2 plugs in without touching the
  wire types or the `Reaper` trait.
- `// TODO(A.2 v2)` markers in
  `crates/mvm-cli/src/commands/ops/mcp.rs` flag the exact lines
  that change.

## Why

nix-sandbox-mcp uses `session` for REPL persistence inside a single
sandbox process. mvm's analog is template snapshots — boot once, run
many calls against the warm VM, snapshot/destroy at session end. This
is a strict win over nix-sandbox-mcp's design because mvm sessions
inherit microVM isolation; nix-sandbox-mcp sessions are
bubblewrap-bound.

## Design

`tools/call run` with `session=ID`:

- **First call with new session ID:** allocate a snapshot-resumed VM
  (or cold-boot if no snapshot for env). Call
  `mvm_runtime::vm::microvm::run_from_snapshot()` from
  `lifecycle.rs:539`. Stash `(session_id → VmId)` in a local
  in-memory map (lifetime = MCP server process).
- **Subsequent calls with same session ID:** route the command to the
  existing VM via the guest agent's `Exec` over vsock.
- **Session reaping:** idle timeout (default 300s, env
  `MVM_MCP_SESSION_IDLE`), max lifetime (default 3600s, env
  `MVM_MCP_SESSION_MAX`).
- **Explicit close:** new tool param `close: bool` — when true after
  exec, snapshot if env has `persist_on_close=true`, then destroy.

Token budget impact: adds ~40 tokens (session + close fields). Stays
under the 500 tok target.

## Files

**Edit (within Proposal A's crate):**

- `crates/mvm-mcp/src/tools/run.rs` — add `session` and `close` params.
- `crates/mvm-mcp/src/server.rs` — add session map + reaper thread.
- `crates/mvm-mcp/src/session.rs` (new) — session struct, idle/max
  tracking, snapshot-on-close logic.

**Refactor (shared with A):**

- `crates/mvm-cli/src/exec.rs` — split `run()` into `run_oneshot()`
  (current behavior) and `run_in_existing(vm_id, argv)` (new).

## Security composition

- The vsock `Exec` handler is feature-gated by `dev-shell` (ADR-002
  W4.3). The MCP server must be feature-gated identically. CI gate:
  extend the existing `do_exec` symbol grep to also assert
  `mvm_mcp::session` is absent in the prod build.
- Session-pinned VMs hold the same threat-model status as `mvmctl dev`
  VMs.

## Verification

- `cargo test -p mvm-mcp session::tests::idle_reaping`,
  `max_lifetime`, `snapshot_on_close`.
- Integration: open session, run two distinct shell commands, assert
  state persists between calls.
- CI: feature-gate test asserts `mvmctl mcp` in prod build doesn't
  expose session params.

## Sequence

Sits after A. Treat as A.2 — same crate, additive.

---

# Cross-cutting considerations (must-fold into proposals before merge)

## Security/correctness (must do)

- **A: stdout-only-JSON-RPC discipline.** MCP servers MUST write
  *nothing* to stdout that isn't a valid JSON-RPC frame. Initialize a
  stderr-only `tracing_subscriber` *before* the dispatch loop, and add
  a CI test that runs `mvmctl mcp --stdio < /dev/null` with
  `RUST_LOG=trace` and asserts stdout is empty after a clean shutdown.

- **A: audit logging.** Every `tools/call run` (env, code length, exit
  code, duration, caller-claimed session id) lands in
  `~/.mvm/log/audit.jsonl` via `mvm_core::audit::log_event(...)`.

- **A: resource limits per call.**
  - `timeout_secs` ∈ [1, 600].
  - Memory: cap below the template's machine-config default; reject
    `tools/call` whose env's template requests > 4 GiB. Knob:
    `MVM_MCP_MEM_CEILING_MIB`.
  - Concurrency: hard cap `MVM_MCP_MAX_INFLIGHT` (default 4); over
    the queue depth `MVM_MCP_MAX_QUEUE` (default 16), return error.
  - Output: stdout/stderr each truncated at 64 KiB with explicit
    `[truncated, N more bytes]` marker.

- **A: dev-shell feature gating is transitive.** ADR-002 §W4.3 demands
  no `do_exec` symbol in prod builds. `mvm-mcp`'s `stdio` feature
  must require the workspace `dev-shell` feature. CI gate: extend
  the existing `do_exec` symbol grep to cover `mvmctl mcp` too.

- **B: secret injection mechanism.** Verify before starting B: read
  `crates/mvm-cli/src/exec.rs` for any `secret_files` field, and
  `crates/mvm-runtime/src/vm/microvm.rs` for `secret_files: vec![]`
  in `FlakeRunConfig`. If absent, B grows a sub-task to add it via
  mvm's existing secrets path (`/mnt/secrets` per ADR-002).

- **D: iptables/proxy dispatch lives in Lima on macOS.** mvm's
  bridge `br-mvm` runs *inside the Lima VM* on macOS, not on the
  host. The egress-proxy launcher and iptables rules must dispatch
  via `shell::run_in_vm()`, not run directly on macOS. Follow the
  established pattern in `crates/mvm-runtime/src/vm/network.rs`.

## UX / interop (should do)

- **A: protocol version pinning + capabilities.** `initialize` returns
  `protocolVersion` and `capabilities`. Pin to the current MCP
  protocol revision (verify against the spec repo at implementation
  time). Advertise `capabilities.tools.listChanged: false`. Reject
  `initialize` requests for incompatible protocol versions with a
  clear error.

- **A: tool-call response framing.** Return stdout and stderr as two
  separate `content` blocks of `type: "text"`. Include a final
  `content` block with `{"type":"text","text":"exit_code=N"}` and
  set `isError: true` iff the exit code is nonzero.

- **A: metrics integration.** Add counters
  `mvm_mcp_calls_total{tool="run", env, status}`, histogram
  `mvm_mcp_call_duration_seconds`, gauge `mvm_mcp_inflight` to the
  existing `mvmctl metrics` registry.

- **A + D: docs site.** New pages under
  `public/src/content/docs/`: `guides/mcp-server.md` (A) and
  `reference/network-policy.md` (D).

- **B: graceful first-run when Anthropic key is missing.** Service
  start script checks for `/run/secrets/anthropic-api-key`; if
  absent, writes a clear message to its log and exits 0 (so the
  integration health check shows "no key configured" rather than
  crash-loop).

- **C: probe leak note.** The local-LLM probe issues a TCP connect
  to `127.0.0.1:11434` and `127.0.0.1:8080` on every `template init`
  invocation. Visible to other local processes (`netstat`).
  Documented in the man page.

## Plumbing (nice to have)

- **A: nix-sandbox-mcp wire compat.** If exact param names / response
  shapes match (`env`, `code`, `session`), existing clients
  configured for nix-sandbox-mcp can point at `mvmctl mcp` with one
  config edit.

- **A: shell-env note in threat model.** For `env=shell`, `code` *is*
  shell. There is no in-microVM interpreter sandbox beyond the
  microVM's own walls; note this in ADR-003.

- **D: orphan cleanup invariant.** `mvmctl cache prune` (existing)
  should reap orphaned egress proxies and stale `MVMEGRESS-*`
  iptables chains.

- **B: cross-platform CI for the example flake.** macOS CI for B
  needs `nix flake check` to pass.

- **Plan housekeeping.** `specs/plans/22-agent-sandbox-patterns.md`
  is the research-survey predecessor of A/B. After A and B land,
  mark 22 as `Status: Superseded by [32]`.

- **ADR numbering check.** ADR-003 (Proposal A) and ADR-004 (Proposal D)
  are the next free integers after `specs/adrs/002-microvm-security-posture.md`.

---

# Cross-cutting verification

After all proposals land:

```bash
cargo build --workspace                  # all crates compile, including mvm-mcp
cargo test --workspace                   # 1067+ existing + new tests green
cargo clippy --workspace -- -D warnings  # mvm CLAUDE.md rule
nix flake check ./nix/images/examples/llm-agent  # B's flake checks
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | \
  mvmctl mcp --stdio | jq '.result.tools[0].name'  # → "run"
mvmctl template create claude-code-vm --flake ./nix/images/examples/llm-agent \
  --profile minimal --role agent
mvmctl template build claude-code-vm
# In an MCP-enabled LLM client: ask the LLM to "run python -c 'print(2+2)' in
# the python env" → observe a microVM boot, run, return "4", tear down.
```

---

# Sequence

A, B, C, D are largely independent. Recommended order if done
serially:

1. **C** (smallest blast radius, ~30 LoC + tests; ~half a day).
2. **B** (no Rust changes; flake + service.nix + docs; ~1 day).
3. **A v1** (new crate + ADR-003; ~3 days). B's `claude-code-vm`
   becomes the canonical demo env in A's docs.
4. **D** (egress policy + ADR-004; ~1 sprint). Updates B to default
   to `AllowDomainsStrict` + Anthropic-only allowlist.
5. **A.2** (MCP session semantics; additive within `mvm-mcp`; ~2-3
   days). Composes with D so sessions inherit egress policy.

Hosted-MCP transport is filed as plan 33 — an mvmd cross-repo task —
not sequenced here.
