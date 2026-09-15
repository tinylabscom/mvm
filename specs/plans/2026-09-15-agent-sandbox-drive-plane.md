# An AI agent that boots in the sandbox, driven without argv

Backing: preview
Validation: none — this is a proposed design; no code implements it and no test exercises it.

**Issues:** epic [#3275](https://github.com/tinylabscom/mvm/issues/3275); [#3257](https://github.com/tinylabscom/mvm/issues/3257), [#3258](https://github.com/tinylabscom/mvm/issues/3258), [#3259](https://github.com/tinylabscom/mvm/issues/3259), [#3260](https://github.com/tinylabscom/mvm/issues/3260), [#3261](https://github.com/tinylabscom/mvm/issues/3261), [#3262](https://github.com/tinylabscom/mvm/issues/3262), [#3263](https://github.com/tinylabscom/mvm/issues/3263), [#3264](https://github.com/tinylabscom/mvm/issues/3264)

## Outcome

`mvm` ships a working, tested, documented path for booting an AI coding agent
inside a sealed microVM, driving it from host code over a typed interface, and
letting it reach its model API without the API key ever existing inside the
guest. No surface in that path builds an argv and shells `mvmctl`.

The product claim — a tight, auditable sandbox for AI agents — is today backed
by half a mechanism (credential substitution, egress presets, token budget) and
zero end-to-end evidence. Nothing in the tree boots an agent. The one published
recipe mounts a raw API key into the guest, which contradicts the headline
invariant. This plan closes both halves.

## Where we actually are

| # | Gap | Evidence | Fix lands in |
| --- | --- | --- | --- |
| G1 | Our only published agent recipe writes a raw `sk-ant-…` to a file and mounts it into the guest | `public/src/content/docs/guides/nix-flakes.md:277-330` | WS0 |
| G2 | No AI-agent example exists anywhere | `examples/` has none | WS0 |
| G3 | A cited image directory does not exist | `crates/mvm-contract/src/policy/network_policy.rs:111` names `nix/images/examples/llm-agent/`; `nix/images/examples/` is absent | WS0 |
| G4 | Credential substitution — the capability that makes the claim true — is documented in no agent-facing guide | `crates/mvm-core/src/keyholder/substitution.rs`, `crates/mvm-cli/src/commands/vm/invoke.rs` vs. `public/src/content/docs/guides/` | WS0 |
| G5 | Every verb an agent needs to be driven (`Exec`, `FsRead`, `FsWrite`, `ProcStart`, `ConsoleOpen`) is DevOnly, so the agent story and the prod story are disjoint | `crates/mvm-agentd/src/vsock/request_policy.rs` | WS1 |
| G6 | The language SDKs shell out to `mvmctl` once per call | `crates/mvm-sdk/sdks/python/mvm/_sandbox.py:728`, `crates/mvm-sdk/sdks/typescript/src/_sandbox.ts:613` | WS2 |
| G7 | `mvm-sdk` cannot link an in-process backend: `mvm-client` → `mvm-hostd` → `mvm-sdk` is a real cycle | `crates/mvm-client/Cargo.toml:43` | WS2 |
| G8 | MCP exposes machine lifecycle only — no files, no exec stream, no stdin | `crates/mvm-mcp/src/lib.rs:586-673` (14 tools) | WS3 |
| G9 | `host.secrets.v1` is named by ADR-001 claim 13 and by `CLAUDE.md`, but no handler is registered | `crates/mvm-hostd/src/broker/handlers/mod.rs:6-10` registers time/kv/assurance/audit/beacon | WS4 |
| G10 | `agent-session resume --boot` is the only agent path that starts a hypervisor, and has no tests | `crates/mvm-cli/src/commands/agent_session.rs` | WS4 |
| G11 | Plan checkboxes are inverted: the CLI workstream is ticked over unticked store/transition workstreams | `specs/plans/2026-08-18-durable-agent-sessions.md` | WS4 |
| G12 | `guides/agent-tool-contract.mdx` presents an unshipped surface under a heading a skimming reader takes as shipped | `public/src/content/docs/guides/agent-tool-contract.mdx:93-160` | WS0 |

## What already works and is not rebuilt here

- `NetworkPreset::Agent` allow-lists the model API hosts
  (`crates/mvm-contract/src/policy/network_policy.rs`).
- The token budget is enforced at the per-VM endpoint
  (`crates/mvm-hostd/src/supervisor/network_endpoint_proxy.rs`).
- Credential substitution end to end: placeholder mint
  (`crates/mvm-core/src/keyholder/substitution.rs`), endpoint handshake writing
  `substitution-env.json`
  (`crates/mvm-vmm/src/host/network_endpoint_spawn.rs`), invoke-time injection
  of the placeholder plus proxy and CA bundle
  (`crates/mvm-cli/src/commands/vm/invoke.rs`), SNI-bound TLS termination and
  swap (`crates/mvm-hostd/src/supervisor/terminator/tls.rs`), and the
  `secret.substituted` chain-signed entry.
- The stream plane: `InputGate`'s single-writer lease, TTL, ordering, the
  refusal ladder, and the refuse-when-unauditable rule
  (`crates/mvm-hostd/src/stream/{plane.rs,input_gate.rs,journal.rs,redact.rs}`).
- `RunEntrypoint` streams `EntrypointEvent` and is already ProdSafe, as are
  `StreamInput` / `CloseStreamInput`.

Three of the four capabilities an agent needs to be driven already exist in
prod-safe form. This plan adds the fourth and puts a grant in front of all of
them; it does not build a second transport.

## WS0 — Make the published story true

Issues: [#3257](https://github.com/tinylabscom/mvm/issues/3257), [#3258](https://github.com/tinylabscom/mvm/issues/3258), [#3259](https://github.com/tinylabscom/mvm/issues/3259).

- [ ] Rewrite `public/src/content/docs/guides/nix-flakes.md:277-330` onto the
      substitution path: `mvm.secret(...)` bound to the model host, an agent
      network preset, and a placeholder in the guest env. Delete the
      `printf 'sk-ant-…' > …` + `--mount` recipe. The manual file-mount pattern
      may stay documented only as an explicitly-labelled escape for
      non-HTTP credentials, and must not be the agent example.
- [ ] Add `examples/agent-workload/` — a `mkGuest` flake booting an agent CLI,
      a `mvm.toml` declaring the secret binding and egress preset, and a README
      showing the full `machine run` invocation and the audit entries it emits.
- [ ] Create `nix/images/examples/llm-agent/` so
      `crates/mvm-contract/src/policy/network_policy.rs:111` resolves, or delete
      the reference. Do not leave a doc comment pointing at an absent path.
- [ ] Write `public/src/content/docs/guides/agent-sandbox.md`: what the guest
      receives (a placeholder), what the host does (terminate TLS, substitute,
      audit), what egress is allowed, and what the audit chain records. This is
      the page the product claim rests on.
- [ ] Correct the framing in `public/src/content/docs/guides/agent-tool-contract.mdx:93-160`
      so an unshipped surface is not presented as shipped.
- [ ] Add the example to `just e2e-docs` so the documented commands are
      executed, not just written.

## WS1 — `DriveGrant`: one grant, no new transport

Issue: [#3260](https://github.com/tinylabscom/mvm/issues/3260).

- [ ] Add `DriveGrant { workspace_roots, program_id, max_bytes_in, max_bytes_out, ttl }`
      to the signed plan's grants (`crates/mvm-contract/src/ir/`,
      `crates/mvm-core/src/plan/`). The program is named by the plan, never by
      the caller and never by the model — the same rule claim 17 already applies
      when it refuses a shell entrypoint.
- [ ] Add `DriveOpen { program_id, cwd }` streaming `DriveEvent{stdout,stderr,exit}`
      and `DriveFile { Read | Write | List | Stat }` to
      `crates/mvm-agentd/src/vsock/request.rs`, classified ProdSafe in
      `request_policy.rs` **only** behind a present `DriveGrant`.
- [ ] Implement `DriveFile` by moving the existing `FsRead`/`FsWrite`/`FsList`/
      `FsStat` handler bodies behind a grant check. The DevOnly variants keep
      their classification untouched, so claim 4's witness set does not move.
- [ ] Restrict every path to `workspace_roots` at the guest handler, and again
      at the host, before the request is sent.
- [ ] Route `DriveOpen`'s process launch through the same env-synthesis seam
      `invoke.rs` uses, or the substitution placeholder never reaches the agent.
      This is the one non-obvious wiring constraint in the workstream.
- [ ] Host side is `InputSession` + `StreamReader` + the grant. No new socket, no
      new port, no new journal.
- [ ] Witnesses: `drive_open_refused_without_grant`,
      `drive_file_refused_outside_workspace_roots`,
      `drive_open_receives_substituted_placeholder_not_a_secret`,
      `drive_refusals_are_chain_signed`.

## WS2 — Delete the argv transport

Issue: [#3261](https://github.com/tinylabscom/mvm/issues/3261).

**The SDK does not shell out to `mvmctl`. Not per call, not through a
long-lived helper process, not as a fallback.** Spawning the CLI from a
library is the design being removed, and no transitional form of it is
acceptable in the replacement.

The SDKs shelling `mvmctl` is not a bug someone introduced; `specs/adrs/027-cli-surface-consolidation.md:167-174`
records it as deliberate and names the blocker — `mvm-sdk` sits below the
runtime, so linking the local backend would form a cycle — and states that
converging onto `MvmClient` is follow-on work. That follow-on was never done,
and the ADR's own framing ("still deliberately") reads as settled rather than
pending. The cycle is real today: `mvm-client` depends on `mvm-hostd`
(`crates/mvm-client/Cargo.toml:43`), which depends on `mvm-sdk`.

So the fix is not "make `mvm-sdk` link `mvm-client`". It is to stop treating
`mvm-sdk` as the host-side driver at all.

- [ ] Add `crates/mvm-hostlib` at the top of the dependency graph, beside
      `mvm-cli`: it links `mvm-client` and exposes one versioned C ABI over the
      `MvmClient` trait plus the drive verbs. Nothing depends on it, so no cycle
      is possible by construction.
- [ ] Carry an ABI major/minor and a `mvm_hostlib_abi_is_compatible` entry point
      the bindings must call before use, so a mismatched pair fails loudly
      instead of reading a moved struct.
- [ ] The bindings load the library in-process. No transport in the rewrite
      may spawn a process — not `mvmctl`, and not a helper daemon standing in
      for it.
- [ ] Rewrite `_LiveTransport` (`crates/mvm-sdk/sdks/python/mvm/_sandbox.py:728`)
      and its TypeScript twin (`sdks/typescript/src/_sandbox.ts:613`) onto that
      ABI. Streaming becomes possible; the one-process-per-call cost goes away.
- [ ] Add `xtask check-no-cli-shellout`: no file under `crates/mvm-sdk/sdks/`
      may reference `subprocess`, `spawnSync`, `execFile`, or `$MVM_CLI_BIN`.
      The rule is worth nothing if only prose holds it.
- [ ] Amend ADR-027's §"One client contract behind both the CLI and the SDK" to
      record the convergence and the new crate. An ADR that says "still
      deliberately shells out" must not survive the change.
- [ ] Update `specs/plans/2026-08-15-sdk-binding-fan-out.md`, whose whole
      costing assumes surface B is an argv builder.

## WS3 — Typed drive tools over MCP

Issue: [#3262](https://github.com/tinylabscom/mvm/issues/3262).

- [ ] Extend `crates/mvm-mcp/src/lib.rs` with `mvm.drive.{open,write,events}` and
      `mvm.drive.files.{read,write,list}` over the same ABI.
- [ ] Gate advertisement on the grant: a tool the plan does not grant is not
      listed, rather than listed and refused.
- [ ] Adopt a fail-closed classification table — a tool with no explicit risk
      classification is denied, not defaulted. An adjacent computer-use sandbox
      project generates its whole tool surface from a contract crate with a
      pinned contract version and denies anything unclassified; that part is
      worth copying.
- [ ] Witness: `mcp_tool_absent_when_grant_absent`,
      `mcp_unclassified_tool_is_denied`.

## WS4 — Close the loose ends the claim rests on

Issues: [#3263](https://github.com/tinylabscom/mvm/issues/3263), [#3264](https://github.com/tinylabscom/mvm/issues/3264).

- [ ] Decide `host.secrets.v1`: either implement the handler and register it in
      `crates/mvm-hostd/src/broker/handlers/mod.rs`, or move claim 13's prose in
      `specs/adrs/001-microvm-security-posture.md` and `CLAUDE.md` onto the
      substitution endpoint, which is what actually enforces it. Leaving a named
      service with no handler is the failure mode `check-claim-catalog` cannot
      see.
- [ ] Test `agent-session resume --boot` (`crates/mvm-cli/src/commands/agent_session.rs`).
      It starts a hypervisor and has no coverage.
- [ ] Reconcile `specs/plans/2026-08-18-durable-agent-sessions.md` (WS6 ticked
      over unticked WS1/WS3/WS4) and the matching rows in
      `specs/REFACTOR-STATUS.md`.
- [ ] Add a BDD scenario that boots the `examples/agent-workload/` image, drives
      it through the drive plane, asserts the guest env holds a placeholder and
      never the secret, and verifies the audit chain.

## Acceptance

- [ ] A contributor can run one documented command and watch an agent work
      inside a sealed microVM.
- [ ] `rg -n 'subprocess|spawnSync' crates/mvm-sdk/sdks/` returns nothing, and a
      gate holds it.
- [ ] No published page instructs a reader to put a raw credential in a guest.
- [ ] Every drive refusal is chain-signed, and the BDD scenario asserts the
      guest env held a placeholder and never the secret.
- [ ] `just ci`, `just check-gated`, and every xtask gate green.

## Explicitly out of scope

- Any change to claim 4's DevOnly set. The drive verbs are new and
  grant-gated; nothing is reclassified.
- A guest NIC, a second egress path, or any listener inside the guest.
- Display and human handoff — `specs/plans/2026-09-15-workload-display-plane.md`.
