# Plan: Agent-sandbox product surface — close every gap on our security core

Backing: preview
Validation: none — this plan proposes work; each workstream names the tests and gates that will witness it when it lands.

## Status

**In progress.** Drafted 2026-09-25 from a source-level comparison against an
external host-kernel agent sandbox (process-level allow-lists, a host proxy,
per-session undo, a hash-chained audit log, signed profile packs, detachable
PTY sessions). Tracking issue #3731; one issue per workstream below.

## North star

Keep the security core and rebuild the product surface on top of it.

The core does not move: the microVM is the isolation boundary; the guest has no
NIC; vsock is the only host↔guest channel; the per-VM host network endpoint is
the single egress decision point (`check-single-network-path`); every grant
comes from the signed `ExecutionPlan`; every decision lands in the chain-signed
audit log; no raw secret enters the guest (claim 13). **Security wins every
tie** — where a convenience would weaken one of those properties, we take a
different shape of the convenience rather than the weaker property.

What we adopt is experience: authored profiles and composable policy, signed
packs run by name, credential injection that needs no code changes, visible
denials that turn into policy, runtime approvals, undo/redo/replay with real
diffs, reattachable sessions, instruction-file provenance, docs and packaging.

## Where we stand

| Capability | Our mechanism today | Gap to close |
|---|---|---|
| Isolation | microVM per workload, NIC-less guest | none (stronger than process sandboxing) |
| Network filtering | loopback forward proxy in guest → vsock → host endpoint `EgressGate`; host:port allow-list | route model, L7 method/path rules, `ask`, private-range default deny, visible denials |
| Credential injection | host substitution endpoint, placeholders, header-only | `--secret` on run, TLS termination for bound destinations, secret source references, provider routes, OAuth |
| Audit trail | chain-signed, host-signer key, segment handoffs, inclusion proofs | per-session summary + ledger, `VERIFIED`/`MISMATCH` UX, filters, durability statement |
| Provenance | cosign-signed release blobs, build attestations, `env verify-release` | instruction-file signing + trust policy + pre-boot scan; distro package attestation |
| Undo / rollback | VM checkpoints; `vm diff` lists paths only; no host-tree apply | content diff, journaled apply, undo/redo, replay |
| Runtime supervisor | static grants; approval ledger exists in `mvm-contract` but unwired | ask decisions for network/tools/secrets with terminal/webhook backends |
| Sessions | persistent machines, `-d`, console dies on disconnect | console reattach, one lifecycle surface, enforced healthcheck/timeout |
| Policy authoring | `mvm.toml`, `--grants-file`, workload IR, flags; signed plan is machine-generated | TOML policy groups → profiles → resolved manifest (the signed plan) |
| Packs | `mvm-templates` read-only catalogue | signed packs, `search`/`pull`/`run --profile ns/name`, agent packs |
| Tool privileges | supervisor tool gate from plan `tool_policy` | per-tool policy in profiles, mediation, per-tool credential binding |
| Env hygiene | none | loader/shell/interpreter variable denylist |
| Library & bindings | SDKs spawn `mvmctl` per call; hostlib covers ~7 methods | in-process hostlib for everything; `mvm-client` is the one library |
| Packaging | install.sh, Homebrew tap | deb, rpm, AUR, nixpkgs, crates.io, native lib in wheels/npm |

## Decisions (taken 2026-09-25)

1. **The proxy is the guest-facing surface of the vsock convention**, not a
   second transport. The route schema (prefix → upstream, injection mode,
   endpoint rules, allow/deny/ask) is the typed policy each `NetworkFlow`
   carries to the host endpoint. Vsock stays the only wire.
2. **`--secret`: host TLS termination only for destinations the signed plan
   binds**, using the per-VM CA the guest already trusts; everything else stays
   an opaque tunnel. Each destination gets its own placeholder.
3. **Undo: the agent never writes the host tree.** Changes come back through a
   reviewed apply (`Apply to working tree? [y/N]`, `--apply` when
   non-interactive), journaled and preceded by a content-addressed host
   snapshot, so `undo`/`redo` always work and a crash mid-apply is recoverable.
4. **Policy format: TOML**, with the JSON Schema generated from the Rust types.
   The resolved manifest is the signed `ExecutionPlan`.
5. **Runtime approvals cover network destinations, tool calls and secret use on
   every backend.** Filesystem grants stay static: the VM image is that
   boundary.
6. **SDKs never spawn `mvmctl`.** `mvm-client` is the one Rust library;
   `mvm-hostlib` is the C ABI over it; every language binds to hostlib.
7. **Packs live in `mvm-templates`** and define their own images with their own
   `mvm.toml` / `flake.nix`. `mvm-images` builds only the images `mvmctl`
   itself requires.
8. **Composition only narrows**: denies beat allows, required groups cannot be
   excluded, a child cannot unblock network, packs carry no escape hatches.

## What we deliberately do not copy

- Process-level host sandboxing in place of the microVM.
- Handing a raw credential to the workload's environment as an alternative mode.
- Packs that write the host's agent configuration files.
- Lenient proxy authentication, or a single placeholder valid for every route.
- Learning policy from stderr heuristics: we have typed denial events.

## Priority order

Security-bearing gaps first, then the foundations the UX needs:

1. PS-12, PS-02, PS-03, PS-11, PS-07, PS-10 (security-bearing)
2. PS-01, PS-04, PS-05, PS-09, PS-08 (foundations and daily UX)
3. PS-06, PS-13 (build on PS-05)
4. PS-15, PS-16, PS-17, PS-18, PS-19, PS-20, PS-21

## Workstreams

### PS-01 — SDKs in-process through mvm-hostlib (#3711)
- [ ] hostlib dispatch covers create/boot/run, exec (streaming), files, sessions, stop/rm, logs
- [ ] Python and TypeScript facades use hostlib; subprocess transport deleted
- [ ] xtask gate: no SDK source spawns or resolves `mvmctl` (with its own fixtures)
- [ ] `mvm-client` re-exports the embedder surface; Rust quickstart uses only `mvm-client`
- [ ] runtime lookup of `libmvm_hostlib` documented (packaging in PS-15)

### PS-02 — Egress route model on vsock flows (#3712)
- [ ] route + endpoint-rule types in `mvm-contract` (`deny_unknown_fields`, fuzzed)
- [ ] injection modes: header, url_path, query_param, basic_auth; per-destination placeholders
- [ ] L7 endpoint rules (method + path glob) → allow / deny / ask
- [ ] default deny for loopback, RFC1918, CGNAT, link-local and metadata ranges; DNS pinned at the endpoint
- [ ] enforcement only in `EgressGate`; every decision audited with route id and rule

### PS-03 — Credential injection UX (#3713)
- [x] `--secret NAME[:HOST,...]` on `run` and `machine run` (finish #3333), fail-closed before boot
- [x] host TLS termination for plan-bound destinations only — each plan binding
      carries its destinations in the signed plan, narrowing the stored
      allow-list; one placeholder per binding, refused and audited anywhere
      else; upstream TLS verified, no fallback to relay
- [ ] secret source references: `env://`, `file://`, `keychain://`, `op://`, `bw://`
- [ ] provider routes: anthropic, openai, github, gitlab, gemini
- [ ] `[secrets]` in `mvm.toml` (names + destinations only)
- [ ] OAuth2 client-credentials and token-response placeholder capture
- [ ] scrub a substituted value out of the response before it reaches the
      guest: a destination that echoes request headers hands the real value
      back today (observed live against an echo endpoint)
- [x] `examples/claude-code` stops putting a raw key in the guest

### PS-04 — Denial feedback (#3714)
- [ ] live, deduplicated egress denials on the host with the correct remedy per reason, plus an exit summary
- [ ] denial → policy draft selector (Grant / Skip), never auto-granting
- [ ] `mvmctl why --host | --path | --tool | --secret` against a resolved policy, `--json`

### PS-05 — Policy files, profiles, resolved manifest (#3715)
- [ ] TOML policy groups and profiles (`extends`, `groups.include/exclude`, `when`, overrides)
- [ ] merge rules from Decision 8 with tests, cycle and depth limits
- [ ] JSON Schema generated from Rust and published in docs
- [ ] `mvmctl policy resolve|show|validate|diff`; `--plan FILE` accepts a resolved manifest
- [ ] `mvm.toml [policy]`; user profiles under the config dir via `mvm-core::config`

### PS-06 — Signed packs and agent profiles (#3716)
- [ ] pack manifest schema and keyless signing workflow in `mvm-templates`
- [ ] `mvmctl search`, `pull ns/name[@ver]`, `run --profile ns/name -- CMD`, `pack ls|rm|update`
- [ ] lockfile with digest pins; admission refuses drift (signed-bundle path, claim 9)
- [ ] publisher trust policy; escape-hatch fields stripped from pack profiles; no host-config writes
- [ ] agent packs: claude, codex, pi, opencode, goose; runtime packs: python, node, rust, go

### PS-07 — Runtime approval supervisor (#3717)
- [ ] `ask` outcomes from PS-02/PS-13/secret use pause at the host and consult a backend
- [ ] terminal backend on the controlling TTY: arming window, control-sequence stripping, empty = deny, no TTY = deny
- [ ] webhook and chain backends; SDK callback through hostlib
- [ ] once / session scope with TTL; nothing silently persisted; every decision audited; rate limit

### PS-08 — Undo, redo, replay, diff (#3718)
- [ ] `vm diff` with content (unified / side-by-side / json), vs boot baseline and between checkpoints
- [ ] exit prompt + `--apply`; pre-apply content-addressed host snapshot; journal; crash recovery
- [ ] session exclusions persisted so restore never deletes ignored files
- [ ] `mvmctl undo` / `redo`; per-step checkpoints; `replay` from a checkpoint with recorded input
- [ ] snapshot Merkle roots in the audit chain; protected-path gate applies to apply

### PS-09 — Detachable sessions (#3719)
- [x] console reattach with bounded scrollback; single client; dev-only and grant-gated (claim 15)
      — the guest agent keeps one console session per VM alive across client
      disconnects (1 MiB replay ring, fresh data port per attach, typed
      `ConsoleBusy`, explicit `take_over`, optional detach timeout); new verbs
      `ConsoleAttach`/`ConsoleDetach`/`ConsoleList` are DevOnly like
      `ConsoleOpen`; `~d` detaches, `~.` ends
- [x] one lifecycle surface: `ps`, `attach`, `detach`, `logs -f`, `stop`, `inspect`
      — `machine attach` (alias of `console`) and `machine detach` join the
      existing `ps`, `logs -f`, `stop`; `inspect` still covers persistent
      machine specs only
- [ ] detached start fails closed; healthcheck and session timeout enforced; restart policy

### PS-10 — Cryptographic audit trail UX (#3720)
- [ ] per-session integrity summary (event count, chain head, Merkle root)
- [ ] hash-chained session ledger (plan id, snapshot roots, image/kernel identity)
- [ ] `mvmctl audit list | show | verify <session>` with `VERIFIED` / `MISMATCH`, filters, `--json`
- [ ] durability (fsync) policy stated and tested; chain-head anchoring documented; rotation default matches docs

### PS-11 — Instruction-file provenance (#3721)
- [ ] trust policy: publishers (keyless/keyed), digest blocklist, deny/warn/audit, project cannot weaken user
- [ ] `mvmctl trust init|sign|verify` for instruction files; keyless signing workflow for our repos
- [ ] pre-boot scan of workspace inputs wired into admission; files read-only in the guest; audited
- [ ] mvm-scout static scan for injection indicators in instruction files

### PS-12 — Environment hygiene (#3722)
- [x] one shared denylist filter (loader, shell, interpreter, password-manager session variables)
- [x] applied to guest env passthrough and every host helper spawn; exact-name re-admission only
- [x] per-family tests and a gate that host spawns use the filter

### PS-13 — Tool-level privileges (#3723)
- [ ] per-tool policy in profiles (argv patterns, routes, secrets, allow/deny/ask)
- [ ] MCP tool gate wired to a live path; secrets bound to (tool, destination)
- [ ] in-guest command mediation for declared tools, reported over vsock and audited

### PS-14 — Existing enforcement plans
The protected-path gate and cumulative action ledger plans (2026-09-24) are
part of this program's security floor and are not duplicated here; PS-08's
apply goes through the protected-path gate.

### PS-15 — Packaging (#3724)
- [ ] deb and rpm built and attested in the release workflow; AUR; nixpkgs-ready derivation
- [ ] crates.io publish for the embeddable crates, ordered and idempotent
- [ ] per-platform wheels and npm packages carrying `libmvm_hostlib`
- [ ] per-artifact release smoke tests

### PS-16 — Nix developer experience (#3725)
- [ ] `#prebuilt` flake output with hashes updated by a release job that opens a PR
- [ ] lean devShell with the pinned toolchain; cold start measured before and after
- [ ] no external cache provider

### PS-17 — Task-runner surface (#3726)
- [ ] recipe inventory and reduction; the top level fits one screen and mirrors CI

### PS-18 — Docs (#3727)
- [ ] one page per capability; client guides for each agent pack; profile and pack authoring guides
- [ ] schema reference generated from PS-05; stale claims fixed

### PS-19 — Fewer feature flags (#3728)
- [ ] inventory; delete, merge or move to runtime config; CI lanes updated

### PS-20 — Unreachable surface (#3729)
- [ ] `up::Args` wired or deleted; `--network-allow` references and `publish-crates.yml` crate list corrected

### PS-21 — CLI thin over mvm-client (#3730)
- [ ] every PS workstream lands library-first; inventory of CLI paths that bypass `mvm-client`
