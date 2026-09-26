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
- [x] hostlib dispatch covers create/boot/run, exec (streaming), files, sessions, stop/rm, logs
      — ABI 1.2: `machine.run`/`machine.create` through `LocalBackend::launch`
      and its `LaunchRequest` validation, `machine.start`, `machine.inventory`
      (persistent-machine sessions and attach, with fail-closed posture), and
      `guest.proc.stream.{open,next,close}` (handle + poll output streaming on a
      bounded reader); the existing `machine.*` and `guest.*` methods cover
      files, stop/rm and logs
- [x] Python and TypeScript facades use hostlib; subprocess transport deleted
      (`_cli`/`_subprocess` gone, `Sandbox`/`Machine` rewritten, `MVM_NO_VM`
      dispatch in-language; the Rust `mvm-sdk` subprocess clients deleted too)
- [x] xtask gate: no SDK source spawns or resolves `mvmctl` (with its own fixtures)
      — `xtask check-no-cli-shellout`, in `check-all`
- [x] `mvm-client` re-exports the embedder surface; Rust quickstart uses only `mvm-client`
      (`mvm_client::authoring`, `RootfsSource`, grants, guest payloads,
      inventory records, plan types, error codes; `tests/embedder_surface.rs`)
- [x] runtime lookup of `libmvm_hostlib` documented (packaging in PS-15):
      `MVM_HOSTLIB_PATH` → packaged in the SDK → beside `mvmctl`; `mvmctl run
      --mode live` sets the variable to the library beside itself
- [ ] the in-process launcher accepts a command override and guest
      environment, so `Machine.run(command=...)`, `Sandbox.create(command=...)`
      and the Obscura `BrowserSandbox` preset boot instead of refusing
      (converge with the CLI's `machine run` front half; drive-plane plan WS2
      "One admission path for every launcher")
- [ ] template/manifest sources launch in-process, so a live `Sandbox.create`
      and the Chromium/Chrome `BrowserSandbox` presets can name a built
      template rather than only an image
- [ ] function-entrypoint dispatch (`await f(...)`, `session(...)`, workload
      references) into a microVM through the library — today it raises a
      typed transport error, and `MVM_NO_VM=1` dispatches in-language; the
      invoke path has to move from the CLI into `mvm-client` first
- [ ] `machine.logs` follow as a stream, like `guest.proc.stream.*`
- [ ] a live-boot scenario driving an SDK through the real library against a
      real guest (the BDD suite records calls in-process)

### PS-02 — Egress route model on vsock flows (#3712)
- [x] route + endpoint-rule types in `mvm-contract` (`deny_unknown_fields`, fuzzed)
      — `policy::routes`, `fuzz_egress_routes`; carried on `NetworkPolicy` in the signed plan
- [ ] injection modes: header, url_path, query_param, basic_auth; per-destination placeholders
- [x] L7 endpoint rules (method + path glob) → allow / deny / ask
      — decided by `EgressGate::decide_route` on every read request; an unbound
      host is terminated only on an explicit `intercept` grant; `ask` is held and
      answered through PS-07's approval supervisor;
      `--allow-endpoint` and `[[network.routes]]` (transient runs; persistent
      machines refuse routes for now)
- [x] default deny for loopback, RFC1918, CGNAT, link-local and metadata ranges; DNS pinned at the endpoint
      — one classifier (`mvm_contract::policy::restricted_address`) for every
      connect, datagram, DNS answer and forward-leg dial; metadata, loopback,
      link-local, CGNAT, `0.0.0.0/8` and embedded IPv4 forms are absolute;
      RFC1918/ULA/multicast/reserved re-admitted only by a grant naming the
      address; refusals audited with their class; the forward leg resolves
      through the gate's recorded answer
- [x] enforcement only in `EgressGate`; every decision audited with route id and rule
      — `host.route.decided { route, rule, outcome, destination, method }`
- [ ] endpoint routes recorded on persistent machines (`MachineSpec`)

### PS-03 — Credential injection UX (#3713)
- [x] `--secret NAME[:HOST,...]` on `run` and `machine run` (finish #3333), fail-closed before boot
- [x] host TLS termination for plan-bound destinations only — each plan binding
      carries its destinations in the signed plan, narrowing the stored
      allow-list; one placeholder per binding, refused and audited anywhere
      else; upstream TLS verified, no fallback to relay
- [x] secret source references: `env://`, `file://`, `keychain://`, `op://`, `bw://`
      — `secret set|put --from REF`, resolved on the host once when accepted
- [x] provider routes: anthropic, openai, github, gitlab, gemini — each with
      its guest variable and credential header, shown by `secret providers`
- [x] `[secrets]` in `mvm.toml` (names + destinations only), merged with
      `--secret` so a flag narrows and never widens
- [ ] OAuth2 client-credentials and token-response placeholder capture —
      moved to #3743
- [x] scrub a substituted value out of the response before it reaches the
      guest: every value substituted in the VM is replaced by its placeholder
      in response headers and bodies (streaming, split-safe), audited as
      `secret.reflection_scrubbed`; identity encoding is requested upstream
      and an encoded response is refused
- [x] `examples/claude-code` stops putting a raw key in the guest

### PS-04 — Denial feedback (#3714)
- [x] live, deduplicated egress denials on the host with the correct remedy per reason, plus an exit summary
      (foreground `run` / `machine run` and `machine logs -f`; `run --json` carries
      `egress_denials`; `mvmctl explain` lists a finished run's refusals. Read from
      the chain the per-VM endpoint already writes, now attributed with `vm_name`)
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
- [x] `ask` outcomes from PS-02 routes and secret use pause at the host and consult a backend
      — `mvm_hostd::supervisor::runtime_approval::ApprovalSupervisor` in the
      per-VM endpoint holds the flow, records the request in the contract's
      `ApprovalLedger`, and asks the broker the launching `mvmctl` binds on
      the VM's `approval.sock`; a binding with `approve = ask`
      (`mvmctl secret set --approve ask`) asks before its placeholder is
      substituted; timeout, no broker or any error denies
- [ ] PS-13 tool calls consult the same supervisor — the `tool_call`
      subject exists; `tool_gate.rs` has no live caller to ask it
- [x] terminal backend on the controlling TTY: arming window, control-sequence stripping, empty = deny, no TTY = deny
      — `/dev/tty`, never workload stdin; an `-it` run denies (`tty_busy`)
      rather than race the workload; `PromptRenderer` is the seam PS-04's
      live denials share
- [x] webhook and chain backends — HTTPS or loopback only, no redirects,
      4 KiB reply cap, timeout; `--approval-mode all|any`
- [ ] SDK callback through hostlib — `CallbackBackend` is the callback type.
      Remaining: a hostlib ABI entry that registers a callback, a broker bound
      per machine hostlib launches, and the Python and TypeScript facades
- [x] once / session scope with TTL; nothing silently persisted; every decision audited; rate limit
      — session approvals live in the endpoint for 15 minutes; 10 prompts a
      minute, the rest denied `rate_limited`; `approval.requested / granted /
      denied / timed_out` chain-signed with the request id
- [x] surface: `--approval tty|deny|webhook=URL` on `run` and `machine run`,
      `[approval]` in `mvm.toml`; default tty for an operator at a terminal,
      deny otherwise
- [ ] a broker for detached and persistent machines — nobody answers today,
      so their asks deny

### PS-08 — Undo, redo, replay, diff (#3718)
- [ ] `vm diff` with content (unified / side-by-side / json), vs boot baseline and between checkpoints
- [ ] exit prompt + `--apply`; pre-apply content-addressed host snapshot; journal; crash recovery
- [ ] session exclusions persisted so restore never deletes ignored files
- [ ] `mvmctl undo` / `redo`; per-step checkpoints; `replay` from a checkpoint with recorded input
- [ ] snapshot Merkle roots in the audit chain; protected-path gate applies to apply

### PS-09 — Detachable sessions (#3719)
- [ ] console reattach with bounded scrollback; single client; dev-only and grant-gated (claim 15)
- [ ] one lifecycle surface: `ps`, `attach`, `detach`, `logs -f`, `stop`, `inspect`
- [ ] detached start fails closed; healthcheck and session timeout enforced; restart policy

### PS-10 — Cryptographic audit trail UX (#3720)
- [ ] per-session integrity summary (event count, chain head, Merkle root)
- [ ] hash-chained session ledger (plan id, snapshot roots, image/kernel identity)
- [ ] `mvmctl audit list | show | verify <session>` with `VERIFIED` / `MISMATCH`, filters, `--json`
- [ ] durability (fsync) policy stated and tested; chain-head anchoring documented; rotation default matches docs

### PS-11 — Instruction-file provenance (#3721)
- [x] trust policy: publishers (keyless/keyed), digest blocklist, deny/warn/audit, project cannot weaken user
      — `mvm_client::instruction_trust::policy`; user policy at
      `<MVM_HOME>/config/instruction-trust.toml`, project policy at
      `<project>/.mvm/instruction-trust.toml` (advisory alone); schema generated
      from the Rust types at `schema/instruction-trust-policy-v0.json`
- [x] `mvmctl trust instructions init|sign|verify|policy`; keyless signing workflow for our repos
      — `.github/workflows/sign-instructions.yml` signs this repository's files
      on a path-filtered push to `main` or dispatch, verifies the bundles through
      the in-process verifier, and uploads them as an artifact (no commit). Other
      repositories copy it rather than call it: a reusable workflow's certificate
      names the called file, whoever called it
- [x] pre-boot scan of `--mount` sources, `--asset` trees and the local workload
      directory wired into admission; every verdict chain-audited
      (`trust.instruction_verified` / `_unsigned` / `_blocked`); `deny` refuses
      with `plan.admission_refused` stage `instruction_provenance`
- [ ] files read-only in the guest: holds for `--mount` (read-only by default, a
      per-launch snapshot, scanned at every admission). Open: volumes attached as
      block devices are not scanned — including `machine volume mount --host DIR`,
      whose directory is re-snapshotted at the next start after a host edit, and
      whose `--rw` private copy keeps in-guest edits across restarts
- [ ] mvm-scout static scan for injection indicators in instruction files
      — in review: tinylabscom/mvm-assurance#202 (`SCOUT-PROMPT-002`, one shared
      instruction-file surface definition)

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
- [ ] per-platform wheels and npm packages carrying `libmvm_hostlib` — the
      loaders already look in `mvm/_native/` (Python) and `native/` (npm) before
      falling back to beside `mvmctl`; the release tarball also has to ship the
      library beside `mvmctl`
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
- [x] inventory; delete, merge or move to runtime config; CI lanes updated

Inventory of every `[features]` entry (crates with feature tables: mvm-core,
mvm-contract, mvm-agentd, mvm-backends, mvm-build, mvm-runtime, mvm-vmm,
mvm-fs, mvm-hostd, mvm-client, mvm-sdk, mvm-hostlib, mvm-cli, mvm-conformance,
mvmctl root; `crates/deps/libkrun-sys` is vendored FFI and stays as-is):

| Feature | Verdict |
|---|---|
| `mvm-runtime/apple-container` | **Deleted** — inert flag; the backend module is compiled unconditionally and nothing enabled or cfg-gated it. |
| `mvm-build/interactive` | **Deleted** — zero enablers anywhere (the Cargo comment claiming "tests/dev enable it" was stale); its two `#[cfg]` blocks in `mvm-egress-proxy.rs` were unreachable. The env-override behaviour was deliberately compile-time (the proxy faces the guest; an env-tweakable allowlist is a security property), so it was deleted rather than moved to runtime config. |
| `mvm-core/attestation-{sev-snp,tdx,apple-device}` | Keep, **owner decision** — dead as compile flags (stubs are always compiled, zero cfg gates) but SPRINT.md records them as documented future scaffolding pending a maintainer ratification call on deleting the stubs themselves. |
| `mvm-agentd/flowmux-async` | Keep, **owner decision** — merge candidate into `addons` (strict subset minus tokio-vsock/hickory); benches and hostd dev-deps use the narrower surface. |
| `mvm-cli/pure-mkfs`, `mvm-cli/builder-vm` | Keep, **owner decision** — near-always-on (only test builds opt out); folding into unconditional code changes what nix builds compile. |
| Everything else (`hostd-transport`, `client`/`client-remote`, `manifest-verify`, `schema` family, `test-support` family, `bdd`, `embed-host-bins`, `contributor-bootstrap`, `release-channel`, `release-artifact-bootstrap`, `template-registry-s3`, `hvf-live-validation`, `trusted-apfs`, `wasm-backend`, `ebpf-telemetry`, `network-perf`, `custom-dns`, `dev-watch`, `tracing-bridge`, `remote`, `deploy-remote`, libkrun family, `attestation-tpm2`, mvmctl `host`/`user`/`dev`) | Keep — each has a live consumer, a CI lane, an xtask gate, or an mvmd-facing contract (mvmd needs `client`/`client-remote`, `hostd-transport`, `remote`, `release-channel`, `tracing-bridge`, the `mvm-contract` family, and the schema emitters). |

CI lanes: no lane referenced the two deleted flags, so `lint-features`,
`lint-features-test-support`, `lint-features-embed`, the release feature-set
check, and the xtask gates (`check-two-surfaces`, `check-core-runtime-free`,
`check-guest-agent-runtime-free`, `check-sdk-transport-free`,
`check-closure-budget`, `check-feature-closure-budget`) are unchanged; the
all-features closure shrinks, which the 488-crate budget ratchet absorbs.
Follow-ups for the owner-decision rows above, plus re-examining
`mvm-build/builder-libkrun` staying in `default`, are best done as their own
small PRs.

### PS-20 — Unreachable surface (#3729)
- [ ] `up::Args` wired or deleted; `--network-allow` references and `publish-crates.yml` crate list corrected

### PS-21 — CLI thin over mvm-client (#3730)
- [x] every PS workstream lands library-first; inventory of CLI paths that bypass `mvm-client`

Inventory of `mvm-cli` paths that reach past `mvm-client` (into
`mvm-runtime`/`mvm-core`/`mvm-hostd`/`mvm-agentd` directly), classified by
severity. `mvm-cli` still names `mvm-core` in 189 files — full elimination is
a long refactor; this table is the tracking list.

**Real bypasses, large (multi-day extractions — follow-up work, not this PR):**
checkpoint state machine (`commands/vm/checkpoint*`, ~6.6k lines); transient-run
core (`exec.rs` + `exec/{session,guest_run,launch_plan,mounts,transient}.rs`,
~4.5k); warm pool (`commands/pool*`, ~2.9k); baked invoke
(`commands/vm/invoke.rs`, 2.8k); agent sessions (`commands/agent_session.rs`,
2.4k); builder-VM env (`commands/env/builder_vm/*`, ~6k, dev-env domain);
image OCI cache (`commands/image/pull_core.rs`, `cache.rs`, ~3.3k); audit
`DecisionStore` reads (`commands/ops/audit.rs` — half-moved, best medium
follow-up).

**Real bypasses, small — moved behind `mvm-client` in this change:**
| Was | Now |
|---|---|
| `snapshot ls/rm` reaching `mvm_runtime::vm::instance_snapshot` + name-registry cleanup + audit | `mvm_client::snapshot::{list_instance_snapshots, remove_instance_snapshot}` (new module; same audit entry) |
| `wait`/`boot-report` vsock `ReadinessStatus` round-trip | `mvm_client::readiness::fetch_live_readiness` |
| transient-run backend selection + egress validation (`exec/backend_select.rs`) | `mvm_client::boot::{select_exec_backend, select_backend_name_for_egress, validate_backend_for_egress, validate_image_egress_backend, validate_image_egress_backend_name}` (tests moved with it) |

**Legitimately CLI-side (not bypasses):** clap parsing, TTY/console plumbing,
table/JSON rendering, install/self-update/packaging, doctor probes, and the
build domain (`mvm_build`/`mvm_sdk` calls), which is a library in its own
right. Pattern for future slices: `mvm_client::guest` (guest RPC verbs) and
`mvm_client::volume::LocalVolumeService` — a service module + DTOs in the
client, CLI left with args + rendering.

## Execution log and handoff

Snapshot as of 2026-09-27, updated after the agents were stopped. This section is the pick-up point: it records what
landed, what is in flight, the decisions taken while executing, and the known
defects found along the way. The workstream checkboxes above remain the
per-item source of truth; `specs/REFACTOR-STATUS.md` is the rollup; tracking
issue #3731 carries the same status as a comment.

### Landed

| PR | Workstream | What it delivered |
|---|---|---|
| #3733 | plan | this plan and its rollup entry |
| #3739 | PS-12 (#3722, closed) | one env denylist for guest passthrough and 26 host helper spawn sites; `check-helper-env-hygiene` gate; launch-plan env keys validated as shell names |
| #3742 | PS-03 | `--secret` on `run` / `machine run`; destinations signed into the plan; per-binding placeholders; host TLS termination only for plan-bound destinations |
| #3745 | PS-03 (#3713, closed) | reflected-credential scrub on every terminated response path; `secret set --from env:// file:// keychain:// op:// bw://`; gitlab/gemini providers and declared headers; `[secrets]` in `mvm.toml` |
| #3748 | PS-02 | one restricted-address classifier; private-range default deny; NAT64/6to4/Teredo embedded-address closure; DNS pinned for the forward leg; five claim-10 witnesses |
| #3749 | PS-02 | endpoint routes (method + path rules) decided at the gate; explicit interception grant; `ask` seam; `--allow-endpoint`, `[[network.routes]]`; `fuzz_egress_routes` |
| #3754 | PS-01 | SDKs call `libmvm_hostlib` in-process (ABI 1.2); subprocess transport deleted; `check-no-cli-shellout` gate; `mvm-client` re-exports the embedder surface |
| #3755 | PS-04 | egress refusals shown on the host live and at exit with per-reason remedies; `explain` gains denials; shared audit follow reader (fixes a tail-after-rotation skip) |
| #3756 | PS-07 | `ask` held at the endpoint, answered by a tty / webhook / chain broker from the launching `mvmctl`; fail-closed; chain-signed `approval.*` entries |
| #3759 | PS-01 | homepage SDK samples follow the in-process READMEs |
| #3770 | PS-21 (#3730, closed) | snapshot, live-readiness and backend selection moved behind `mvm-client`; bypass inventory above |
| #3771 | PS-19 (#3728, closed) | never-enabled feature flags deleted; full inventory recorded |

### Open or queued (at snapshot time)

| PR | Workstream | State / next step |
|---|---|---|
| #3784 | PS-01 (closes #3711) | command/env/template sources, BrowserSandbox presets, in-VM dispatch via `mvm_client::entrypoint`, `machine.logs.stream.*` (ABI 1.3); armed for the merge queue |
| #3751 | PS-09 | console reattach with 1 MiB scrollback, `~d` detach, `--list`, `--force` take-over, `machine detach`; CI red, being rebased and fixed |
| #3753 | PS-11 | instruction-file trust policy, sidecar signatures, pre-boot admission scan, `trust instructions *`, signing workflow; conflicts with main, being rebased |
| #3758 | PS-10 | `session.sealed` entries, derived session ledger, `trust audit sessions` / `show` / `verify <session>`; two claim-8 witnesses; CI being fixed |
| #3767 | PS-20 | unreachable `up::Args` and stale references removed (opened by another session) |
| #3768 | PS-17 | task-runner surface reduced (opened by another session) |
| mvm-assurance#202 | PS-11 | mvm-scout `SCOUT-PROMPT-002` whole-file instruction-injection indicators; awaiting review |

### Stopped mid-flight (2026-09-27)

All program agents were stopped at the user's request on 2026-09-27. Their
unfinished work is pushed as branches with no PR. Commits labelled `wip:` are
formatted snapshots on which clippy and the test gates were **not** run;
every branch needs a rebase onto main, the full gates, and a PR.

| Branch | Workstream | State |
|---|---|---|
| `feat/policy-profiles` | PS-05 (#3715) | 8 commits, complete per its agent; PR body was being drafted |
| `fix/verb-grant-expiry` | #3752 | 3 commits, complete per its agent |
| `feat/no-network-hint` | PS-04 (#3714) | 1 commit, complete per its agent |
| `feat/vm-diff-content` | PS-08 (#3718) | 1 commit + `wip:` (guest diff verb, `diff/`, `workspace.rs`) |
| `feat/egress-injection-modes` | PS-02 (#3712) | `wip:` only (`query_param` / `url_path` / `basic_auth`) |
| `fix/oci-proxy-env-resolution` | #3757 | `wip:` only (`exec/oci_boot.rs`, delivery note drafted) |
| `fix/transient-launch-initramfs` | transient `LocalBackend::launch` | `wip:` only (`universal_initramfs.rs`, `host_shell.rs`) |
| `wip/instruction-provenance-ci-fix` | PS-11 (#3753) | `wip:` on top of `feat/instruction-provenance`: the unfinished CI fix; fold into #3753 |

### Not started

PS-06 packs (needs PS-05), PS-13 tool privileges (needs PS-05), PS-15
packaging, PS-16 Nix DX, PS-18 docs. The PS-06 split is fixed: packs live in
`mvm-templates` and define their own images with their own `mvm.toml` /
`flake.nix`; `mvm-images` builds only the images `mvmctl` itself requires.

### Decisions taken during execution

- **Reflected credentials are scrubbed**, not merely documented: every
  terminated response replaces a substituted value with its placeholder
  (headers and body, across chunk boundaries); upstreams are asked for
  identity encoding and a compressed response is refused
  (`response_encoded_unscannable`). Values under 8 bytes and transformed
  reflections (base64, split markup) are stated limits.
- **Builder VM loses private-range reach** under its open egress policy
  (#3748). Only a flake fetching from a literal private IP is affected; it now
  needs an explicit grant.
- **L7 rules never intercept silently**: an unbound host is terminated only
  when its route grants `intercept`; otherwise `endpoint_rules_unenforceable`.
- **No-network hint**: a run with no network grants that exits nonzero prints
  one line naming `--allow-host`; nothing on exit 0; `"network": "none"` in
  JSON.
- **SDK machines are named and persistent**, stopped and removed by `kill()`,
  because transient `LocalBackend::launch` boots without an initramfs (see
  defects). Revisit once that is fixed.
- **Audit durability**: fsync on authorizing and boundary entries (admission,
  failure, exit, seal, segment events), not every entry. Measured cost per
  fsync: 4-5 ms on macOS, 44-49 ms on the rotational KVM host.
- **Approvals on detached machines deny** until a per-machine broker exists;
  never approve silently.

### Known defects found along the way

- #3752: the run verb grant is minted before a cold guest-runtime build and
  can expire before boot (`VerbNotAuthorized`).
- #3757: a `--manifest` run naming an OCI image gets no guest proxy/CA env.
- Transient `LocalBackend::launch` (`mvm_hostd::run::admit_and_boot_local`)
  attaches no universal initramfs and panics at `/init` for Rust callers.
- #3753 open box: host-directory volumes attached as block devices
  (`machine volume mount --host DIR`) are never scanned for instruction files.
- For review: a boot command override on a `prod` build slot is accepted, the
  same as `machine run -d -- cmd`.
- CLAUDE.md claim-8 prose still says tail truncation is undetectable; after
  #3758, truncation through a session seal is detectable (the ADR-001 table
  carries the precise statement).

### How to resume

1. Read this section, the brief below, and `specs/research/host-kernel-agent-sandbox-comparison.md`, then `gh issue view 3731` for the latest status comment.
2. For each open PR and each branch in "Stopped mid-flight": check CI
   (`gh pr checks N`), rebase onto main keeping both sides of any conflict,
   fix root causes, run the full gates, open or update the PR, and enqueue
   it through the merge queue.
3. Branches are named in the tables; their worktrees live under
   `.worktrees/` beside the repository and may be removed once merged.
4. Next workstreams in priority order: PS-05 → PS-06 and PS-13 → PS-08 →
   PS-15 → PS-16 → PS-18.

### Brief for whoever resumes

Rules this program follows beyond CLAUDE.md and AGENTS.md:

- **Never name the external tool** this plan was compared against — not in
  code, comments, docs, commits, branches, PR titles or bodies, issues, or
  even as a descriptor. Say "the reference tool" in conversation; write
  around it in the tree. The comparison lives in
  `specs/research/host-kernel-agent-sandbox-comparison.md`.
- **Security wins every tie.** Keep the microVM, the NIC-less guest,
  vsock-only egress through the one host endpoint, and the signed, audited
  `ExecutionPlan`. Adopt the experience, never the weaker mechanism.
- **The SDKs never run `mvmctl`**; everything goes through `mvm-hostlib`
  over `mvm-client`, and `check-no-cli-shellout` holds it.
- One worktree per slice under `.worktrees/` beside the repository, one PR
  per coherent slice, pushed early so a stopped session loses nothing.
- Commits and PRs carry no AI attribution and no co-author trailer.
- Arm a green PR with `gh pr merge N --squash --auto` run twice (the second
  run shows it entered the queue), then check the merge queue.
- Tick the plan's boxes, `specs/REFACTOR-STATUS.md`, and a delivery note
  in `specs/sprint/delivery/` in the same PR; update this execution log and
  post a status comment on #3731 when PRs land.
- Delete a worktree's `target/` once its PR is queued; disk is shared.
- Agents may be stopped by an account rate limit. Before assuming work
  landed, check the worktree and the branch on origin.
