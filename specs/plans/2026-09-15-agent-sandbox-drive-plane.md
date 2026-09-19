# An AI agent that boots in the sandbox, driven without argv

Backing: preview
Validation: none — this is a proposed design; no code implements it and no test exercises it.

**Issues:** epic [#3275](https://github.com/tinylabscom/mvm/issues/3275); [#3257](https://github.com/tinylabscom/mvm/issues/3257), [#3258](https://github.com/tinylabscom/mvm/issues/3258), [#3259](https://github.com/tinylabscom/mvm/issues/3259), [#3260](https://github.com/tinylabscom/mvm/issues/3260), [#3261](https://github.com/tinylabscom/mvm/issues/3261), [#3262](https://github.com/tinylabscom/mvm/issues/3262), [#3263](https://github.com/tinylabscom/mvm/issues/3263), [#3264](https://github.com/tinylabscom/mvm/issues/3264); found during WS0: [#3283](https://github.com/tinylabscom/mvm/issues/3283), [#3284](https://github.com/tinylabscom/mvm/issues/3284), [#3285](https://github.com/tinylabscom/mvm/issues/3285), [#3286](https://github.com/tinylabscom/mvm/issues/3286), [#3287](https://github.com/tinylabscom/mvm/issues/3287), [#3288](https://github.com/tinylabscom/mvm/issues/3288)

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
| G9 | Claim 13 and the SDK sidecar catalog named the retired `host.secrets.v1` service even though the live boundary is the host-side substitution endpoint | Resolved: the claim now names and witnesses the endpoint, and the retired service no longer requests the SDK sidecar | WS4 |
| G10 | Resolved: `agent-session resume --boot` is covered at the CLI boundary with a successful cold-tier mock-backend boot, plus its existing refusal tests | `crates/mvm-cli/src/commands/agent_session.rs` | WS4 |
| G11 | Resolved: partially delivered session workstreams use `[~]`, while the fully delivered CLI remains `[x]`; the refactor rollup now says the same | `specs/plans/2026-08-18-durable-agent-sessions.md` | WS4 |
| G12 | `guides/agent-tool-contract.mdx` presents an unshipped surface under a heading a skimming reader takes as shipped | `public/src/content/docs/guides/agent-tool-contract.mdx:93-160` | WS0 |
| G13 | **An off-the-shelf HTTPS client cannot use substitution.** The substituting guest proxy refuses `CONNECT`; the TLS terminator and per-VM egress CA exist but the workload runner never enables them. No shipped agent CLI can reach its model API with the key substituted | `crates/mvm-agentd/src/forward_proxy.rs:62-66,135`; `crates/mvm-runtime/src/workload_runner/runner/spawner.rs:107-110` | WS-S |
| G14 | Secrets reach a workload only through `machine run --entrypoint --from-workload-ir`; transient, persistent and session paths hardcode an empty list, and PID 1 never gets a placeholder | `crates/mvm-cli/src/exec.rs:724`, `commands/vm/up/oci_persist.rs:223`, `exec/session.rs:1036` | WS-S |
| G15 | Resolved: a kept-alive entrypoint machine preserves the requested `--name`, and its completion notice identifies both the machine and session | `crates/mvm-cli/src/commands/machine/runtime.rs`, `commands/vm/invoke.rs`, `exec/session.rs` | WS-S |
| G16 | `secret.substituted` is written only when the upstream response completes; a forward that fails after the credential was sent leaves no substitution entry | `crates/mvm-hostd/src/supervisor/network_endpoint_proxy.rs:1944-1963,2524-2540` | WS-S |
| G17 | Resolved: `machine run` exposes the safe named network presets and a positive AI token budget, and both are represented in Workload IR and the language SDKs | `crates/mvm-cli/src/commands/vm/exec.rs`; `crates/mvm-contract/src/ir/workload.rs`; `crates/mvm-sdk/` | WS-S |
| G18 | Two guest egress entry points with different capabilities: a `CONNECT`/SOCKS relay on 1080 that cannot substitute, and a forward proxy on 18080 that cannot `CONNECT` | `crates/mvm-agentd/src/forward_proxy.rs`; `commands/vm/invoke.rs:1339-1350` | WS-S |

## What already works and is not rebuilt here

- `NetworkPreset::Agent` allow-lists the model API hosts
  (`crates/mvm-contract/src/policy/network_policy.rs`).
- An AI token-budget policy type exists at the per-VM endpoint
  (`crates/mvm-hostd/src/supervisor/network_endpoint_proxy.rs`) and is now
  configurable from `machine run` and Workload IR (G17).
- Credential substitution for absolute-form HTTP requests: placeholder mint
  (`crates/mvm-core/src/keyholder/substitution.rs`), host bindings from
  `mvmctl secret set` enforced at admission
  (`crates/mvm-hostd/src/keyholder/admission.rs`), endpoint handshake writing
  `substitution-env.json`
  (`crates/mvm-vmm/src/host/network_endpoint_spawn.rs`), invoke-time injection
  of the placeholder and proxy variables
  (`crates/mvm-cli/src/commands/vm/invoke.rs`), header substitution after the
  claim-10 gate, and the `secret.substituted` chain-signed entry.
- An SNI-bound TLS terminator (`crates/mvm-hostd/src/supervisor/terminator/tls.rs`)
  exists but is **not wired** on any workload path (G13). Earlier revisions of
  this plan listed it as working; it is not.
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

- [x] Rewrite `public/src/content/docs/guides/nix-flakes.md:277-330` onto the
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
- [x] Write `public/src/content/docs/guides/agent-sandbox.md`: what the guest
      receives (a placeholder), what the host does (substitute after the egress
      gate, audit), what egress is allowed, what the audit chain records, and —
      plainly — every limit a user will hit today (G13–G17). This is the page
      the product claim rests on, so it states what ships, not what WS-S will
      make true.
- [x] Correct the framing in `public/src/content/docs/guides/agent-tool-contract.mdx:93-160`
      so an unshipped surface is not presented as shipped.
- [ ] Add the example to `just e2e-docs` so the documented commands are
      executed, not just written.

## WS-S — Make substitution work for a real agent

Issues: [#3283](https://github.com/tinylabscom/mvm/issues/3283),
[#3284](https://github.com/tinylabscom/mvm/issues/3284),
[#3285](https://github.com/tinylabscom/mvm/issues/3285),
[#3286](https://github.com/tinylabscom/mvm/issues/3286),
[#3287](https://github.com/tinylabscom/mvm/issues/3287),
[#3288](https://github.com/tinylabscom/mvm/issues/3288).

Found while documenting WS0. Without this workstream the example in WS0 can
only use a hand-written client, which is not "an agent boots in the sandbox".
It therefore comes before the example and before WS1.

### Why the terminator is unwired

It was not a decision. The terminator was built against a topology that no
longer exists: its live glue is driven by a TCP listener recovering the
original destination from `SO_ORIGINAL_DST` or a proxy preamble
(`crates/mvm-hostd/src/supervisor/network_endpoint_proxy.rs:68`), which needed
an nftables redirect off a guest NIC. The vsock-only cutover deleted the NIC
and the redirect, and `terminator_listen` has been `None` at every call site
since.

The TLS half is sound and witnessed
(`crates/mvm-hostd/src/supervisor/terminator/tls.rs` —
`bound_sni_terminates_substitutes_and_reoriginates`,
`unbound_sni_is_spliced_without_termination`, and two fail-closed tests), and
it is generic over `Read + Write`, so it does not care that the transport
changed. The *flow* half around it (`handle_https_terminator`) is a parallel
pipeline missing four controls the main one has: it never consults the egress
gate, never meters the AI budget, never runs reversible replacement, and
buffers whole responses. Reuse the TLS half; delete the flow half rather than
re-point it.

### The shape of the fix

Host-only. The guest needs no new code, no new opcode and no new port: the host
**already** refuses an opaque flow to a bound host
(`opaque_refusal_reason`, called from `handle_open_tcp` in
`crates/mvm-hostd/src/supervisor/flowmux.rs:605`), so "a `CONNECT` to a bound
host is never relayed opaquely" is already true — it just fails instead of
working. This work turns that refusal into a terminated flow that runs through
`SubstitutionService::process_body_stream`, which is where the claim-10 gate,
the claim-12 bind check, redaction, AI metering and streaming already live.

Because the decision moves into the host, whether a request gets substituted
stops depending on which proxy the workload happened to pick — which is what
retires the second guest proxy (#3288).

### Decisions taken

- **The per-VM CA is self-signed, not an intermediate under a host root.** The
  existing minting produces an intermediate, which forces every guest client to
  support partial-chain verification; rustls does, but older OpenSSL builds do
  not, and the whole point is that an unmodified client works. A per-VM
  self-signed root keeps the per-VM scope and the name constraints while
  removing the compatibility question.
- **The key is persisted 0600 in the VM state dir**, mirroring the FlowMux
  identity, so a warm-claimed child can terminate under the identity it
  inherited rather than refusing.
- **Cleartext `:80` to a bound host is terminated too.** Symmetric with TLS, and
  it removes the last reason to keep the absolute-form proxy.
- **The `CONNECT`-capable guest client survives; the forward proxy on 18080 is
  deleted.** It cannot stream — it collects the whole body and writes a
  `content-length`, so a streamed model response arrives at once at the end.
- **Termination binds to the flow, not the port**: any port whose first bytes
  are a ClientHello, provided the host is bound. An unbound host is spliced
  untouched — mediating all guest egress was rejected in ADR-023 and stays
  rejected.

### Ordered tasks

- [x] T0. Delete `crates/mvm-hostd/src/supervisor/flowmux/session.rs`, which no
      `mod` declares and the compiler never sees, and repoint the
      `check_single_network_path` entries that name it. A gate asserting things
      about an uncompiled file is worse than no gate.
- [x] T1. `terminable(host, port) -> Option<TerminationMode>` beside
      `opaque_refusal_reason`, with the bound-but-no-intermediate case returning
      `None` so the flow stays refused.
- [x] T2. Generalize `TcpStreamHandle.upstream` to a `FlowSocket` so a flow can
      be backed by a socket pair as well as a TCP stream. The one real refactor.
- [x] T3. `terminator/flow.rs`: terminate, read the request, hand it to
      `process_body_stream`, write the response back chunked, loop for
      keep-alive. Refuse when the decrypted `Host` disagrees with the `CONNECT`
      authority.
- [x] T4. Hook `handle_open_tcp`: gate first, then terminate, refuse or relay.
- [ ] T5. Mint, persist and configure the per-VM CA at the endpoint spawner,
      honouring warm-claim inheritance.
- [ ] T6. Deliver the certificate to the guest on the per-boot identity drive
      and repoint the CA-detection path that keys off a file nothing writes.
- [ ] T7. Point the proxy environment at the one surviving guest proxy.
- [ ] T8. Delete the absolute-form forward proxy and its guest binary (#3288).
- [x] T9. Audit the substitution when the credential is written, with the
      outcome recorded separately (#3286). "Written" is the hand-off to the
      forward leg, which over-reports a connect failure and never
      under-reports a send.
- [ ] T10. One secret-resolution step shared by every admission path (#3284),
      and decide PID 1: wire the boot-time token or delete its guest parser.
- [x] T11. Honor `--name` on the kept-alive entrypoint path (#3285).
- [x] T12. Expose the agent preset and the token budget, or delete them, and
      delete the unreachable network fields on the undispatched verb (#3287).
- [ ] T13. Witnesses in `crates/mvm-hostd/tests/connect_substitution_witness.rs`,
      modelled on the wasm egress witness (real gate, registry and recorder;
      only the forwarder is a test double, because the production one refuses
      loopback): `unmodified_https_client_gets_substituted_credential`,
      `connect_to_bound_host_is_never_relayed_opaquely`,
      `connect_to_bound_host_without_an_intermediate_is_refused`,
      `terminated_connect_is_refused_when_policy_denies_the_destination`,
      `decrypted_host_header_must_match_the_connect_authority`,
      `terminated_connect_streams_events_before_completion`,
      `substitution_is_audited_when_upstream_fails_after_send`,
      `a_warm_claimed_child_inherits_its_parents_egress_intermediate`,
      `the_guest_trust_bundle_contains_the_intermediate_and_no_key`. Add them to
      the ADR-001 rows for claims 12, 13 and 16 in the same change.
- [ ] T14. Correct ADR-001's claim-10 row, which still describes nftables, TAP
      and gateway enforcement plus an acknowledgement hatch that does not exist.
- [x] T15. Make the claim-10 gate a required argument of `SubstitutionService`
      and `FromPlanInputs`, so a service that forwards without deciding the
      destination cannot be built (#3301, the last item of #3302). An endpoint
      config with no network policy now projects default-deny in every egress
      mode; `Wire` used to project no gate at all.
- [x] T16. Record every claim-10 and peer refusal on the substitution path as a
      chain-signed `secret.flow_refused { destination, reason }`, with a fixed
      reason and no request content (#3300). This covers the terminated flow's
      502 arm, which reaches the same check.
- [x] T17. Refuse and record a request carrying a placeholder outside a header,
      in its URL or body, including one split across streamed body chunks
      (#3297). Placeholders are substituted only in headers; one anywhere else
      used to go to the destination as the token itself.

### Residual risk to record, not to hide

The gate resolves the destination for the flow, and the forwarder resolves it
again through the SSRF-guarded resolver — a small rebinding window. Either pass
the admitted addresses into the forward leg or record the gap explicitly.

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

- [x] Make the runtime say what process it is running in before the crate
      exists. Sibling-binary resolution and every self-re-exec used
      `current_exe()` directly, which is `mvmctl` for the CLI and the host
      interpreter for a loaded library. `HostProcess`
      (`crates/mvm-vmm/src/host/aux_bin/host_process.rs`) carries the two facts
      those paths need — a declared helper directory and whether the process is
      a library embedder — and `refuse_cli_spawn` is the single refusal every
      would-be CLI spawn goes through. Declarations are set-once process
      globals rather than environment variables, because mutating the
      environment of a multithreaded host is unsound.
- [ ] Add `crates/mvm-hostlib` at the top of the dependency graph, beside
      `mvm-cli`: it links `mvm-client` and exposes one versioned C ABI over the
      `MvmClient` trait plus the drive verbs. Nothing depends on it, so no cycle
      is possible by construction. The crate, its ABI and the read-only machine
      methods (`machine.list`, `machine.inspect`, `machine.logs`,
      `backend.capabilities`) have landed. Launch, guest and drive methods
      follow.
- [x] Carry an ABI major/minor and a `mvm_hostlib_abi_is_compatible` entry point
      the bindings must call before use, so a mismatched pair fails loudly
      instead of reading a moved struct. Enforced rather than advisory:
      `mvm_hostlib_call` refuses with `MVM_HOSTLIB_ABI_NOT_NEGOTIATED` until a
      binding has negotiated.
- [ ] One admission path for every launcher, so the library cannot admit an
      SDK machine under a different plan than the CLI gives the same request.
      The CLI's boot admission now lives in `mvm-client`
      (`crates/mvm-client/src/admission/`); `mvm_client::launch` still admits
      through `mvm_hostd::run::admit_and_boot_local` and moves onto it next.
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

- [x] Pin the existing tool surface before growing it. Each tool is one row in
      `crates/mvm-mcp/src/lib.rs` carrying its name, description, input schema,
      and the client operation that gates it, so a tool can no longer be
      specified and silently never offered. The advertised surface is pinned in
      `crates/mvm-mcp/tests/fixtures/tool-contract.json` (sorted by name, keys
      sorted, with the gating operation per tool);
      `tool_surface_matches_the_pinned_contract` fails on any difference, and
      `every_specified_tool_is_offered_by_a_real_gate` and
      `every_specified_tool_has_a_handler` hold the table's rows to a real gate
      and a real dispatch arm. Re-bless an intended change with
      `MVM_UPDATE_MCP_TOOL_CONTRACT=1 cargo test -p mvm-mcp --test protocol tool_surface_matches_the_pinned_contract`
      and review the fixture diff as a contract change.
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

- [x] Retire `host.secrets.v1` from the SDK-served service catalog and move
      claim 13's prose and witnesses onto the live host-side substitution
      endpoint. `check-claim-catalog` now refuses the retired broker service as
      claim authority, and a contract regression checks that the retired binding
      does not request the SDK sidecar.
- [x] Validate the claim-authority repair with focused regressions, workspace
      check and clippy, Linux-gated target checks, generated-stub drift checks,
      and the hermetic BDD suite.
- [x] Test `agent-session resume --boot` (`crates/mvm-cli/src/commands/agent_session.rs`).
      Cover a successful cold-tier boot through the CLI-owned client boundary,
      including the approval fence, durable generation transition, admitted
      workload identity, runtime overlay, and mock backend start.
- [x] Reconcile `specs/plans/2026-08-18-durable-agent-sessions.md` (WS6 ticked
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
