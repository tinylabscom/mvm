# rvproxy gateway migration — session close-out + R2 slices 2–4 handoff (2026-06-15)

Archive of the rvproxy-adoption work across this session (ADR-082 / Plan 193),
and the pickup prompt for the remaining R2 build. rvproxy sibling repo:
`/Users/auser/work/tinylabs/mvmco/rvproxy`.

## What landed this session

- **R3 — live libkrun boot through rvproxy: GREEN.** Three rvproxy fixes:
  DNS reply sourced from the gateway IP (#38), guest-bound TCP segmented to the
  MTU (#42 — a full response was EMSGSIZE-tearing the vfkit unixgram transport),
  read/write timeouts cut to per-poll budgets (#53 — a 30s read froze the
  single-threaded pump ~30s/idle-poll). A live `mvmctl dev up` built the
  builder-VM rootfs cold (~540k connections relayed). Lesson recorded: a PR shown
  "MERGED" can be merged into a *closed* stack and never reach main — verify with
  `git merge-base --is-ancestor <fix> origin/main`.
- **Parity gate (Plan 193 WS-1.5): LIVE in CI.**
  `scripts/rvproxy-gateway-parity.sh` + `.github/workflows/rvproxy-parity.yml`
  (mvm #872 / #900 / #903). Runs the claim-10 / flow-audit / Plan-129 witness
  families + the one binary-discriminating conformance witness
  (`gvproxy_dhcp_offer_roundtrips_through_bridge`) against both gvproxy (control)
  and rvproxy (candidate via `MVM_GATEWAY_BIN`); refuses the flip unless rvproxy
  genuinely runs and passes. macos-latest, pinned-rev candidate built from the
  private repo via the `RVPROXY_CHECKOUT_TOKEN` repo secret, fail-closed.
  Validated green end-to-end in CI; `workflow_dispatch` + paths-filtered
  `pull_request`.
- **WS-2 design + R2 contract: MERGED.** mvm #905 (Plan 193 §"WS-2 design": the
  enforcement inventory, the config+event-sink consumption model, who-calls,
  parity-first test plan) + rvproxy #92 (sharpened `specs/plans/014` R2 into the
  four-capability contract). Correction codified in both: the *declared*
  egress-secret substitution stays in mvm's host-side vsock/`:443` terminator,
  NOT a gateway plugin — only undeclared redaction + the placeholder-leak drop
  move to the gateway.
- **R2 slice 1 (deny-by-default flow decision): PR'd, OPEN for review.**
  rvproxy #97 (branch `feat/r2-flow-decision-api`). `[policy] default_egress_deny`
  → `build_gateway_config` → `GatewayConfig` → enforced at `policy_destination_reason`
  (covers TCP/UDP/DNS-resolver), reason `"deny-by-default"`. Backward-compatible
  (defaults false). Tests + fmt + clippy -D warnings clean
  (transport 170 / cli 89 / policy 2 / config 79). **Not auto-merged** — it's
  rvproxy's security-critical core; left for the maintainers.

## Retained for the next session

- rvproxy worktree `.worktrees/r2-build` (branch `feat/r2-flow-decision-api`,
  slice 1) + the Hetzner box checkout `~/rvproxy-r2` — so slice 2 can stack on
  slice 1 if #97 hasn't merged yet.
- Two pre-existing stale rvproxy worktrees (`r3-dhcp-trace2`,
  `r3-libkrun-dns-fix`) are early/parallel-session leftovers on merged branches —
  left untouched on purpose.

## Open follow-ups (settings / coordination, not code)

- **Make the parity lane a required check** (branch protection on mvm `main`).
  Recommended *deferred until WS-2 lands* — today the candidate is pinned and the
  enforcement arm is bridge-side/binary-agnostic, so a ~10× macOS gate per gateway
  PR isn't worth blocking merges yet; it becomes high-value once WS-2 makes the
  witnesses binary-discriminating. Also: a paths-filtered workflow needs a
  skip-shim before it can be a naive required check (non-matching PRs hang).
- **Loop the rvproxy maintainers** on #97 (slice-1 direction) and the merged R2
  contract (#92) so they can schedule / co-own the R2 build.

## Next: R2 slices 2–4 — pickup prompt

Paste into a fresh session once #97's direction is confirmed.

```
Continue building rvproxy R2 (the native flow-decision + audit API that lets mvm delete
its in-line gateway splice). Slice 1 (deny-by-default flow decision) is done and under
review as rvproxy PR #97 (branch feat/r2-flow-decision-api). Build slices 2–4 below.

CONTEXT / SOURCES OF TRUTH
- Contract (what to build): rvproxy specs/plans/014-mvm-adoption-requirements.md §R2 — four
  capabilities. Slice 1 delivered capability 1's config-enforced shape.
- mvm-side consumption design + the parity-first test plan: mvm
  specs/plans/193-rvproxy-network-substrate.md §"WS-2 design".
- North star: each capability must let mvm's bridge witnesses (claim-10 / flow-audit /
  Plan-129-substitution) run against rvproxy's NATIVE path with IDENTICAL verdicts (mvm's
  WS-1.5 parity gate). Preserve: no-bypass (every guest packet through the gate), fail-closed
  (sink/plugin unavailable ⇒ deny), backward-compatible defaults.

REPO / WORKFLOW
- rvproxy repo: /Users/auser/work/tinylabs/mvmco/rvproxy ; crate rvproxy-transport.
- Worktree from slice 1: .worktrees/r2-build (branch feat/r2-flow-decision-api). For each
  slice, branch off origin/main once #97 merges; if it hasn't, stack on
  feat/r2-flow-decision-api.
- Build/test on the QUIET Hetzner box (the Mac is usually saturated):
  ssh -i ~/.ssh/hetzner-rvproxy -o StrictHostKeyChecking=no root@88.99.197.234
  rsync -az --delete --exclude target --exclude .git -e "ssh -i ~/.ssh/hetzner-rvproxy" \
    <worktree>/ root@88.99.197.234:~/rvproxy-r2/
  then on the box: cargo test -p <crate>; cargo fmt -p <crate> -- --check;
  cargo clippy -p <crate> -- -D warnings. Touch crates: rvproxy-transport, rvproxy-policy,
  rvproxy-cli, rvproxy-config.
- TDD per slice (one failing test → minimal impl → green). Open each slice as its own PR for
  the rvproxy maintainers — do NOT auto-merge into rvproxy's core. rvproxy is openly named.

KEY DATAPLANE ANCHORS (verify line numbers; they drift)
- tcp.rs handle_syn() (~698–879): flow BIRTH; policy consult ~706–757 (deny sites already
  emit GuestEgressAuditEvent::denied); upstream connect ~801; conn-table insert ~849–858.
- tcp.rs handle_existing_flow() (~906–1030): FIN/RST close; host-close at
  TcpReceiveResult::Closed.
- tcp.rs TcpConnectionTable::evict_idle() (~51–62): idle eviction.
- gateway/mod.rs: SingleVmGatewayService::handle_frame() dispatch; policy_destination_reason()
  (slice-1 chokepoint); GatewayRuntimeServices::builder() (~444–475) injects sinks.
- gateway/audit.rs: GuestEgressAuditSink trait + GuestEgressAuditEvent (Allowed/Denied/
  ResponseRelayed/NoResponse/Error) — the pattern to model the flow-event sink on.
- rvproxy-core domain/control.rs: NetworkStats counters.
- rvproxy-core transform/plugin/runtime.rs (~62–92): PluginDecisionEvent + PluginDecisionSink
  async-export (JSONL/UDS) pattern. rvproxy-config schema (~336–374): audit sink config.
- rvproxy-core traits/byte_transform.rs (~68–75): ByteTransform + TransformOutcome
  (Continue/Drop) — sees BYTES ONLY, no flow context today.
- rvproxy-core transform/plugin/secret_redaction.rs: secret-redaction-filter (Mutator),
  static find/replace via `replacements`.

SLICE 2 — flow-lifecycle events (capability 2)
  Define a flow-event model: FlowOpened / FlowClosed{reason} carrying 5-tuple + verdict +
  byte counts. Add a sink trait (model on GuestEgressAuditSink), default Noop. Emit:
  FlowOpened on accepted connect, FlowClosed{reason} on FIN/RST (handle_existing_flow),
  idle-evict (evict_idle), and host-close. Wire a consumable export (JSONL + UDS) via the
  audit config, reusing the PluginDecisionSink async-queue. Add fail-closed semantics
  (sink unavailable ⇒ deny) + a flow_decision_sink_failures counter in NetworkStats.
  Tests: open→FlowOpened; deny→FlowClosed{deny-by-default}; FIN/RST/idle→FlowClosed{reason};
  sink-unavailable→deny. Goal: mvm folds these into its chain-signed audit.

SLICE 3 — per-packet observe/modify/flow-kill (capability 3)
  Give the egress transform hook FLOW CONTEXT (flow key / 5-tuple) and a FLOW-KILL outcome
  (today ByteTransform only drops a packet, can't deny a flow). This is the substrate for
  mvm's observer pipeline + the redaction drop. Tests: a transform returning flow-kill tears
  the flow down (sticky) + emits FlowClosed; modify rewrites payload; over-MTU/unserializable
  fails closed (kills flow).

SLICE 4 — mvm-rule-carrying redaction (capability 3, redaction half)
  Extend the secret-redaction-filter contract beyond static find/replace to carry mvm's rule
  set (secret-shaped + PII region rules), so mvm's undeclared-redaction stage is expressible
  as an rvproxy Mutator plugin. IMPORTANT: declared-credential substitution (injecting a real
  secret) STAYS in mvm's host-side terminator — do NOT add it to the gateway (it would widen
  the secret's blast radius; see 014 R2 correction). Tests: a rule masks a matching region,
  passes clean bytes, ignores ingress.

AFTER ALL FOUR LAND (separate, mvm-side): mvm consumes them (config + event sink), runs the
WS-1.5 parity gate against the native path, and only then deletes the gateway_bridge splice +
the Plan-141 per-backend on_packet hooks, and flips the macOS default to rvproxy.
```
