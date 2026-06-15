# Plan 193 — rvproxy network substrate (replace gvproxy/passt)

> **For agentic workers:** proposed / cross-repo-gated. Each workstream needs a
> who-calls audit + failing-test step fleshed out before implementation (Plan
> 177 style). Steps use checkbox (`- [ ]`) syntax.

**Status: 🔴 proposed — cross-repo dependency on `rvproxy`.** The matching
requirements doc lives in the sibling repo at
`rvproxy/specs/plans/014-mvm-adoption-requirements.md`; rvproxy's own
`docs/mvm-integration.md` + `specs/plans/008-orchestration-plane.md` define the
contract. Do not start the mvm cutover (WS-3) until rvproxy confirms the
libkrun-`unixgram` transport (WS-1 finding below).

**Goal:** replace the external **gvproxy** (macOS: libkrun `unixgram` + Vz
`vfkit`) and **passt** (Linux Firecracker) host-side gateways with a single
embeddable/supervised **`rvproxy`** substrate — a Rust-native virtual network
daemon with a typed control API + flow/audit event pipeline.

**Why (the three structural gvproxy/passt problems this removes):**

1. **No native flow API → mvm wraps the datapath in-line.** Claim 10 (default-
   deny egress) + Plan 129 egress-secret substitution + Plan 141's packet
   observer all hang off an *in-line splice + `etherparse`* wrapper bolted onto
   gvproxy **and** passt **separately** (`mvm-hostd` `gateway_bridge.rs`:
   `PlanFlowPolicy`, `FlowOpened`/`FlowClosed`/`PolicyDropped`, deny-by-default).
   rvproxy exposes flow decisions + audit events natively — this collapses mvm's
   most brittle, security-load-bearing networking code into a contract. **Biggest
   win.**
2. **gvproxy(macOS) vs passt(Linux) divergence** special-cased throughout. One
   rvproxy substrate spans mvm's workload backends (macOS VZ/vfkit + libkrun,
   Linux Firecracker, QEMU-unix).
3. **Unclean teardown noise (the bug below).**

## Tracked bug — gvproxy ERROR-on-poweroff (the teardown noise)

mvm's builder VMs are one-shot: they power off when the `nix` build finishes,
closing the vfkit/unixgram socket **before** mvm can stop gvproxy. gvproxy (Go
subprocess) treats this normal disconnect as an error, so **every** builder-VM
completion emits, e.g.:

```
level=error msg="cannot receive packets from …/gvproxy.sock-krun.sock,
  disconnecting: … use of closed network connection"
level=error msg="gvproxy exiting: …"
```

The build succeeds — it is benign log noise that *looks* like a failure. It is
**structurally hard to fix in the gvproxy model**: the VM self-exits before the
host's `GvproxyHandle::Drop` SIGTERM can land, so gvproxy always sees the socket
close first. rvproxy (R1 in the requirements doc) fixes it cleanly: a guest
poweroff is an expected typed event, not an ERROR. Until then it is accepted
noise — do not chase a gvproxy-side fix (gvproxy v0.8.8 has only a `-debug`
bool; there is no log-level flag, and the "bad log level" warning is gvproxy's
own internal default).

## Not-a-fix findings (verified 2026-06-12, do not redo)

- **gvproxy "bad log level" warning** — not mvm-fixable; gvproxy v0.8.8 exposes
  no log-level flag. Goes away with rvproxy.
- **nix-seed re-download** — *not* a normal-use problem: the nix-2.31.1 seed is
  cached under `<cache>/stage0/` and only re-downloaded for a *fresh/isolated*
  `MVM_CACHE_DIR` (e.g. a CI or smoke run). No change warranted.
- **Build slowness** is the **base-VM fingerprint churn**, NOT networking:
  `builder_vm_source_fingerprint` folds in the whole workspace `Cargo.lock` + the
  embedded host-binary byte hashes, so active development busts the builder-VM
  cache (and re-materializes Stage 0, ~9s) on most builds. A separate, careful
  change (narrow the fingerprint to a `Cargo.lock` subset / source identity);
  tracked here as context but out of scope for the rvproxy cutover.

## Workstreams (proposed)

- [x] **WS-1 — transport spike (gate).** libkrun `krun_add_net_unixgram`
      **proven 2026-06-14**: a live `mvmctl dev up` through rvproxy on macOS
      built the builder-VM rootfs cold (~540k egress connections relayed, DHCP +
      DNS + sustained download) and reached "Dev environment ready". Took three
      rvproxy fixes — DNS reply sourced from the gateway IP (#38), guest-bound
      TCP segmented to the MTU (#42, was EMSGSIZE-tearing the transport), and
      read/write timeouts cut to per-poll budgets (#53, a 30s read timeout froze
      the single-threaded pump). Vz `vfkit` + Firecracker `passt` replacements
      still pending. Owner: coordinated with the rvproxy session (their Plan 014
      R3).
- [ ] **WS-1.5 — parity-gate scaffold.** `scripts/rvproxy-gateway-parity.sh`
      runs the claim-10 / flow-audit / Plan-129-substitution witness families
      plus the binary-discriminating conformance gate
      (`gvproxy_dhcp_offer_roundtrips_through_bridge`) against both gvproxy
      (control) and rvproxy (candidate via `MVM_GATEWAY_BIN`), refusing the flip
      unless rvproxy genuinely runs and passes. Validated head-to-head on macOS
      (both PASS) and negatively (a non-gateway binary is REFUSED). Note: the
      enforcement witnesses are bridge-side and binary-agnostic *today*, so this
      proves transport/conformance parity; the enforcement arm becomes
      binary-discriminating only once WS-2 moves enforcement onto rvproxy's
      native flow API. CI lane LIVE: `.github/workflows/rvproxy-parity.yml`
      runs the script on `macos-latest`, building the candidate from a pinned
      rvproxy rev (`RVPROXY_DEFAULT_REF`=`520a5dc`, overridable via the
      `workflow_dispatch` input) cloned with the `RVPROXY_CHECKOUT_TOKEN` repo
      secret, gvproxy as the control; fail-closed without the secret.
      Validated green end-to-end in CI 2026-06-15 (gvproxy PASS + rvproxy PASS +
      enforcement witnesses green). Triggers: `workflow_dispatch` + a
      paths-filtered `pull_request` (gateway-contract files; macos-latest is
      ~10× ubuntu cost per ADR-038, so the filter keeps it off unrelated PRs).
      Remaining activation = make it a **required** check in branch protection
      (a settings decision, not code), and bump `RVPROXY_DEFAULT_REF` as rvproxy
      lands gateway changes.
- [ ] **WS-2 — flow-decision + audit seam.** Port `gateway_bridge`'s
      `PlanFlowPolicy` deny-by-default gate + flow-audit onto rvproxy's native
      flow API; delete the in-line splice/`etherparse` wrapper (Plan 141) and the
      per-backend `on_packet` hooks once parity is proven. Keep claim-10/12/13
      witnesses green throughout. **🔴 BLOCKED on rvproxy R2** (the native
      flow-decision API does not exist yet — only static config policy + a
      packet-level `ByteTransform` + an audit *export* sink). Design + the R2
      contract this needs are in "## WS-2 design" below; mvm authors the
      requirements into rvproxy `specs/plans/014` R2, the rvproxy session builds
      it, then mvm does the port.
- [ ] **WS-3 — backend cutover.** Replace the gvproxy spawn
      (`mvm-build/host_gvproxy.rs`, `libkrun-sys/gvproxy.rs`) + passt with
      `rvproxy run --config` per the integration contract; drop the Homebrew
      gvproxy/passt host deps. Clean teardown (R1) verified: zero error-level
      noise on one-shot builder-VM completion.
- [ ] **WS-4 — `mvm net` verbs.** `mvm net stats/leases/forward` over rvproxy's
      control API (per `docs/mvm-integration.md`); `mvm run --net rvproxy`.

## WS-2 design — port claim-10 enforcement onto rvproxy's native flow API

Operates under ADR-082 (the decision to adopt rvproxy is already made); this is
the *how*, so it lives here, not in a new ADR. Status: design + contract; the
implementation is blocked on rvproxy R2.

### Where enforcement lives today (what WS-2 must reproduce)

Every guest packet traverses the in-line splice in
`crates/mvm-hostd/src/supervisor/gateway_bridge.rs`
(`run_{libkrun_gvproxy,vz_gvproxy,passt}_bridge`) before egress. The splice is
mechanical (datagram/stream copy); the *enforcement* is the load-bearing part,
in three families, all fail-closed:

1. **Coarse deny-by-default gate** — `PlanFlowPolicy: FlowPolicy` evaluates each
   flow at open (`FlowDecisionCtx{direction,dest_ip,dest_port,sni,url_path}` →
   `FlowAction::{Allow,Drop{reason}}`); egress denied unless the admitted policy
   opens it; a Drop emits `FlowClosed{PolicyDropped}` and forwards no bytes.
2. **Per-packet scan + observer pipeline** (Plan 141) — `run_packet_pipeline`
   runs egress scans (`MandatoryDenyEgressScan` link-local/metadata,
   `PlaceholderLeakScan`, `L4PolicyScan`, `DnsSinkholeScan`) then the observer
   chain (`on_packet → Verdict::{Forward,Drop,Modify}`); first Drop kills the
   flow (sticky `killed_flows` set), Modify-over-MTU/unserializable kills
   fail-closed.
3. **Egress secret handling** (Plan 129) — split, and the split matters:
   *declared* substitution (inject a real credential the guest never sees) is a
   **host-side vsock/:80/:443 terminator, not a gateway transform** and STAYS
   there (putting live credentials in the data-plane gateway widens the secret's
   blast radius); only *undeclared* redaction (`RedactingSubstitution`) + the
   `PlaceholderLeakScan` backstop ride the egress path and are in scope for the
   gateway.

Audit is structural: the per-VM `signer_task` is the sole writer, fans every
`FlowOpened/FlowClosed/ObserverFault` to observers *before* chain-signing, and
cannot be displaced by tenant policy. No-bypass (ADR-058): there is no
raw-egress path; a bridge panic `exit(1)`s.

### The R2 contract mvm needs from rvproxy

rvproxy must expose, as a stable documented seam:

- **Flow-open decision** — deny-by-default; for each new flow rvproxy yields a
  verdict `Allow | Deny{reason}` *before* any byte egresses. Two viable shapes;
  the contract should support both and we adopt them in order:
  - **(A, primary) config-declared policy** rvproxy enforces natively — extend
    its existing static `PolicyConfig` to cover mvm's deny-by-default + L4 rules
    + DNS allow-list + the always-on mandatory-deny set + placeholder-leak
    backstop. This covers ~all of today's claim-10 and avoids per-flow IPC.
  - **(B, reserved) a synchronous host callback** over the control seam, for
    decisions not expressible as static config (SNI / url-path / binding-aware).
    Reserved until a real need appears; fail-closed if the callback is slow/down.
- **Flow-lifecycle + decision events** — `FlowOpened`/`FlowClosed{reason}`/
  drop/allowed records (5-tuple, verdict, reason, byte counts) emitted to a sink
  mvm subscribes to and folds into its chain-signed audit. rvproxy's
  `PluginDecisionEvent` JSONL/UDS export plumbing is the right carrier; it needs
  *flow* events generated, not only plugin events.
- **Per-packet observe/modify/drop** — a hook returning Allow/Modify/Drop where
  Drop kills the flow (rvproxy's `ByteTransform` can drop a packet but not yet
  *deny a flow*; `DecisionEmitter` is declared but unimplemented). The undeclared
  **redaction** stage maps to a `Mutator` plugin (rvproxy already ships
  `secret-redaction-filter`) — but it is static find/replace today and mvm's
  redactor is rule/region-based, so the plugin contract must carry mvm's rules,
  not just literal pairs.
- **Fail-closed + no-bypass guarantees, contractually**: if the event sink or a
  required plugin is unavailable, deny; rvproxy must guarantee every guest packet
  passes policy+scan before egress (it is the gateway, but the contract must say
  so, mirroring ADR-058).

Explicitly **out of the gateway**: declared-credential substitution stays in
mvm's host-side terminator. (This corrects rvproxy `014` R2's "move it onto the
gateway" aside.)

### How mvm consumes it

rvproxy runs as a supervised subprocess (`rvproxy run --config`, local UDS
control API — `docs/mvm-integration.md`), so the binding is **config + event
sink**, not an in-process trait. mvm: (1) lowers the admitted `NetworkPolicy`
into the rvproxy config (the policy ENGINE moves into rvproxy for shape (A));
(2) subscribes to the flow/decision event sink and re-emits into the chain-signed
audit (claim-10 audit stays mvm's source of truth); (3) keeps the parity gate
(WS-1.5) as the cross-check that rvproxy's engine matches mvm's verdicts before
the splice is deleted. The splice (`gateway_bridge` + the Plan 141 per-backend
`on_packet` hooks) is deleted only after parity holds on the *native* path.

### Who-calls (to flesh out before implementation, Plan 177-style)

- `PlanFlowPolicy` / `FlowPolicy::evaluate` callers — all inside the three
  `run_*_bridge` fns; no external consumers, so the trait can be retired with the
  splice.
- `run_packet_pipeline` / `build_egress_scan` / `RedactingSubstitution` callers
  — same; the scan/redaction *logic* must be re-expressed as rvproxy config/rules
  (or a plugin), not deleted.
- `signer_task` / `AuditEmitter` flow entries — the audit chain is NOT retired;
  it gets re-fed from the rvproxy event sink. Confirm no other writer.
- mvmd consumers of `mvmctl::runtime::*` gateway types — audit before changing
  any public shape.

### Failing-test plan (parity-first, witnesses stay green)

1. Stand up the rvproxy native-policy path behind a flag; keep the splice.
2. Extend the WS-1.5 parity gate so the claim-10 / flow-audit / substitution
   witness families run against the **native** rvproxy path and assert identical
   verdicts to the bridge path (today they are bridge-side and binary-agnostic;
   this is what makes them binary-discriminating).
3. Only when the native path is green on every witness do we delete the splice
   and the per-backend `on_packet` hooks (Plan 141).

### Dependency

Hard-blocked on rvproxy R2. mvm authors these requirements into rvproxy
`specs/plans/014` R2 (done in lockstep with this design); the rvproxy session
owns building the substrate.

## Cross-repo dependency
rvproxy `specs/plans/014-mvm-adoption-requirements.md` (mvm-authored requirements)
+ `docs/mvm-integration.md` + `specs/plans/008-orchestration-plane.md`. The
rvproxy session owns the substrate; mvm owns the cutover + the claim witnesses.

## Non-goals
- mvm's vsock agent/substitution channel (separate from the network gateway).
- mvmd fleet placement (rvproxy stays host-local + replaceable).
- The base-VM fingerprint slowness (separate change; noted above for context).
