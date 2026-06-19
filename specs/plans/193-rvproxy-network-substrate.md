# Plan 193 — rvproxy network substrate (replace gvproxy/passt)

> **For agentic workers:** in progress. Keep the mvm-side cutover parity-first:
> every destructive deletion/default flip needs a who-calls audit plus a green
> witness before implementation (Plan 177 style). Steps use checkbox (`- [ ]`)
> syntax.

**Status: 🟡 in progress — rvproxy R2 is available; mvm-side native parity is
partly landed.** The matching requirements doc lives in the sibling repo at
`rvproxy/specs/plans/014-mvm-adoption-requirements.md`; rvproxy's own
`docs/mvm-integration.md` + `specs/plans/008-orchestration-plane.md` define the
contract. WS-1 transport, WS-1.5 parity scaffold, native config emission/launch,
native flow-audit refeed, and binary-discriminating native enforcement witnesses
are landed. Remaining cutover work is deleting the splice/Plan-141 hooks only
after the native gate is green by default, flipping the default bridge path,
adding the transparent terminator, and making the parity gate required.

> **Priority update 2026-06-15:** Plan 200 consumes this plan as security/network
> substrate. `mvmctl machine --net` and `allow-host` must use the current
> admitted network path until rvproxy is ready; do not block the initial machine
> UX on rvproxy unless a feature requires native rvproxy flow decisions. Do not
> bypass Plan 193/197 guarantees for UX.

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

## Workstreams

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
- [x] **WS-1.5 — parity-gate scaffold.** `scripts/rvproxy-gateway-parity.sh`
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
      Scaffold complete. Remaining activation = make it a **required** check in
      branch protection (a settings decision, not code), and bump
      `RVPROXY_DEFAULT_REF` as rvproxy lands gateway changes.
- [ ] **WS-2 — flow-decision + audit seam.** Port `gateway_bridge`'s
      `PlanFlowPolicy` deny-by-default gate + flow-audit onto rvproxy's native
      flow API; delete the in-line splice/`etherparse` wrapper (Plan 141) and the
      per-backend `on_packet` hooks once parity is proven. Keep claim-10/12/13
      witnesses green throughout. **🟢 UNBLOCKED** — rvproxy R2 shipped (rvproxy
      `014` R2 slices all merged: flow-lifecycle `FlowEvent`/`FlowEventSink`,
      flow-context + `FlowKill` + sticky teardown + the over-MTU/unserializable
      fail-closed guard, and the rule-carrying `secret-redaction-filter` region
      rules). Note the consumption nuance: R2's primary seam is **in-process
      Rust traits** (rvproxy embedded as a lib); mvm consumes rvproxy as a
      **subprocess** (`rvproxy run --config` + event sink), so two R2 pieces are
      followups mvm needs from rvproxy: a JSONL/UDS **`FlowEvent` export** (slice-2
      deferral) and **port/proto + DNS-hostname policy config** (slice-1 covers
      only `default_egress_deny` + CIDR allow/deny). Sub-slices:
  - [x] **2a — policy lowering, full fidelity.**
        `supervisor::network::rvproxy_policy::lower_policy` projects a resolved
        `CanonicalEgress` (+ DNS allow-list) into rvproxy's `[policy]` table at
        **full claim-10 fidelity** now that rvproxy ships the L4 + DNS config
        (rvproxy `014` follow-ups): `default_egress_deny` + mandatory-deny
        `cidr_denylist` + `l4_allowlist` (proto/CIDR/port) + `dns_hostname_allowlist`
        (dotted-suffix sinkhole). The unit parity oracle `permits_flow` mirrors
        rvproxy's `policy_flow_reason` and is proven verdict-identical to
        `CanonicalEgress::permits` for every probed proto/ip/port (no longer just
        the IP layer); `dns_permits` mirrors `DnsSinkholeScan`. The only splice
        residual left (`RvproxyPolicyGaps`) is the byte scans (placeholder-leak +
        undeclared redaction), which ride the transform path, not `[policy]`.
        Pure, no live boot; deletes nothing. (Started as an IP-coarse pre-filter;
        completed to full L4+DNS once rvproxy #115/#119 landed; the
        `dns_hostname_allowlist` field name matches rvproxy main, which merged the
        DNS sinkhole as #119.)
  - [ ] **2b — config emission + native launch path.** Wrap the lowered
        `[policy]` in the full rvproxy config (network/api/forward/audit — the
        audit section points the `FlowEvent` JSONL/UDS export at mvm for 2c) and
        launch `rvproxy run --config` behind a flag, keeping the splice. Real
        config-parse validation lands here via the parity gate (the emitted TOML
        is fed to the actual rvproxy binary). (Overlaps WS-3.)
    - [x] **config emission.** `render_rvproxy_config` emits the complete
          single-vm config (id/mode/network/backend/transport/api/dns/audit +
          the lowered `[policy]`) over mvm-side `Serialize` structs — no rvproxy
          crate dep. Transport is the proven `BackendKind::Vfkit` +
          `TransportKind::Vfkit` unixgram pair (same shape rvproxy's gvproxy-compat
          mode builds), so `run --config` reaches WS-1's validated boot path. The
          emitted TOML is parsed + `RvproxyConfig::validate()`d against the real
          rvproxy binary (off-tree); that caught a silent schema-fidelity hole —
          `DnsConfig` renames its resolvers field to `upstream`, so emitting
          `upstream_resolvers` was dropped to empty and failed validation. Also
          set the four `[policy]` toggles rvproxy defaults to `false`
          (`allow_transport_{ingress,egress}`, `allow_dns_{local,upstream}`) or
          the dataplane drops every frame.
    - [x] **native launch wiring.** `gvproxy::spawn` takes an optional native
          config: `Some` → `<MVM_GATEWAY_BIN> run --config <path>`, `None` → the
          gvproxy-compat flags (`NetworkingMode::Gvproxy.native_config`,
          `#[serde(default)]`). The `mvm-libkrun-supervisor` bin, when
          `MVM_NETWORKING=native`, renders the config from the admitted bundle
          (`rvproxy_launch::write_native_gateway_config`) into the per-VM scratch
          dir and sets `native_config` before the gateway spawn — fail-closed if
          the render fails. The splice still runs and shares the *same* egress
          resolution (`egress_and_dns_from_effective`, now consumed by both), so
          this is additive belt-and-suspenders. Validated against the real
          rvproxy binary three ways: emitted config parses + `validate()`s
          (off-tree), `rvproxy run --config` binds the vfkit + API sockets on
          macOS, and `native_spawn_then_drop_reaps_child` boots a real binary
          through `spawn(.., Some(cfg))`.
    - [x] **native launch — proven live on a real libkrun workload boot.**
          `mvmctl up --flake examples/sleeper --hypervisor libkrun -d` with
          `MVM_NETWORKING=native` + `MVM_GATEWAY_BIN=<macOS rvproxy>` +
          `MVM_GATEWAY_BRIDGE=1`: the workload took the bridge path
          (`tenant_id=Some`), the supervisor's native block fired and rendered
          the correct policy config (`<vm>/rvproxy.toml` — deny-by-default + the
          6-entry mandatory-deny denylist + vfkit transport + flow-audit export),
          and the gateway launched as `rvproxy run --config` (native — no
          `gvproxy.log`, vs gvproxy-compat). Two findings: (1) the bridge is
          off-by-default — `populate_audit_substrate` (which sets `tenant_id`) is
          gated behind `MVM_GATEWAY_BRIDGE=1` (the old gvproxy bridge "vfkit
          socket address is empty" issue; the native `run --config` path does not
          hit it, so this work helps un-gate it — deferred to 2d with the parity
          gate); (2) **fixed** — the bridge path refused under `MVM_DATA_DIR`
          because `validate_audit_substrate` resolved the signing-key dir through a
          private HOME-fixed helper while admission + `compute_audit_substrate`
          use the data-dir-aware `mvm_keys_dir()`; the validator now uses the same
          `mvm_keys_dir()` (path-traversal defense intact; resolves across the
          supervisor process moat; honors the data-dir override per the
          isolation invariant and the out-of-scope-malicious-host threat model).
    - [x] **native launch — guest data-path proven live.** With the audit-substrate
          fix, a real `mvmctl up --hypervisor libkrun -d` (native + bridge,
          `MVM_DATA_DIR`-isolated, no key symlink) booted clean: plan admitted →
          `validate_audit_substrate` passed → supervisor stayed up (`libkrun.pid`
          written) → native `rvproxy run --config` bound the API + vfkit sockets
          (no `gvproxy.log`) → rvproxy logged `tenant_id="rv2b"` +
          `ConnectionEstablished`/`accepted transport connection` (libkrun's
          virtio-net connected to the native gateway). The guest's data path runs
          through native rvproxy enforcing the rendered policy.
    - [ ] **native launch — egress enforcement matrix.** sleeper idles (no
          egress), so the allow/deny/flow-audit verdicts aren't exercised yet;
          needs an egress-attempting fixture (curl an allowed host + a denied
          host, assert the verdicts + flow-audit entries). The last check before
          2d deletes the splice.
  - [x] **2c — flow-event sink → audit re-emission (parser + mapper + pump).**
        `supervisor::network::rvproxy_flow_audit` parses rvproxy's exported
        dataplane-audit JSONL/UDS stream, keeps only the `flow` records, and maps
        each rvproxy `FlowEvent` onto mvm's audit `FlowEvent` (`opened`→`Opened`;
        `denied` close→`Closed{PolicyDropped}` for claim-10; normal
        `closed`→`Closed{Eof}`), with a per-connection `flow_id` from the 5-tuple
        (more granular than the splice's coarse `<vm>-egress`). `pump_flow_audit`
        runs over any `BufRead` (real source = the JSONL file / `UnixStream`) and
        hands mapped events to a sink; the production sink forwards into
        `signer_task`'s mpsc channel so they're chain-signed. Byte-scan kills stay
        splice-side, so rvproxy only emits opened/denied/normal-closed — the
        mapping is total. Pure + golden-tested; spawning the reader thread + the
        sink→channel wiring lands with 2b (the export only flows once rvproxy runs
        with the emitted config).
  - [x] **2d task 1 — native flow-audit → chain feed, PROVEN LIVE.** When the
        gateway is native `rvproxy run --config`, libkrun attaches **directly**
        to rvproxy (`run_supervisor`, no splice in the data path) and a
        standalone `spawn_native_audit_feed` runs `signer_task` +
        `rvproxy_flow_audit::follow_flow_audit`, tailing rvproxy's flow-audit
        export into the chain. Validated end-to-end (2026-06-16, after the
        libkrun workload-egress fix landed): a real `mvmctl up --hypervisor
        libkrun --wait` of `examples/egress-probe` through native rvproxy +
        `MVM_GATEWAY_BRIDGE=1` →
        (1) the guest reached rvproxy (frames processed),
        (2) native rvproxy **enforced deny-by-default** (`workload.exit=3`, both
            targets blocked; rvproxy logged `guest egress denied tcp …->1.1.1.1:443
            deny-by-default`),
        (3) rvproxy **exported `flow` records** (`closed/denied/deny-by-default`),
        (4) the follower **fed them into the chain-signed audit** — `local.jsonl`
            shows `gateway.flow_closed` with **per-connection** `flow_id`
            (`egp-egress-tcp-192.168.127.2:39861-1.1.1.1:443`, reason
            `policy_dropped`), strictly more granular than the splice's coarse
            `<vm>-egress`. The claim-10 audit is now sourced from native rvproxy.
  - [x] **2d task 2 — native-enforcement parity arm (binary-discriminating).**
        `rvproxy_native_denies_and_exports_flow` (gated `MVM_GATEWAY_NATIVE_E2E=1`
        + `MVM_GATEWAY_BIN`) spawns the candidate as native `rvproxy run --config`
        with a deny-all `[policy]` + flow-audit export, plays the VMM directly
        against rvproxy's vfkit socket (no VM, no splice), sends a guest TCP SYN
        to a denied dst, and asserts rvproxy **exports a `verdict:"denied"` flow
        record** — proving native deny-by-default enforcement. gvproxy can do
        neither (no `run --config`, no flow export), so it discriminates the
        binary. Wired as `scripts/rvproxy-gateway-parity.sh` step [2/4]
        (`run_native_enforcement`), required to PASS in the verdict. Validated
        locally: all four arms green against the rvproxy binary + gvproxy control.
  - [x] **2d task 2b — native allow/deny matrix (binary-discriminating).**
        `rvproxy_native_admits_listed_denies_unlisted` renders ONE `[policy]` with
        an L4 allow rule for a public /24 + deny-by-default and probes it twice
        (rvproxy accepts one vfkit connection per spawn and only its first
        post-handshake frame is reliably processed, so each dst gets its own
        spawn of the identical config): the **unlisted** dst (8.8.8.8) is denied
        with reason `l4_allowlist_miss` — proving the rendered allow-list is
        active and consulted (deny-all denies for `deny-by-default` instead) —
        while the **listed** dst (93.184.216.34) is **not** denied, proving
        admission. Admission is asserted as absence-of-deny because rvproxy only
        exports an admitted flow once its upstream connect resolves and its SSRF
        guards (`guest_to_host`/`lan_access`) refuse every locally-reachable
        address before the L4 allow-list is consulted; the unlisted-deny half
        proves the frame path enforces under this config, so the listed half is
        meaningful. Both native witnesses share a `native_first_frame_probe`
        helper. Folded into `scripts/rvproxy-gateway-parity.sh` step [2/4]
        (`run_native_enforcement` now runs the whole `rvproxy_native` family).
        Validated locally: all four gate arms green, both witnesses 5/5.
  - [x] **2d task 2c — remove the dead mvm-side open-policy slot.**
        `BridgeConfig.policy` and the production `AllowAll` `FlowPolicy` are
        gone. `run_bridge_inner` already derived the live flow gate from the
        resolved bundle or threaded bare `NetworkPolicy`, failing closed to
        deny-all when neither exists; the field was a write-only footgun. The
        four supervisor-bin construction sites no longer pass an ignored
        policy, and tests that need an intentionally open flow use
        `PlanFlowPolicy::from_network_policy(NetworkPolicy::unrestricted())`.
  - [ ] **2d — remaining: splice deletion.** Delete the splice + Plan-141
        `on_packet` hooks once the gate is green by default and the native audit
        feed is the sole path. Design + the R2 contract are in "## WS-2 design"
        below.
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
implementation is no longer blocked on R2 itself; deletion is gated on proving
the native subprocess path is green by default and keeps the claim witnesses
equivalent.

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

rvproxy R2 shipped, and mvm has consumed the subprocess-facing pieces needed for
native config emission plus flow-audit JSONL refeed. Remaining dependency work is
the cutover contract: keep the native parity gate green by default, add the
transparent terminator requirement, and only then delete the splice and default
to the native path.

## Cross-repo dependency
rvproxy `specs/plans/014-mvm-adoption-requirements.md` (mvm-authored requirements)
+ `docs/mvm-integration.md` + `specs/plans/008-orchestration-plane.md`. The
rvproxy session owns the substrate; mvm owns the cutover + the claim witnesses.

## Non-goals
- mvm's vsock agent/substitution channel (separate from the network gateway).
- mvmd fleet placement (rvproxy stays host-local + replaceable).
- The base-VM fingerprint slowness (separate change; noted above for context).
