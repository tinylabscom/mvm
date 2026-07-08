# Plan 103 — W6.A gateway audit substrate (implementation tracker)

Implementation tracker for [Plan 102](102-gateway-audit-substrate-impl.md)
W6.A — gateway audit substrate plumbing. Single-source-of-truth
progress checklist for the 9-commit PR landing the no-bypass,
observable, mediable substrate across all three backends
(libkrun+passt, libkrun+gvproxy, Vz+gvproxy).

## Spec + design references

- [Plan 102](102-gateway-audit-substrate-impl.md) — design contract
  (W6.A substrate plumbing + W6.B real flow extraction)
- [Plan 101](101-in-guest-volume-encryption-and-gateway-audit.md) —
  parent plan (claim 10 leg 2 wave map)
- [ADR-058](../adrs/058-claim-10-bytes-leaving-trust-boundary.md) —
  threat model for claim 10
- [ADR-002](../adrs/002-microvm-security-posture.md) — claim list
  (extended to include claim 10)
- [SPRINT.md](../SPRINT.md) — Sprint 56 §W3 sprint slot

## Substrate guarantees this PR commits to

1. **No bypass.** Every byte traverses an auditable bridge. TSI
   removed; supervisor admission refuses non-bridged net configs.
2. **Observable.** Every flow open/close emits a signed event into
   the per-tenant chain + live subscribers see NDJSON.
3. **Mediable.** `FlowPolicy` hook trait at the bridge layer with
   `AllowAll` default; Plan 74 / SNI / L7 plug in later.
4. **Per-tenant isolated.** No cross-tenant coupling introduced.

## Pre-flight

- [x] `gh pr view 452` — merged 2026-05-26
- [x] `git worktree list` + `gh pr list --state open` — no
      collisions on TSI removal or Plan 102 area
- [x] Worktree created at
      `.claude/worktrees/plan-101-w6a-substrate/` off `origin/main`
      (5ea4b84f)
- [ ] Read `crates/mvm-libkrun/src/sys.rs` — confirm
      `add_net_unixstream_fd` + `add_net_unixgram_path` dup
      semantics
- [ ] Read `crates/mvm-supervisor/src/audit.rs` — `AuditEntry` /
      `AuditSigner` shape
- [ ] Read `crates/mvm-supervisor/src/audit_recorder.rs` —
      unified `Recorder` substrate (pick emission path)
- [ ] Read `crates/mvm-core/src/config.rs:62-117` —
      `mvm_data_dir()` + `ensure_private_dir()`
- [ ] Read `crates/mvm-vz-supervisor/Package.swift` + `Sources/` —
      Swift `socketpair` + `XCTest` async patterns
- [ ] Lock grep list for TSI removal:
      `tsi` / `Tsi` / `TSI` / `MVM_NETWORKING`
- [ ] `mvmd` repo state confirmed clean before Phase 6 write

## Phase 6 — mvmd cross-repo spec (first action after this commit)

- [ ] Pick next free plan number in
      `tinylabscom/mvmd/specs/plans/` (current latest = 45)
- [ ] Write `tinylabscom/mvmd/specs/plans/<NN>-network-manager.md`
      with the verbatim content in Plan 102's working tracker
- [ ] Commit + push in mvmd repo
- [ ] Update mvmd `specs/SPRINT.md` if a sprint slot is open

## Commit sequence

### Commit 0 — this file (tracker setup)

- [x] Plan 103 tracker file written
- [x] SPRINT.md Sprint 56 §W3 updated with Plan 103 reference
- [x] SPRINT.md Sprint 56 §W3 §"Out of scope for this sprint"
      extended with 4 ADR-058 items
- [x] SPRINT.md Sprint 56 §Non-goals (explicit) refined
- [ ] Commit + push the worktree branch (initial PR open)

### Commit 1 — Kill TSI

- [x] `crates/mvm-build/src/libkrun_builder.rs:134-207` —
      remove `NetworkingPreference::Tsi` variant
- [x] Remove `=tsi` arm in `resolve_networking_mode` (now warns
      with a TSI-specific message + falls back to per-OS default)
- [x] Remove default-Tsi dispatch arm in `apply_networking_mode`
- [x] `crates/mvm-cli/src/doctor.rs` — gateway probe now `ok: false`
      when missing (was `ok: true`); TSI escape language removed
- [x] Docs sweep:
      - [x] `CLAUDE.md` (TSI paragraph)
      - [x] `specs/adrs/055-passt-virtio-net.md` (Status amended;
            §"Decision" Tsi-env-var note removed;
            `MVM_NETWORKING={tsi,…}` → `{passt,gvproxy}`)
      - [ ] `specs/plans/72-builder-vm-via-libkrun.md` (deferred
            to commit 8 amendments — historical plan, low impact)
      - [ ] `specs/plans/76-secure-fast-boot-and-dx.md` (commit 8)
      - [ ] `specs/plans/88-gvproxy-macos-backend.md` (commit 8)
      - [ ] `removed legacy macOS archival spec` (commit 8)
- [x] Delete tests touching `MVM_NETWORKING=tsi` (two assertions
      in `resolve_networking_mode_parses_env`)
- [x] New test: `tsi_no_longer_resolvable` (five case variants of
      `tsi` all fall back to per-OS default)
- [x] `cargo test -p mvm-build` green (273 lib + 49 integration);
      `cargo clippy -p mvm-build -p mvm-cli -- -D warnings` clean

### Commit 2 — `FileAuditSigner` cross-process flock

- [x] `crates/mvm-supervisor/src/audit_file.rs:123-180` —
      wrap `sign_and_emit` body in `rustix::fs::flock(fd, LockExclusive)`
      (added `flock_exclusive` helper)
- [x] Re-read chain tail under the lock to refresh cursor
- [x] In-memory `cursors: Mutex<HashMap>` becomes fast-path hint
      (overwritten with fresh on-disk hash on every emit)
- [x] `rustix = { version = "1.1", features = ["fs"] }` added to
      mvm-supervisor `[target.'cfg(unix)'.dependencies]`
- [x] Test: `flock_serializes_two_signer_instances_on_same_tenant_file`
      (two `Arc<FileAuditSigner>` instances racing 50 entries each
      from concurrent tokio tasks; `verify_audit_chain` returns
      100, chain holds) — chosen over fork+exec helper as a tighter
      regression that exercises the exact in-memory-cursor-vs-disk
      race the flock prevents
- [x] `cargo test -p mvm-supervisor --lib audit_file::` green
      (10 tests; pre-flock implementation would fail
      `flock_serializes_two_signer_instances_on_same_tenant_file`)

### Commit 3 — Flow event types + `AuditEntry` helpers

**Design adjustment:** the supervisor's chained `AuditEntry`
(`mvm-supervisor/src/audit.rs:33`) uses `event: String` +
`labels: BTreeMap` — not a typed `AuditAction` enum. The Plan
102 spec's "add `AuditAction::Flow*`" landed in the **wrong
enum** (`mvm-core::policy::audit::AuditAction` is the
unrelated v1 fleet-orchestration enum). Right answer: extend
the supervisor's `AuditEntry` with typed helpers + canonical
event strings + structured field types. Free-form `event`
already matches existing chain emitters (e.g.,
`"plan.verified"`).

- [x] `crates/mvm-supervisor/src/audit.rs` — add
      `pub enum FlowDirection { Egress, Ingress }` with
      `#[serde(rename_all = "snake_case")]` + `as_str()`
- [x] Add `pub enum FlowCloseReason { Eof, BridgeError,
      PolicyDropped, Shutdown }` with same wire shape
- [x] Add `pub const FLOW_OPENED_EVENT: &str =
      "gateway.flow_opened"` + `FLOW_CLOSED_EVENT =
      "gateway.flow_closed"`
- [x] Add `AuditEntry::flow_opened(plan, bundle, flow_id, direction)`
      helper — wraps `for_plan` with canonical event +
      `flow_id` + `direction` labels
- [x] Add `AuditEntry::flow_closed(plan, bundle, flow_id,
      direction, reason)` helper — adds `reason` label
- [x] Tests: 8 new (flow_direction wire pin + serde
      roundtrip; flow_close_reason wire pin + serde roundtrip;
      both helper-construction shape tests; helpers inherit
      plan audit_labels; reasons distinguishable on wire)
- [x] `cargo test -p mvm-supervisor --lib audit::` green
      (14 tests: 6 existing + 8 new)

### Commit 4 — `mvm-supervisor::gateway_audit` (subscriber sink)

- [x] Created `crates/mvm-supervisor/src/gateway_audit.rs`
      (~210 lines including tests)
- [x] `pub struct GatewayAuditSink { listener, tx: broadcast,
      socket_path }`
- [x] `pub fn bind(path)` — `create_dir_all` + chmod 0700 on
      parent, pre-unlinks stale path, `UnixListener::bind`,
      chmod 0700 on socket file
- [x] `pub fn subscribe() -> broadcast::Receiver<String>` +
      `pub fn sender() -> broadcast::Sender<String>` (bridge
      holds the sender)
- [x] `pub async fn run(self) -> !` — accept loop, per-subscriber
      `forward_to_subscriber` task spawned on each accept
- [x] Bounded broadcast(256) via `SUBSCRIBER_CHANNEL_CAPACITY`;
      `Lagged` → log + close subscriber connection
- [x] Module wired in `lib.rs` between `firewall` and
      `hickory_dns`
- [x] Tests (3 new):
      - [x] `bind_pre_unlinks_stale_socket` — confirms 0700 + rebind
            over stale regular file works
      - [x] `accepts_many_subscribers_fans_out_jsonl` — 3 clients
            connect, sender push once, all 3 read the same line
      - [x] `slow_subscriber_does_not_block_fast_subscriber_or_sender`
            — bursts > capacity events; slow peer's stream stalls
            (write_all blocks); fast peer still receives ≥ 50 lines
- [x] `cargo test -p mvm-supervisor --lib gateway_audit::` green
      (3 tests)

### Commit 5 — `mvm-supervisor::gateway_bridge` + `FlowPolicy` hook

- [x] Created `crates/mvm-supervisor/src/gateway_bridge.rs`
      (~890 lines including tests)
- [x] `pub trait FlowPolicy: Send + Sync + 'static`
- [x] `pub enum FlowAction { Allow, Drop { reason: DropReason } }`
      (`DropReason(String)` newtype so Plan 74 / SNI / L7 can
      populate without coordinating enum extensions)
- [x] `pub struct FlowDecisionCtx { direction, dest_ip,
      dest_port, sni_hostname, url_path }` — all forward-compat
      Options, W6.A only fills `direction`
- [x] `pub struct AllowAll; impl FlowPolicy for AllowAll`
- [x] `pub enum BridgeEndpoints { Passt, LibkrunGvproxy,
      VzIngest }`
- [x] `pub struct BridgeConfig { vm_name, plan: Arc<ExecutionPlan>,
      bundle: Option<Arc<PolicyBundle>>, audit_socket, signer,
      policy }` (note: events_ingest_socket lives in
      `BridgeEndpoints::VzIngest` since only Vz uses it; cleaner
      than carrying it in BridgeConfig universally)
- [x] `pub fn spawn_bridge_thread(endpoints, cfg) -> JoinHandle<()>`
      — dedicated `std::thread` named `mvm-bridge-<vm>`, current-
      thread tokio runtime + `LocalSet` running bridge / signer /
      sink tasks
- [x] `pub(crate) async fn signer_task(rx, plan, bundle, signer,
      broadcast_tx)` — sole caller of `sign_and_emit` per VM;
      publishes JSON to broadcast in parallel
- [x] **Passt bridge**: `bridge_copy_bidirectional` with
      `into_split` halves + 8 KiB read loop; first-byte per
      direction triggers `FlowPolicy::evaluate` before emitting
      `FlowOpened`; EOF/error emits paired `FlowClosed { Eof |
      BridgeError }`; policy drop emits `FlowClosed {
      PolicyDropped }` and returns
- [x] **LibkrunGvproxy bridge**: SOCK_DGRAM `bind` at
      `supervisor_listen_path` (libkrun connects here); second
      `UnixDatagram` `connect`s to gvproxy; egress task caches
      libkrun's autobind peer via `recv_from` (libkrun is
      anonymous unixgram client); ingress task `send_to(peer)`
      for return path; shuffle preserves packet boundaries
- [x] **VzIngest bridge**: `UnixListener::bind`, 0700 chmod,
      `accept` first connection; subsequent accepts logged +
      dropped (sole-writer contract); read 17-byte magic
      `MVM_VZ_BRIDGE_V1\n` handshake; drain NDJSON
      `FlowEventWire`; deserialize to internal `FlowEvent`,
      forward into mpsc
- [x] `pub const VZ_BRIDGE_HANDSHAKE: &str = "MVM_VZ_BRIDGE_V1\n"`
- [x] `pub const EVENT_CHANNEL_CAPACITY: usize = 1024` — bridge
      `send().await`s on overflow → backpressure to guest, never
      drops
- [x] Bridge thread `catch_unwind` → `std::process::exit(1)` —
      fail-closed (claim-10 load-bearing)
- [x] `FlowEventWire` (tagged enum, snake_case) — stable wire
      shape for both subscriber NDJSON + Swift bridge ingest
- [x] Module wired in `lib.rs` next to `gateway_audit`
- [x] Tests (9 new):
      - [x] `allow_all_policy_lets_all_flows_through` (both directions)
      - [x] `drop_policy_returns_drop_with_reason` (DropAllForTest mock)
      - [x] `flow_decision_ctx_has_optional_sni_url_slots`
            (forward-compat seam check)
      - [x] `flow_event_wire_opened_serializes_as_expected`
      - [x] `flow_event_wire_closed_serializes_with_reason`
      - [x] `flow_event_to_wire_converts_correctly`
      - [x] `vz_ingest_rejects_missing_handshake` (non-handshake
            client bytes → handle_vz_ingest returns Err)
      - [x] `vz_ingest_accepts_handshake_and_drains_ndjson`
            (handshake + JSON → event arrives on mpsc)
      - [x] `passt_bridge_emits_open_close_pair_on_socketpair_traffic`
            (two socketpairs, bidirectional traffic, two opens +
            two closes seen on mpsc)
- [x] Deferred (lower-value-vs-cost in W6.A; tracked in W6.B):
      - signer_task_sole_writer_under_concurrent_events
        (already exercised end-to-end by passt bridge test which
        uses signer_task downstream)
      - bridge_panic_exits_process_nonzero (subprocess plumbing
        too brittle for unit test; behavior covered by
        catch_unwind code review + integration via mvmctl)
      - gateway_child_does_not_inherit_audit_socket_fds
        (CLOEXEC default in Rust OwnedFd; W6.B integration test)
- [x] `cargo test -p mvm-supervisor --lib gateway` green (12
      tests: 3 gateway_audit + 9 gateway_bridge)
- [x] `cargo clippy -p mvm-supervisor --all-targets -- -D warnings`
      clean (after fixing 6 lints: match-as-let pattern, ?
      operator, collapsed if-let)

### Commit 6 — `SupervisorConfig` audit fields + admission validation

**Scope reduced from plan:** plan called for `network: NetworkConfig`
(mandatory) + `run_supervisor_with_bridge<F>` entry point with full
fd-interception (split `configure_with_gateway`, hand BridgeEndpoints
to factory). The fd-interception refactor is invasive — splits an
already-shipping path in two and changes the libkrun-binding fd
ownership story for both passt and gvproxy. **Deferred to commit
6.5 / commit 7** (Vz Swift bridge work pulls it along anyway).

What commit 6 actually ships:

- [x] `crates/mvm-libkrun/src/lib.rs` `SupervisorConfig` — five
      new fields, all `#[serde(default)] Option<...>` so pre-W6.A
      JSON parses cleanly:
      - `tenant_id: Option<String>`
      - `audit_dir: Option<PathBuf>`
      - `gateway_audit_socket: Option<PathBuf>`
      - `gateway_events_socket: Option<PathBuf>`
      - `signing_key_path: Option<PathBuf>`
- [x] `pub fn SupervisorConfig::validate_audit_substrate() ->
      Result<(), AuditSubstrateError>` — claim-10 admission check.
      Refuses configurations with missing fields, empty
      `tenant_id`, `gateway_audit_socket` outside `audit_dir`, or
      `signing_key_path` outside `~/.mvm/keys/` (path-traversal
      defense).
- [x] `pub enum AuditSubstrateError` — typed error variants
      (`MissingField`, `EmptyTenantId`, `AuditSocketOutsideAuditDir`,
      `SigningKeyOutsideKeysDir`); `Display` + `Error` impls.
- [x] `fn home_mvm_keys_dir()` helper for the `~/.mvm/keys/`
      prefix check.
- [x] Tests (9 new):
      - [x] `validate_audit_substrate_accepts_well_formed_config`
      - [x] `validate_audit_substrate_refuses_missing_tenant_id`
      - [x] `validate_audit_substrate_refuses_empty_tenant_id`
      - [x] `validate_audit_substrate_refuses_missing_audit_dir`
      - [x] `validate_audit_substrate_refuses_missing_gateway_audit_socket`
      - [x] `validate_audit_substrate_refuses_audit_socket_outside_audit_dir`
      - [x] `validate_audit_substrate_refuses_missing_signing_key_path`
      - [x] `validate_audit_substrate_refuses_signing_key_outside_mvm_keys`
      - [x] `validate_audit_substrate_refuses_signing_key_path_traversal`
            (notes the limit of starts_with-based defense)
      - [x] `supervisor_config_serde_omits_audit_substrate_fields_when_none`
            (backward-compat: pre-W6.A JSON still parses; validation
            then refuses)
- [x] `cargo test -p mvm-libkrun --lib tests::` 41 tests green
      (was 32; +9 for the validation)
- [x] `cargo clippy -p mvm-libkrun --all-targets -- -D warnings`
      clean (after fixing 4 `unnecessary_lazy_evaluations` lints)

Deferred to commit 6.5 (or rolled into commit 7):
- `run_supervisor_with_bridge<F>` entry point.
- `configure_with_gateway` split into `configure_pre_net` +
  bridge-socketpair-insertion.
- `mvm-libkrun-supervisor` binary swap from `run_supervisor` to
  `run_supervisor_with_bridge`.
- Backend orchestrator population of the new `SupervisorConfig`
  fields in `crates/mvm-backend/src/libkrun.rs`.

The substrate is now: bridge module (commit 5) exists and is
fully testable; the SupervisorConfig fields are defined and
validated; the *wire-up* between SupervisorConfig and bridge
spawn is the deferred work.

### Commit 7 — Vz `NetworkConfig::events_ingest_socket_path` field

**Scope reduced from plan:** plan called for full Swift bridge
rewrite of `Network.swift` + vz.rs orchestrator population + Swift
XCTest harness. The Swift portion can't be compile/test-verified
from this session (requires macOS + Vz framework). **Deferred to
W6.A.5** — a follow-up commit (or PR) where the Swift code can
be developed against the real toolchain.

What commit 7 actually ships:

- [x] `crates/mvm-vz/src/lib.rs` `NetworkConfig::Gvproxy` — add
      `events_ingest_socket_path: Option<String>` field,
      `#[serde(default, skip_serializing_if = "Option::is_none")]`.
      `None` means "bridge inactive" (pre-W6.A behavior); `Some(p)`
      tells the Swift bridge where to connect for FlowEvent
      emission.
- [x] Tests (2 new):
      - [x] `gvproxy_events_ingest_socket_path_roundtrips_when_set`
            — JSON contains the field; deserializes to `Some(...)`
      - [x] `gvproxy_without_events_ingest_socket_path_parses` —
            pre-W6.A JSON (no field) deserializes to `None`
- [x] `cargo test -p mvm-vz --lib` 15 tests green (was 13;
      +2 for the new field)
- [x] `cargo clippy -p mvm-vz --all-targets -- -D warnings` clean

Deferred to W6.A.5 (Vz Swift implementation PR):

- `crates/mvm-vz-supervisor/Sources/mvm-vz-supervisor/Network.swift`
  `makeGvproxyDevice` rewrite (socketpair + bridge ingest connect
  + handshake + splice loops + NDJSON emit).
- `crates/mvm-backend/src/vz.rs:809-812` — populate `network`
  with `NetworkConfig::Gvproxy { events_ingest_socket_path: Some(...) }`
  sourced from `mvm_data_dir() + audit/`.
- `spawn_gvproxy_for_vz` shim reusing
  `mvm_libkrun::gvproxy::spawn`.
- Swift XCTest harness:
  - `testGvproxyBridgeShufflesDatagrams`
  - `testEmitsFlowOpenedOnFirstPacket`
  - `testEmitsFlowClosedOnShutdown`
  - `testIngestHandshakeSentFirst`
  - `testIngestReconnect`

The Rust side is ready for the Swift connect: ingest socket +
handshake + NDJSON drain all land in commit 5's
`run_vz_ingest_bridge`; just needs the Swift writer to connect.

### Commit 8 — ADR-058 + Plan 102 amendments (ADR-055 + SPRINT.md done earlier)

- [x] `specs/adrs/058-claim-10-bytes-leaving-trust-boundary.md`
      `### Leg 2` — appended "W6.A amendment" subsection with
      no-bypass invariant, coverage vs. capture, mediable
      substrate, cross-process chain integrity, scope
      clarification, cross-tenant isolation invariant
- [x] `specs/adrs/058-...` `## Out of scope` — appended 7 items
      under "### Added by W6.A amendment":
      - east-west lateral flows (W11)
      - L7 URL inspection (Plan 34 Phase 2)
      - DoH bypass (Plan 74 follow-up)
      - SNI hostname allowlist (new plan)
      - Side-channel via flow timing
      - Multi-user shared host same UID
      - Cross-tenant network management (mvmd plan 50)
- [x] `specs/adrs/055-passt-virtio-net.md` — TSI escape hatch
      removed (landed in commit 1's docs sweep)
- [x] `specs/plans/102-gateway-audit-substrate-impl.md`
      `## Deferred follow-ups` — three subsections:
      - `### W6.A.5` (Vz Swift bridge + fd interception wire-up;
        deferred from W6.A as the Swift code can't compile-verify
        from this session)
      - `### W6.B follow-ups` (real flow extraction items)
      - `### Adjacent new plans` (SNI inspector, Plan 34 Phase 2,
        DoH deny, gvproxy supply-chain, mvmd-network-manager)
- [x] SPRINT.md Sprint 56 §W3 + §Non-goals updated in commit 0;
      no further amendment needed in commit 8

### Commit 9 — PR description + open

- [ ] Live smoke recipe per backend in PR description
- [ ] No-bypass canary documented
- [ ] Tenant isolation rationale table
- [ ] W6.B follow-ups + Adjacent new plans flagged
- [ ] PR description references Plan 103 tracker
- [ ] `gh pr create` opens PR against `main`

## Workspace gates (must all pass before PR open)

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace -- -D warnings`
- [ ] `cargo test --workspace`
- [ ] `swift test` (mvm-vz-supervisor)

## Live smoke (per backend; acceptance gates)

- [ ] (a) Linux + libkrun + passt: `nc -U` shows FlowOpened +
      FlowClosed after guest curl
- [ ] (b) macOS + libkrun + gvproxy: same
- [ ] (c) macOS + Vz + gvproxy: same
- [ ] No-bypass canary: `MVM_NETWORKING=tsi` fails with
      "TSI mode is no longer supported."
- [ ] Audit chain integrity: `mvmctl audit verify` exit 0
- [ ] Cross-process flock canary: two VMs same tenant; verify
      exit 0
- [ ] Tamper canary: byte-flip chain → verify exit nonzero

## W6.B follow-ups (next PR; tracked here for visibility)

Mirrored in Plan 102 `### deferred follow-ups #### W6.B
follow-ups` per commit 8.

- [ ] Flow flooding DoS: per-instance rate cap (1000/sec) +
      `FlowFlood` aggregation events for excess
- [ ] Parser fault containment: `std::panic::catch_unwind` around
      etherparse; emit `GatewayAuditFault` on panic; degrade flow
      to pass-through splice
- [ ] Bounded flow table (4096 active flows / instance) with
      oldest-idle eviction and `FlowEvicted` emission
- [ ] Real per-direction byte counters in `FlowClosed` (from
      parsed frame sizes)
- [ ] Parser fuzz target
      `crates/mvm-libkrun/fuzz/fuzz_gateway_bridge.rs` seeded
      from real Ethernet captures
- [ ] Rust→Swift drop command channel for Vz mediation
      actuation
- [ ] Broadcast/ARP/DHCP noise distinguishing — emit
      `FrameOther` for non-IP frames; drop from main per-flow
      event stream
- [ ] Spurious vfkit-handshake `FlowOpened` on passt ingress —
      parser-aware fix

## Adjacent new plans (separate work streams)

Mirrored in Plan 102 `### deferred follow-ups #### Adjacent new
plans` per commit 8.

- [ ] Move gvproxy spawn helper out of mvm-libkrun
      (mvm-providers or new mvm-gateways crate)
- [ ] New plan: SNI inspector in gateway bridge (hostname-level
      allowlist without MITM)
- [ ] Plan 34 Phase 2: finalize TLS MITM in L7EgressProxy with
      workload-CA trust (URL-path allowlist for HTTPS)
- [ ] Plan 74 follow-up: mandatory-deny well-known DoH endpoints
      (1.1.1.1:443, dns.google, etc.)
- [ ] gvproxy supply-chain hardening: pin version+SHA in doctor;
      vendoring evaluation
- [ ] **mvmd-network-manager** cross-repo plan written in
      `tinylabscom/mvmd/specs/plans/` (per-tenant gateway pool,
      egress quotas, tenant-level rollup)

## Status

🟢 **W6.A merged 2026-05-27** (PR #459 on `main` at `df950fd9`).

🟢 **W6.A.5 substrate wire-up merged 2026-05-28** (PR #487 on `main`).
Vz Swift bridge + libkrun `run_supervisor_with_bridge<F>` + host-side
gvproxy lifecycle shipped; `mvm-libkrun-supervisor` split into its own
leaf crate.

🟡 **Phase 3c producer activation in flight (2026-05-28)** — executed
as [Plan 112](112-w6a-phase-3c-producer-activation.md) on
`worktree-plan-102-phase-3c`. Widens `VmStartConfig` with three
`Option<String>` fields (`tenant_id` / `plan_json` / `bundle_json`),
populates from `AdmittedPlan` at the three `mvmctl up`
construction sites, delegates substrate resolution to a new shared
`crates/mvm-backend/src/audit_substrate.rs` module (allowlist
validation + path derivation; seam for the future `NetworkProvider`
trait), threads the result into libkrun's `SupervisorConfig`. Vz path
gets the allowlist guard but defers full chain-emit wiring to the
NetworkProvider trait plan (needs lockstep Swift `Config.swift` schema
update + a Rust drainer for `events_ingest_socket_path`). Live smokes
scheduled for the Phase 3c PR merge.

🟢 **Plan 113 — NetworkProvider observer fan-out + Firecracker substrate (Path X)** — shipped on `worktree-plan-113-network-provider`. Observer trait + Pipeline + ObserverAllowlist live inside mvm-supervisor (alongside the existing gateway_bridge); BridgeConfig gains observers field; signer_task fans out under catch_unwind before chain signing. Vz drainer + Firecracker bridge ship as thin binaries linking mvm-supervisor. A2 confinement via new mvm-jailer-lite crate (seccompiler + landlock). ADR: [ADR-064](../adrs/064-network-provider-trait.md). Plan: [Plan 113](113-network-provider-trait-firecracker-substrate.md).
