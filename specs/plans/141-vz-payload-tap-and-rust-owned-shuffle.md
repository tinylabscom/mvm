# Plan 141 — Backend-agnostic packet-observer core (`on_packet` / `Verdict`) for libkrun + Firecracker

> **For agentic workers:** REQUIRED SUB-SKILL: use
> `superpowers:subagent-driven-development` (recommended) or
> `superpowers:executing-plans`. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Give the gateway audit bridge a synchronous packet-observation
pipeline — `Observer::on_packet(ctx, pkt) -> Verdict { Forward | Drop |
Modify(Vec<u8>) }`, parsed once per frame via `etherparse`, fanned out in
policy order, with first-Drop-wins, per-VM `killed_flows`, fail-closed
`Modify`, an opt-in flow-byte log, and per-observer Prometheus latency —
wired into the **Passt (Firecracker)** and **LibkrunGvproxy (libkrun)**
bridge variants. **No Vz changes** (delivered in-process by Plan 152).

**Architecture:** A pure, socket-free `packet` module (parse + payload
rebuild) and a pure `run_packet_pipeline` fan-out runner form the
backend-agnostic core; each bridge variant feeds raw frames into that one
runner. The runner reuses Plan 113's `catch_unwind` panic-isolation from
`signer_task`. Observers stay **host-allowlisted, never tenant-shipped**
(ADR-064 §7) — the existing `ObserverAllowlist` is untouched. Security
spine: claim 1 (least-privilege `directions()` blast-radius containment),
claim 10 (no untrusted bytes leave unobserved; `Modify` fails closed so a
redactor can never leak).

**Tech Stack:** Rust, `etherparse` 0.20 (NEW workspace dep — Task 1),
`tokio` (existing), `mvm-hostd::supervisor::{gateway_bridge,network,audit}`,
`mvm-core::policy::NetworkPolicy`, `mvm-cli::metrics_server`.

---

## Context

ADR-064 §Decision 8 carved out "Vz catches up later" for payload-tap. The
original Plan 141 tried to close that with an SCM_RIGHTS fd-handoff to a
*surviving* Swift supervisor. The **2026-06-04 rescope** (ADR-064 §8 +
memory `project_vz_strong_support_direction`) made the VZ supervisor
Rust-native (Plan 152), so Vz owns its device *and* bridge in-process —
the Swift handoff is throwaway. **Plan 141 is rescoped to its
backend-agnostic core** for **libkrun + Firecracker only**. It now depends
only on Plan 113 (merged, PR #512), so it is unblocked.

The bridge today (`gateway_bridge.rs`) does opaque byte-copy and never
parses L3/L4 (`FlowDecisionCtx.dest_ip/dest_port` hardcoded `None`, "no
parser yet"). This plan introduces the first real parse on that path.

**`etherparse` correction:** prior prose claimed it was already a
workspace dep. It is **not** (verified 2026-06-04 — zero repo references;
absent from `[workspace.dependencies]`; latest published is 0.20). Task 1
adds it. Rationale (memory `reference_etherparse_not_yet_workspace_dep`):
it lands on the untrusted-guest-bytes path where claim 5 fuzzes parsers,
so a mature fuzzed-upstream parser beats a hand-rolled one
(`feedback_limit_dependencies` tolerates this profile).

---

## Resolved design questions

- **Q7 — capability advertisement.** Moved to Plan 152 (concerns the Vz
  leaf's `payload_tap` flip). libkrun + Firecracker already report
  `payload_tap: true`. No change here.
- **Q8 — `Modify` failure modes (RESOLVED: uniform fail-closed).** Any
  `Modify` the bridge cannot safely emit → kill the flow (insert
  five-tuple into `killed_flows`, drop this + all subsequent packets on
  that flow) + emit `gateway.flow_observer_fault` attributing the
  observer + reason. Matrix:

  | Failure | Behavior |
  |---|---|
  | Modified frame exceeds MTU (no re-frag in V1) | kill + fault, reason `modify_over_mtu` |
  | Rebuild fails (etherparse can't re-serialize) | kill + fault, reason `modify_unserializable` |
  | `Modify(bytes)` where `bytes == original` | treat as `Forward` (skip rebuild) |
  | Observer panics | `catch_unwind` → warn → `Forward` for that observer, siblings continue |

  Rationale: on TCP a silent single-packet drop just stalls (retransmit →
  re-modify → re-fail loop), so drop-packet degrades to a dead flow
  anyway without an audit trail. One fail-closed terminal state is
  simpler and secure.

- **Q9 — per-direction registration (RESOLVED: include, minimal).**
  `Directions { Egress | Ingress | Both }`; `fn directions(&self) ->
  Directions { Directions::Both }` default (keeps every flow-event
  observer unchanged); runner skips `on_packet` when direction excluded.
  Least-privilege: egress observer never sees inbound bytes.
- **Q10 — `VzIngest` arm.** Untouched; deletion/rename → Plan 152.

---

## Scope decision: both backends, gvproxy-first

Both production backends wired here, sequenced: LibkrunGvproxy datagram
path first (one `recv` = one frame → clean insertion exercising the whole
core), then Passt (`SOCK_STREAM` `bridge_copy_bidirectional` has no frame
boundaries — needs a length-prefix-aware rewrite feeding the *same*
runner). Localizes Passt-reframing bugs away from pipeline bugs.

**Backend-agnostic core = Tasks 1–7. Backend wiring = Tasks 8–10. Fuzz +
tick = Task 11.**

---

## File structure

| File | Responsibility | Action |
|---|---|---|
| `Cargo.toml` (root) | add `etherparse` to `[workspace.dependencies]` | Modify |
| `crates/mvm-hostd/Cargo.toml` | consume `etherparse` (+ `hex` if absent) | Modify |
| `crates/mvm-hostd/src/supervisor/network/packet.rs` | pure parse + payload rebuild | Create |
| `crates/mvm-hostd/src/supervisor/network/pipeline.rs` | pure `run_packet_pipeline` | Create |
| `crates/mvm-hostd/src/supervisor/network/latency.rs` | per-observer latency + `.prom` writer | Create |
| `crates/mvm-hostd/src/supervisor/network/mod.rs` | extend `Observer`; add `Verdict`/`Directions`/`PacketCtx`; register submodules | Modify |
| `crates/mvm-hostd/src/supervisor/audit.rs` | `flow_observer_fault` + `FLOW_OBSERVER_FAULT_EVENT` | Modify |
| `crates/mvm-hostd/src/supervisor/gateway_bridge.rs` | `FlowEventKind::ObserverFault`; per-VM `killed_flows`; wire runner into both loops | Modify |
| `crates/mvm-core/src/policy/policies.rs` | `NetworkPolicy.flow_byte_log` + `FlowByteLogSpec` | Modify |
| `crates/mvm-hostd/src/supervisor/network/flow_byte_log.rs` | append-only writer + retention sweep | Create |
| `crates/mvm-cli/src/metrics_server.rs` | broaden scrape discovery to `metrics-*.prom` | Modify |
| `crates/mvm-cli/src/commands/cache.rs` | flow-byte-log sweep in `cache prune` | Modify |
| `crates/mvm-hostd/fuzz` | `fuzz_packet_parse` target | Modify |

Verified anchor points (read 2026-06-04):
- `Observer` trait: `network/mod.rs:86-90`; `RequiredCapabilities`/`ProviderCapabilities` 46-73; `Pipeline` 119-166; `ObserverAllowlist` 174-343; `MAX_OBSERVERS=8`.
- `signer_task` fan-out + `catch_unwind`: `gateway_bridge.rs:266-333` (pattern to reuse).
- gvproxy loop: `run_libkrun_gvproxy_bridge` `gateway_bridge.rs:654-823` (one datagram = one frame).
- Passt loop: `bridge_copy_bidirectional` `gateway_bridge.rs:494-648` (opaque 8 KiB copy; needs reframe).
- `FlowEvent`/`FlowEventKind`: `gateway_bridge.rs:200-211`; `FlowEventWire` 221-249.
- `AuditEntry::flow_opened/flow_closed`: `audit.rs:94-132`; `FlowDirection` 149-166; `FlowCloseReason` 178-197.
- `NetworkPolicy`: `mvm-core/src/policy/policies.rs:32-53` (already has `observers: Vec<String>`).
- metrics discovery: `mvm-cli/src/metrics_server.rs:140` matches `starts_with("metrics-") && ends_with("-flow-count.prom")` — must broaden.

---

# Phase A — backend-agnostic core

### Task 1: Add the `etherparse` workspace dependency

- [x] Add to root `[workspace.dependencies]` (after `ipnet`): `etherparse = "0.20"` with a comment (untrusted-guest-bytes path; claim 5).
- [x] In `crates/mvm-hostd/Cargo.toml` `[dependencies]`: `etherparse = { workspace = true }`.
- [x] Verify `cargo tree -p mvm-hostd -i etherparse`.
- [x] Commit `build(mvm-hostd): add etherparse for the packet-observer pipeline`.

### Task 2: Pure packet parse + payload rebuild (`packet.rs`)

- [x] **Failing tests first:** `parse` five-tuple+payload; `parse` None on non-IP/truncated; `rebuild_with_payload` same-length + shorter success; over-MTU → `RebuildError::ExceedsMtu`; non-IP original → `RebuildError::Unparseable`. Build frames with `etherparse::PacketBuilder`.
- [x] Implement: `L4Proto`, `FlowKey` (Hash+Eq), `FiveTuple::flow_key()`, `ParsedPacket<'a> { five_tuple, l4_payload: &'a [u8], raw_frame: &'a [u8] }`, `RebuildError { ExceedsMtu{len,mtu}, Unparseable, Serialize(String) }`, `parse() -> Option`, `rebuild_with_payload(raw,new_payload,mtu) -> Result<Vec<u8>>` (fix IP len + IP/L4 checksums; refuse over-MTU). **Confirm 0.20 API names by compiling.** V1 shortcut: refuse on IP extension headers (`Unparseable`).
- [x] `pub mod packet;` in `network/mod.rs`. Tests PASS. Commit.

### Task 3: Extend `Observer` — `Verdict`, `Directions`, `PacketCtx`, `on_packet`

- [x] Failing tests: `Directions::includes` truth table; default observer → `Both` + `Verdict::Forward`.
- [x] Implement `Directions{Egress,Ingress,Both}::includes`, `Verdict{Forward,Drop,Modify(Vec<u8>)}`, `PacketCtx<'a>{vm_name,tenant,direction,flow_id}`, and two **defaulted** trait methods `directions()` + `on_packet()`. Tests PASS. Commit.

### Task 4: `flow_observer_fault` audit entry

- [x] Failing test: helper sets event `gateway.flow_observer_fault` + labels flow_id/direction/observer/reason.
- [x] Implement `FLOW_OBSERVER_FAULT_EVENT` const + `flow_observer_fault(plan,bundle,flow_id,direction,observer,reason)`. PASS. Commit.

### Task 5: Per-observer latency recorder (`latency.rs`)

- [x] Failing tests: `record` accumulates; `prometheus_format` emits `mvm_observer_latency_us_{sum,count}{observer,vm,direction}`; scrape-file name is `metrics-<vm>-observer-latency.prom`.
- [x] Implement `ObserverLatency` (Mutex<BTreeMap<(name,dir),(sum,count)>>) with tmp+rename writer (mirror `FlowCountMetrics`). `pub mod latency;`. PASS. Commit.

### Task 6: The pure fan-out runner (`pipeline.rs`)

- [x] Failing tests: empty→Forward(Borrowed); non-IP→Forward,key None; Modify rebuilds + chains; first Drop wins→Kill{Drop}; over-MTU→Kill{ModifyOverMtu}; direction filter skips; panic isolated→Forward; Modify==original→Forward(Borrowed).
- [x] Implement `KillReason{Drop,ModifyOverMtu,ModifyUnserializable}::as_str`, `PacketDecision<'a>{Forward{frame:Cow,flow_key},Kill{observer,reason,flow_key}}`, `run_packet_pipeline(observers,ctx,raw_frame,mtu,latency)` reusing the `catch_unwind` pattern. `pub mod pipeline;`. PASS. Commit.

### Task 7: Flow-byte-log policy field + append-only writer

- [x] Policy (mvm-core): default-off + serde tests → `NetworkPolicy.flow_byte_log: Option<FlowByteLogSpec>` (`#[serde(default)]`) + `FlowByteLogSpec{max_disk_bytes:u64,max_age_days:u32,directions:FlowByteLogDirections}` + `FlowByteLogDirections{Egress,Ingress,Both}`.
- [x] Writer (mvm-hostd `flow_byte_log.rs`): append/read-back test → `RecordRef{record_id,sha256}`, `FlowByteLogWriter::{create(0600),append}`, `read_all_records`, `sweep_retention(root,max_age_days)`. `pub mod flow_byte_log;`. PASS. Commit.

---

# Phase B — backend wiring

### Task 8: Wire runner into LibkrunGvproxy datagram loop

- [x] `FlowEventKind::ObserverFault{observer,reason}` + `signer_task` arm (`flow_observer_fault`) + `FlowEventWire::FlowObserverFault` variant/From (wire roundtrip test first).
- [x] Thread `observers`, `Arc<ObserverLatency>`, `mtu=1514`, `killed_flows: Arc<Mutex<HashSet<FlowKey>>>` into `run_libkrun_gvproxy_bridge`. Both directions: killed-flow short-circuit → `run_packet_pipeline` → `latency.write_scrape_file()` → Forward sends (possibly rebuilt) frame / Kill inserts flow + emits ObserverFault + drops.
- [x] Integration tests (UnixDatagram pair): redactor → modified bytes downstream; drop → nothing + ObserverFault event. PASS. Commit.

### Task 9: Wire runner into Passt frame-aware loop + broaden metrics filter

- [x] Pure `read_one_frame`/`write_one_frame` (4-byte BE length prefix; cap ≤ 65535) with duplex roundtrip test.
- [x] Replace `bridge_copy_bidirectional`'s opaque loops with frame-aware loops feeding the runner (preserve first-frame `FlowOpened` + EOF `FlowClosed`). Update the existing socketpair test to length-prefixed frames; add redactor + drop tests.
- [x] Broaden `metrics_server.rs:140` to `ends_with(".prom")`; update filter test (latency file now picked up). PASS. Commit.

### Task 10: Flow-byte-log retention sweep in `cache prune`

- [x] `cache.rs` prune calls `flow_byte_log::sweep_retention(<audit-dir>/flow-bytes, 7)` via `mvm-core::config` path helper. Old-removed/fresh-kept test. Commit.

### Task 11: Fuzz target + plan-doc tick + claim catalog

- [x] `crates/mvm-hostd/fuzz/fuzz_targets/fuzz_packet_parse.rs` (parse→rebuild round-trip, no panic); registered in `security.yml` `fuzz` job + root `Cargo.toml` exclude. Boxes ticked.
- [x] Claim catalog: **left unchanged by design.** The packet-observer pipeline strengthens existing claim 10's no-bytes-leave-unobserved enforcement; it is not a new numbered claim (numbering is ADR-002-governed). Promotion to a catalog witness row belongs with the ADR-002 update, mirroring claim 14's "promotion queued" pattern — and editing the catalog risks the `check-claim-catalog` gate. The new tests back the existing claim 10 posture.

---

## Verification (end-to-end)

```bash
rustup run nightly cargo fmt --all -- --check
cargo nextest run -E 'not package(mvm-backend)'   # mvm-backend test bin SIGKILLed by macOS codesign (env-only)
cargo test --workspace --doc
cargo clippy --workspace -- -D warnings
```

Live gvproxy arm (no KVM): `MVM_GATEWAY_DHCP_E2E=1 cargo test -p mvm-hostd
--lib gvproxy_dhcp_offer_roundtrips_through_bridge` drives a real DHCP
`DISCOVER → OFFER` through the bridge against the installed gvproxy binary
(PR #614). Fuller workload check (force libkrun + isolate caches per memory
`project_dev_host_runs_builder_via_vz`): run a workload with an
allowlisted payload-tap observer; confirm modification on the wire,
`mvmctl audit verify` green, kill-flow emits `gateway.flow_observer_fault`,
`/metrics` shows `mvm_observer_latency_us_*`. **Passt arm: a live
Firecracker+passt KVM round-trip is a deferred follow-up** (see
[§Deferred follow-ups](#deferred-follow-ups)) — needs a `/dev/kvm` host.

---

## Out of scope (deferred)

All Vz changes (Swift refactor, fd-handoff, `VzIngest`→`VzManaged`, Vz
`payload_tap` flip Q7, `mvm-vz-drainer` deletion Q10) → **Plan 152**.
AppleContainer payload tap → own plan. Flow-byte-log encryption-at-rest →
own ADR. Per-observer timeout enforcement, TCP RST on kill, IP
extension-header rebuild, async/ring-buffered execution,
`Defer`/`DropPacket`-vs-`KillFlow` variants → all deferred.

### Deferred follow-ups

- [x] **Passt framing confirmed against real passt + CI-gated.** The
  gvproxy arm is live-validated against the real gateway (PR #614); the
  Passt arm's qemu-socket framing is now confirmed against the real passt
  binary by `scripts/passt-framing-check.py` (spawns `passt --fd`, sends a
  4-byte-BE-framed DHCP DISCOVER, asserts a 4-byte-BE-framed OFFER comes
  back — no KVM, passt is userspace). Wired as the per-PR `passt-framing`
  job in `ci.yml`. This locks in the framing assumption behind
  `gateway_bridge::{read,write}_one_frame`.
- [ ] **Full Firecracker-boot E2E on `/dev/kvm`.** A real microVM boot +
  passt + the bridge, end-to-end, still hasn't run — it needs a Linux host
  with `/dev/kvm`. **Route A (no extra infra):** a lane on a KVM-capable
  runner — GitHub `ubuntu-latest` exposes `/dev/kvm` and `ci-full.yml`'s
  `workload-spawn-smoke-linux` already boots Firecracker there; add a
  passt+bridge DHCP/observer assertion. **Route B:** a remote `/dev/kvm`
  box for interactive runs. Low marginal value now that the framing
  (the actual risk) is confirmed + CI-gated — the boot mostly re-confirms
  it; intentionally left deferred.

---

## Status

🟢 **Closed — merged to `main`.** The backend-agnostic core + both backend
wirings (all 11 tasks) shipped in **PR #609**; the live-validation
follow-up (real-gateway DHCP test + a bridge bug fix) shipped in
**PR #614**. Q8/Q9 closed via brainstorm; Q7/Q10 moved to Plan 152.
`etherparse 0.20` added (was absent).

Verification (CI + local): clippy `-D warnings` clean; nightly
`fmt --all --check` clean; doctests clean; full mvm-hostd + mvm-core
suites green plus the new unit + integration tests (packet parse/rebuild,
runner fan-out, gvproxy + framed-Passt redaction/drop, latency,
flow-byte-log, metrics filter, cache sweep). `fuzz_packet_parse` runs in
`security.yml`'s fuzz job.

**Live-validation status:**

- **gvproxy (libkrun) arm — live-validated.** PR #614 added an opt-in
  real-gateway DHCP round-trip test
  (`gvproxy_dhcp_offer_roundtrips_through_bridge`, gate
  `MVM_GATEWAY_DHCP_E2E=1`): drives a real DHCP `DISCOVER → OFFER` through
  the bridge against the installed gvproxy binary — no microVM, no KVM. It
  surfaced and fixed a **pre-existing** bug: the gvproxy-facing socket was
  unbound, which real gvproxy rejects (`vfkit accept error: vfkit socket
  address is empty`); it now binds `<listen>.gw-out`. The gateway contract
  is documented in rvproxy's `docs/gvproxy-conformance.md` (rvproxy PR #7);
  the same test is rvproxy's drop-in conformance gate (gvproxy passes;
  rvproxy fails only at the `-listen-vfkit` CLI surface).
- **Passt (Firecracker) arm — framing confirmed against real passt +
  CI-gated; full boot deferred.** passt uses the qemu-socket protocol
  (4-byte-BE length prefix). This is now confirmed against the **real
  passt binary** by `scripts/passt-framing-check.py` (DHCP DISCOVER→OFFER
  round-trip over `passt --fd`, no KVM), wired as the per-PR
  `passt-framing` job in `ci.yml` — locking in the assumption behind
  `gateway_bridge::{read,write}_one_frame`. The reframer is also
  duplex-unit-tested. The only thing not run is a full Firecracker microVM
  boot on `/dev/kvm` — tracked under
  [§Deferred follow-ups](#deferred-follow-ups); low marginal value now,
  the gap is a live KVM environment, not code.
