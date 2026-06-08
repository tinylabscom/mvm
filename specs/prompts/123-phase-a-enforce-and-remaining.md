# Plan 123 — per-tenant egress enforce (Phase A tail) + the full remaining map

> Session kickoff prompt. Recommended immediate task first, then every remaining
> Plan 123 item across all three phases so nothing is lost. Source of truth:
> `specs/plans/123-network-storage-warmstart.md` (A/B/C, "deferred follow-ups").

## Context

Plan 123 = three independent subsystems in `mvm-network` / `mvm-storage` /
`mvm-backend`: **Phase A** `NetworkProvider` (provisioning + default-deny egress
+ DNS + audit — the seam Plan 129 hangs on), **Phase B** `StorageProvider` /
`MountProvider`, **Phase C** warm-start (per-backend: Firecracker live-memory
resume, Vz save/restore, libkrun disk-snapshot). Phases A and B are largely
landed; the tail is decisions/infra + the (large, gated) warm-start subsystem.

Execution order was B → A → C; the doc's per-step checkboxes lag (many show `[ ]`
but landed — e.g. `mvm-network` is authored, the traits + `LocalStorage` +
`EncryptedStorage` + content-addressed/snapshot + `MountRegistry` + S3 provider
all shipped). Trust the per-phase **Status** notes + this list, not raw boxes.

---

## RECOMMENDED IMMEDIATE TASK — Phase A: per-tenant `NetworkPolicy → FlowPolicy` enforce (libkrun)

**Why this first:** it's the one remaining Plan 123 item that's *security-
relevant*, *bounded*, and *locally verifiable* (libkrun boots on the macOS dev
host). It's the same egress chokepoint the Plan 129 secrets work rides, so it
tightens claim-10/12 on the default macOS path.

**The gap (concrete):** the gateway-bridge consults `FlowPolicy::evaluate` before
opening a flow (`crates/mvm-hostd/src/supervisor/gateway_bridge.rs` — `FlowPolicy`
trait + `AllowAll` default), but the libkrun supervisor hard-wires
`policy: Arc::new(AllowAll)` (`crates/mvm-vm-host/src/bin/mvm-libkrun-supervisor.rs:~297`).
So per-tenant the libkrun flow-open gate is wide open; only the host-side
**mandatory-deny** backstop (#647) and the packet-level `build_egress_scan`
(L4 + DNS, already threaded into `ObserverWiring.scan`) constrain it.

**Do:** map the admitted plan's `NetworkPolicy` (the claim-10 type) → a
`FlowPolicy` impl (deny-by-default, admit the plan's allowed `(host/CIDR, port,
proto)` + DNS allow-list) and replace `Arc::new(AllowAll)` on the libkrun
supervisor with it. Mirror the Firecracker enforcement (`SupervisorEgressEnforcer`
/ `install_default_deny`) so the two backends enforce the same policy through the
same seam. Confirm the DNS allow-list (`DnsSinkholeScan`) is also threaded
per-tenant (today some sites pass empty). Keep `MandatoryDenyEgressScan` +
`PlaceholderLeakScan` as the always-on backstops.

**Validate:** libkrun on the macOS host (`examples/agent_ping`) + the
no-VM bridge integration tests (real Unix sockets, no VM — `run_libkrun_gvproxy_bridge`,
the path that *is* exercisable on this Mac, #656). A bound destination passes; an
unbound one is denied at flow-open (FlowPolicy) AND at the packet scan.

---

## ALL REMAINING WORK — by phase (so nothing is dropped)

### Phase A — `NetworkProvider` (mostly landed; tail = the above + decisions)
- [ ] **(recommended task above) per-tenant `NetworkPolicy → FlowPolicy` enforce on libkrun** + per-tenant `DnsSinkholeScan`.
- [ ] **L3 slice B — re-point the two live libkrun selection sites through the provider.** Needs a decision: the workload site (`cfg!(macos)`) ignores `MVM_NETWORKING`, the builder honors it — not a faithful no-op refactor. Resolve the divergence, then re-point.
- [ ] **L2 — `microvm_nix` (QEMU) egress — product call.** That start path does `bridge_ensure`+`tap_create` with **no** `apply_network_policy`, and egress policy isn't in `VmStartConfig`. Either (a) plumb `network_policy` into `VmStartConfig` so every backend enforces claim-10 uniformly (cross-cutting), or (b) document microvm_nix/QEMU as a non-untrusted-workload (Tier-2) backend needing no enforcement. **Do not bulldoze `deny_all()` onto it** (no admit path → breaks all egress).

### Phase B — `StorageProvider` / `MountProvider` (landed; tail = env-gated)
- [ ] **Linux LUKS2 arm of `EncryptedStorage`** — block-level `cryptsetup luksFormat/luksOpen` + `mkfs`/`mount` over a loop device. Un-buildable/un-verifiable on macOS; land on **Linux CI**, gated (`MVM_LIVE_LUKS=1`), per the `mvm_core::rotate_luks_slot` precedent. (macOS file-seal arm via `mvm_core::crypto::volume` is done.)
- [ ] **S3 `MountProvider` live-bucket validation** — exercise `from_s3_config` against a real/minio bucket (only the `object_store::InMemory` path is unit-tested today).
- [ ] **opendal → object_store consolidation** — actually **Plan 126's** scope (note it, don't do it here).

### Phase C — warm-start (the big remaining subsystem; gated)
Per-backend matrix, **scheduled last, highest-risk**, needs the gated live-KVM +
macOS-26 lanes — and a **host-side `PostRestore` sender that does not exist yet**
(the guest handles `GuestRequest::PostRestore`; nothing sends it). Build that
sender first; it's a C prerequisite, not an afterthought. Warm-pool / checkpoint
also gated on **Plan 152 WS-B** (the Rust VZ supervisor).
- [ ] **Firecracker** live-memory fast-resume — diff/layered snapshots (read-only golden base + COW per-VM delta, reusing Phase B3's snapshot-upper) + `userfaultfd`/NBD/hugepages page-fault resume + VMGenID rotate-and-reseed on resume (depends on the `PostRestore` sender). SIGUSR1 "primed" ready-barrier for a deterministic warm base. **Live-KVM-gated.**
- [ ] **Vz (macOS 26+)** — `saveMachineState`/`restoreMachineState` round-trip + VMGenID rotate + guest reseed. The apple_container/Vz backend currently reports `pause_resume=false`. **macOS-26-gated.** (A faster diff-snapshot/UFFD-equivalent on Vz is its own investigation.)
- [ ] **libkrun** — no memory snapshot; warm-start = fast re-boot from the overlay/rootfs disk snapshot (Phase B3). Implement that path.
- [ ] **`doctor`** reports the per-backend warm-start capability + probes the Linux substrate (NBD module, HugeTLB reservation), failing closed with hints.
- [ ] **Cloud-Hypervisor** snapshot parity (only if CH stays a backend).
- [ ] Soften the gap-analysis "live-memory resume" line to the honest per-backend matrix (FC + Vz live-memory; libkrun disk-only).
- [ ] Phase C success criteria: warm-start is a per-backend capability; `cargo test --workspace` (host tiers) + the gated live-KVM/macOS lanes + clippy + fmt green.

---

## Recommended sequencing

1. **Now:** the per-tenant libkrun `FlowPolicy` enforce (security, bounded, local).
2. **Then, with a product decision:** L2 microvm_nix (the `VmStartConfig` policy-field call — option (a) also cleans up the whole-fleet claim-10 story) and L3 slice B.
3. **Opportunistic / when on Linux:** Phase B LUKS2 arm (Linux CI), S3 live validation.
4. **Defer until its prereqs land:** Phase C warm-start — do **not** start before the `PostRestore` host sender exists and Plan 152 WS-B is in; it's the largest, riskiest, most-gated chunk.

## Files
- Phase A: `crates/mvm-hostd/src/supervisor/gateway_bridge.rs` (`FlowPolicy`, `ObserverWiring`), `crates/mvm-vm-host/src/bin/mvm-libkrun-supervisor.rs` (`Arc::new(AllowAll)` site), `crates/mvm-hostd/src/supervisor/network/stages.rs` (`build_egress_scan`, `DnsSinkholeScan`), `crates/mvm-hostd/src/supervisor/firewall/seam.rs` (`SupervisorEgressEnforcer`), `crates/mvm-network/src/{provider,enforcement}.rs`, `crates/mvm-backend/src/{network_provider,libkrun}.rs`, `crates/mvm-build/src/libkrun_network_provider.rs`.
- Phase B: `crates/mvm-storage/src/{encrypted,s3}.rs`.
- Phase C: `crates/mvm-backend/src/{firecracker,vz,libkrun}.rs`, `crates/mvm/src/.../instance_snapshot`, the `PostRestore` sender (new, host-side).

## Constraints / gotchas
- **`mvm-backend` test binary is SIGKILL'd by macOS codesign** (`nextest --workspace` aborts on `mvm_backend --list`) — run `-E 'not package(mvm-backend)'` locally; lean on Linux CI for that crate. The libkrun **bridge** path *is* locally testable (no VM, real sockets, #656).
- **`mvmd` owns** the production `NetworkProvider` impls (WireGuard/Tailscale `Custom`), the encrypted/object-store *data-plane* backends, and tenant/deploy policy — Plan 123 is the host-side **seam + built-ins**, don't re-home mvmd's backends.
- CLAUDE.md is "Firecracker-only on Linux" — that frames the L2 microvm_nix decision.
- Merges: repo requires **squash**; main branch protection requires 1 approving review (`aneyzberg`) with `enforce_admins=true` — self-merge needs a brief `enforce_admins` toggle + restore-and-verify, or aneyzberg's approval.
- `specs/REFACTOR-STATUS.md` does **not** list Plan 123 yet — add it when you touch this, and keep the doc checkboxes honest (tick what's landed).
