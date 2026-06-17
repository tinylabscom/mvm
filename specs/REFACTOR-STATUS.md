# Refactor status — rollup checklist

**Latest update: 2026-06-17** Plan 202 Phase 2c landed: admission host-signing can now route through the resident signer helper. The helper protocol gained `sign_host`, the helper signs existing host-signer `SignRequest` envelopes with the resident key path, and `mvm-host-signer` becomes a keyless compatibility proxy when configured with `signer_helper_uds_path`. Phase 2 remaining work is restart/head rebuild (2d). Plan 125 is also closed/rehome-only: its SDK/CLI veneer work is complete, and the remaining host-services daemon/process-model work now lives in Plan 202.


**Additional 2026-06-15 planning rollup:** Plan 200 de-duplication pass completed — Plans 199/200 are the priority product path; Plan 200 maps ownership against Plans 114/125/126/136/155/156/159/189/193/197/198 so `machine` owns beginner UX, Plan 199 owns install/host packaging, Plan 126/156 own dependency and binary-size mechanics, Plan 155 owns low-level artifact execution, Plan 159/189 stay VZ-specific, Plan 193/197 stay security substrate, and Plan 198 is completed perf input. Plan 200 also records binary-first install, optional source-built Nix, current image-backed one-shot docs before flakes/manifests, future `mvmctl machine`, local image sources, scenario-led beginner docs, explicit limitations docs, verified portable artifacts, measured hot-start claims, no crate-count reduction across security boundaries, `mvm.toml` schema v1 with `image`/`flake` mutual exclusion and strict default-deny network/auth/volume rules, managed macOS virtualization as the safer default, custom kernels as signed runtime/artifact payloads, SDKs mirroring the CLI without bypassing admission/audit, and dependency weight as a first-class DX/security goal measured by default binary closure. Plan 199 Workstream A is complete: source-built Nix `mvmctl` package + host overlay, project-release binary download refused by tests, native libkrun linkage explicit/opt-in, and host Nix remains optional. Plan 201 adds a proposed WarmLease borrow-handle + batched guest exec docs-only workstream over the standby pool and agent-RPC, with no new backend/transport or admission/audit changes.

**Additional 2026-06-16 security rollup:** Template-identifier path-traversal hardening from the prior-art audit note is complete. Legacy `template_load` now validates template names before any `template_spec_path` read, legacy `template_create` validates before writing through `template_dir` / `template_spec_path`, and `manifest export-oci` validates the legacy-name fallback before dispatch so traversal input fails as an invalid template name rather than a file-existence oracle. Regression coverage pins traversal rejection, valid legacy-name load, write-side rejection before directory creation, and 64-char slot-hash dispatch through the manifest-slot path.

**Additional 2026-06-16 — Plan 202 (ADR-084) proposed, merged #977:** grounding the first live in-guest `host.audit.v1` round-trip (Plan 125 E5.3b-4 — in-guest `audit-probe` proven on libkrun, #973) surfaced that the shipped broker/audit-signer model forks two host subprocesses *per VM* and couples `host.audit.v1` availability to `MVM_GATEWAY_BRIDGE`. ADR-084 + Plan 202 re-architect this to two long-lived **per-tenant** daemons (register/deregister, `O(active tenants)` not `O(VMs)`, moat + claims 12/13 preserved, guest wire unchanged, mvmd consumes the same daemon). The vz broker-socket bug found alongside it landed as #971. Plan 202 is proposed/not-started; Phase-1 kickoff prompt committed.

**Additional 2026-06-17 — Plan 202 Phase 3c landed:** `mvmctl doctor` now reports per-tenant host-agent daemon state as an informational platform check. It enumerates `<MVM_DATA_DIR>/host-agent/<tenant>/`, reports warm daemons from live `daemon.pid` + `control.sock`, flags stale pid/socket artifacts, and treats first-run absence as non-blocking. Phase 1 (broker daemon/control plane) and Phase 3a (daemon default-on) are landed; Phase 2 signer-helper daemonization remains next.

**Additional 2026-06-17 — Plan 202 Phase 2a/2b landed:** the resident per-tenant signer-helper path is in place. `mvm-signer-helper` runs as a child of `mvm-host-agent`, owns `vm_id → Chain` workload-audit heads, opens/closes per-VM chains on register/deregister, and receives only the tenant key path from the keyless host-agent. The shared helper wire (`register_vm` / `deregister_vm` / `append_entry` / `probe`), host-agent audit forwarding by server-derived `vm_id`, and cross-VM chain isolation tests landed; remaining Phase 2 work after 2c is restart/head rebuild.

> MAINTENANCE: keep this file current. Whenever you land, merge, or descope a
> workstream in any plan below, tick/strike the matching box here in the SAME
> change and bump the "Last updated" date — update BOTH the glance checklist
> and the matching plan in the details. This is a hand-maintained rollup of
> the per-plan checkboxes in `specs/plans/` and `specs/SPRINT.md` — it is a
> quick index, not the source of truth. If it disagrees with a plan doc, the
> plan doc wins; fix this file.

## Plans at a glance

A box is ticked only when the whole plan is ✅ DONE. In-progress (🟢/🟡) and
not-started (🔴) plans stay unticked — see the per-plan breakdown in **Plan
details** below for the workstream-level state.

- [x] **PLAN 121** — Crate consolidation (32→15) · ✅
- [x] **PLAN 169** — Backend-agnostic agent RPC · ✅
- [x] **PLAN 166** — QEMU Linux dev/test backend · ✅
- [x] **PLAN 165** — Sealed-prod interactivity (claim 15) · ✅
- [x] **PLAN 170** — Host lifecycle convergence · ✅ mvm-side (density → mvmd)
- [x] **PLAN 153** — CLI directory split · ✅ (subsumed into Plan 178)
- [x] **PLAN 178** — CLI surface consolidation (~56→~28) · ✅ (dir-purity deferred)
- [x] **PLAN 129** — Secrets / SigV4 substitution · ✅ **COMPLETE** — both tiers (declared substitution incl. SigV4/HMAC bind-checked + undeclared detection), terminator-path + vsock, claim-12/13 leak-gate (claim 16), endpoint self-confines (Landlock+seccomp jailer); QEMU clean-room e2e GREEN; FC bringup fixes landed (#804); live-FC e2e spun out (builder-VM box infra, not plan logic)
- [x] **PLAN 152** — Rust-native VZ supervisor · ✅ native objc2, Swift deleted; WS-C fork primitive satisfied (snapshot/restore + fork stack), WS-D nested-KVM out-of-scope for vz parity
- [ ] **PLAN 118** — Supervisor standby pool · 🟡 **vz + libkrun DONE** (saved-standby warm pool live-validated + self-replenish #840 + overshoot flock closed); open boxes: the **non-vz** FC standby pool (the mvmd-facing deliverable), and new **Part C / PR-10c** — density + concurrent-launch distribution bench (per-instance footprint + P50/P95/P99 under concurrency), 🔴 proposed, extends Part A's probe, read-only/no-bypass, closes the no-published-numbers gap surfaced by external prior art (`specs/notes/external-agent-sandbox-runtime-prior-art.md`)
- [ ] **PLAN 159** — vz-inspired macOS VZ DX · 🟡 **all vz work shipped** (warm pool, checkpoint/fork, two-copy + instant memory fork, live Vz validation); the only open boxes are **non-vz**: WS-5 D (verb renames / curl\|sh installer, folds into Plan 181 WS-D) + signed delta-image distribution
- [x] **PLAN 123** — Network / storage / warm-start · ✅ **DONE** — Phase A/B done; C1/C4 done; C3 (Vz save/restore) MET via 159 WS-2; the lone residual, C2 (FC live-memory), is carved to **Plan 175** (live-KVM-gated), not a 123 box
- [x] **PLAN 124** — Lean guest agent · ✅ **core complete** — full D1.2 RPC thread landed (stubs + check-stubs gate + 2a contract + 2b client + 2c adoption); D1.3 SDK veneer → Plan 125; Phase E signed config-on-device DESCOPED (baked + verity-sealed, no vsock round-trip); the residual KVM-live-verity / libkrun-Vz overlay-attach / no_std items are explicit **own-efforts**, rehomed out of 124 scope
- [x] **PLAN 125** — CLI surface + SDK DX veneer · ✅ **CLOSED / rehomed** — Phases B/C/D shipped in both SDKs; Phase A closed as "grouped surface + deliberate conveniences"; Phase E shipped `--secret NAME:host`, decorator coherence, doctor backend matrix, named security profiles, guest broker transport, typed `host.audit.v1` / `host.time.v1` / `host.cost.v1` clients, Python/TypeScript cdylib shims, host-spine coverage, and libkrun live `host.audit.v1` proof. The remaining host-services daemon/process-model work is explicitly **Plan 202** (per-tenant daemon, signer-helper admission signing, restart/head rebuild, mvmd adoption, and retirement of `spawn_broker_services_if_admitted`), not Plan 125.
- [ ] **PLAN 126** — Dependency reduction · 🟡 ~30%; duplicate-major lock-gate landed (+ supply-chain CI restored); D1 forbidden-dep-gate landed (closure ban on sigstore/opendal/pgp); aws-lc-rs ban still blocked by oci-client; dep-baseline.md write-up remains
- [x] **PLAN 177** — Backend consolidation (8→4) · ✅ both phases merged (#806/#789/#812/#814/#817); DX-parity → Plan 189; lone caveat = host-gated hardware smoke
- [x] **PLAN 182** — Trait hygiene + backend catalog · ✅ DONE — Clock/KeyProvider unified, `backend_catalog!` single-source, doctor sourced from it, arch docs current (all via #802). The lone open box (literal `cargo test --workspace`) is closed as documented-environmental: package-by-package + `-E 'not package(mvm-backend)'` are green; the aggregate only SIGKILLs the `mvm-backend` unit-test bin via macOS amfid codesign on this host (CI runs it green)
- [x] **PLAN 184** — Backend descriptor registry · ✅ DONE — catalog promoted to a `BackendDescriptor` registry (descriptor-named helpers); dual `instantiate`/`instantiate_dyn` constructors with dyn↔enum parity test; doctor migrated to `instantiate_dyn`; `AnyBackend` narrowed to enum-specific ops (no duplication remained); boundary + ordering-freeze tests; arch/supervisor docs describe the behavior/discovery/dispatch split
- [x] **PLAN 185** — Idiomatic Rust hygiene audit · ✅ COMPLETE (Phases 1–7, all tasks closed): Phase 1 TestEnv migration (mvm-core/mvm-hostd/mvm-build/libkrun-sys/**mvm-cli complete** — duplicate local env-test locks deleted; only host-gated mvm-backend env tests remain for CI/Linux); Phase 2 poison-lock policy decided + applied (env serializers folded into TestEnv, runtime state locks fail-closed); Phase 3 naming/typed-selectors COMPLETE (#892 `DeviceMapperBackend` + #894 `VmEgressProxy`/`SupervisorEgressProxy` + #895 typed `BackendKind` selectors). Phase 5 Task 8 DONE (SAFETY invariants on the 12 simple-syscall mvm-guest blocks; `mvm-verity-init` dm-verity bin done — 13 blocks annotated + fixed-payload ioctls isolated behind a safe `dm_ioctl_fixed` wrapper with a `const _` size assertion; `mvm-guest/console.rs` done — every unsafe block annotated + the post-fork `putenv`/`execvp` malloc path replaced with a pre-built `execve` since the agent is multithreaded at console-fork time; `mvm-guest-agent` bin done — four remaining close/signal-test blocks annotated; `vz_objc.rs` objc2 cluster done #976 — every unsafe block now annotated). Phase 5 Task 9 DONE-by-verification (test-support dev-only + optional stacks gated/documented, check-core-runtime-free enforced). Phase 4 Task 6 DONE — every hand-written `#[allow(clippy::too_many_arguments)]` eliminated: `boot_builder_vsock` → `BuilderVsockBoot` (#920); the two claim-12 paths → builders, bodies byte-preserved via top-of-fn destructure (`sign_into_headers` → `SignRequest` #926, `terminate_and_substitute` → `TlsTermination` #927); and the `compile_error!`-confirmed dead FC instance/pool/tenant cluster (`vm/instance|pool|tenant`, `bridge.rs`, `disk_manager.rs`) deleted with `security/jailer.rs` trimmed to its live `jailer_available()` probe (#931, ~3.8k lines, last allow removed by deletion). No hand-written `too_many_arguments` allow left (only bindgen FFI). Phase 6 STARTED — Task 13 doc-gen run: the Phase 3 renames introduced **zero** broken intra-doc links (verified), but the run surfaced ~115 *pre-existing* broken intra-doc links across every crate; `mvm-core` cleared (16 sites, #939) + `mvm-build` unconditional path bugs fixed (45→32 under `--all-features`, #941). **Refined Task 13 finding:** the doc-link count is feature/platform-sensitive — many targets are `#[cfg(feature)]` modules (need `--all-features`) and a cluster is `#[cfg(target_os="linux")]` builder-VM bins that resolve only on a Linux doc build (backticking them would degrade valid Linux docs), so the Phase 7 doc gate must run on **Linux + `--all-features`, per-crate**; only links broken there are real bugs. Task 12 (secret/debug exposure) DONE (#943) — audit clean (gate + `SecretBox` + zeroize + redacting Debug already cover it; field-sweep found no unprotected types), closed the Step 3 gap with negative redaction tests for `HostSigner`/`ResolvedBinding`/`EgressCa`. Task 10 (typed errors in tests) DONE-by-audit — surface is tiny: typed-error paths already use `matches!`, the rest is `anyhow`/`serde` string-matches where the string is the only handle; converted the one genuine candidate (`load_master_key` now downcasts to `RotationError::KeyFilePerms` + matches the structured `mode`). Task 11 (fixture consolidation) DONE (#953) — six near-identical minimal `ExecutionPlan` fixtures collapsed into a shared `mvm_core::plan::test_support::PlanFixture` builder (cfg/test-support-gated, no new deps), the mvm-hostd audit cluster migrated to thin wrappers, net −156 lines + 2 builder unit tests. **Phase 6 Tasks 10/11/12 + Task 13 (mvm-core, mvm-build) done.** Phase 7 closeout VALIDATED on the x86_64 Linux box: `cargo test --workspace` green — 3720+ tests across the heavy crates alone (mvm-core 1244, mvm-hostd 962, **mvm-backend 914** — the latter SIGKILLs under macOS amfid, so Linux is the only place it runs) + the rest, **zero genuine failures**. The Linux run surfaced + fixed a real test-isolation bug (`mvm-host-vm-init` leaked a non-existent `TMPDIR` to 15 parallel tests; `cfg(linux)` so macOS never ran it — `TestEnv`-fixed, #960, 151/151); the only other non-green is `each_embedded_binary_starts_with_elf_magic` which fails by design under `MVM_SKIP_EMBED_BINARIES=1` (stub payloads). clippy green in the required macOS CI env (all 185 changes). **`cargo doc --workspace --all-features --no-deps` now GREEN on Linux** under `-D rustdoc::broken_intra_doc_links` — all **122** pre-existing broken intra-doc links fixed (mvm-core/mvm-build via #939/#941, then the full sweep across every crate + xtask on `docs/plan-185-task13-doclinks`; backticked `<placeholder>`/literal-bracket prose, private/method/cross-crate refs, and module-doc `//!` overview lists; valid `///` item links preserved). **Task 13 DONE.** The pre-existing Linux-only `mvm-host-vm-init` clippy lints (12: `doc_lazy_continuation` + empty-line-after-doc + collapsible if-let) are also **fixed** — the `ci-full` `clippy -p mvm-build -p mvm-backend --all-targets` Linux lane is green on the box (no cascade). **Task 8 (`vz_objc.rs` objc2 SAFETY audit) DONE (#976)** — the ~16 gap SAFETY notes filled citing the serial-dispatch-queue / single-guest invariant (the file already had 89 + uses typed objc2); comment-only, verified on macOS arm64 (the only host that compiles it). **PLAN 185 COMPLETE — all phases and tasks closed, no remaining deferrals.**
- [ ] **PLAN 189** — VZ DX parity (post-convergence) · 🟡 in progress — WS-3 `dev status --json` landed; remaining: save/restore verbs, cached fast-boot default, more --json coverage, base pinning (spun out of 177; sibling of 159)
- [ ] **PLAN 175** — Firecracker live-memory warm-start · 🔴 not started (live-KVM-gated)
- [x] **PLAN 183** — Builder-VM egress posture + network bootstrap · ✅ (E2E-proven 2026-06-12; Vz checkpoint-integration follow-ups tracked in the plan)
- [x] **PLAN 180** — Strip spec refs from code comments · ✅ (lint-gated, #786)
- [x] **PLAN 188** — Capability projection seam (ADR-080 P5) · ✅ LANDED (#801); kernel-side wiring spec'd as Plan 190; WASI-context mapping deferred
- [x] **PLAN 186** — Trace hardening (ADR-080 P1/P3/P4 + hardened P2 pin) · ✅ LANDED (#809; caught + fixed a live shell-injection in the FilesWrite lowering)
- [x] **PLAN 187** — Secret-scan admission gate (ADR-080 P7) · ✅ LANDED (#811)
- [x] **PLAN 190** — Kernel egress decision converges on CanonicalEgress (ADR-080 P5 close-out) · 🟢 LANDED (kernel leg; lenient L4 lowering; zero claim-10 behaviour change; WASI-context mapping deferred to runner plan)
- [x] **PLAN 191** — Declarative file materialization (ADR-080 P2-full) · 🟢 P2-full LANDED (FilesWrite lowers to the declarative `App.files` IR field, baked into the rootfs at build time via `mkFunctionService` `extraFiles`; the `before_start` shell hook is removed — file content/paths never reach a guest shell)
- [x] **PLAN 192** — WASI capability projection (fs/env, ADR-081 A1) · ✅ LANDED — `mvm-core::policy::projection_fs_env` (`CanonicalFs`/`CanonicalEnv`, traversal-refusing canonicalizers, intersection-only `clamp_fs`/`clamp_env`, backend-agnostic WASI preopen/env-name shapes) + `WasiCapPolicy` bound on `EffectivePolicy` + 2 clamp-never-widens property witnesses; no new deps, runtime-free gate green. A2 (`.wasm` admission) + A3 (guest runner) are follow-on plans
- [ ] **PLAN 193** — rvproxy network substrate (replace gvproxy/passt) · 🟡 WS-1 PROVEN (libkrun-unixgram live `dev up` through rvproxy, ~540k connections relayed, builder rootfs built — rvproxy #38/#42/#53) + WS-1.5 parity-gate scaffold `scripts/rvproxy-gateway-parity.sh` (gvproxy↔rvproxy conformance, refuses non-conforming binary) + CI lane LIVE `.github/workflows/rvproxy-parity.yml` (macos-latest, pinned-rev candidate via `RVPROXY_CHECKOUT_TOKEN`, fail-closed) — validated green in CI 2026-06-15 (gvproxy+rvproxy PASS) + paths-filtered `pull_request` trigger; WS-2 native-flow port (the biggest win — replaces the in-line claim-10 datapath wrapper, Plan 141) DESIGNED (Plan 193 §"WS-2 design" + R2 contract authored into rvproxy `specs/plans/014` R2) now 🟡 R2 BUILD UNDERWAY — slice 1 deny-by-default (`default_egress_deny`, rvproxy #97) MERGED to rvproxy main; slices 2–4 remaining (2 flow-lifecycle events in flight by a parallel session, 3 flow-context transform + flow-kill, 4 mvm-rule redaction); then the mvm port + WS-3/4 + making the lane a required check (branch protection), cross-repo. **WS-2.2d mvm-side LANDED (#1009)** — native `rvproxy run --config` audit feed (tail the flow-audit JSONL → chain-signed `signer_task`, no splice) proven live on libkrun, AND the native-enforcement parity arm is now binary-discriminating: two `MVM_GATEWAY_NATIVE_E2E`-gated witnesses (deny-by-default exports a denied flow; an L4 allow-rule config denies the unlisted dst for `l4_allowlist_miss` + admits the listed dst), folded into `scripts/rvproxy-gateway-parity.sh` step [2/4]. Remaining WS-2.2d = delete the splice + Plan-141 `on_packet` hooks + flip `MVM_GATEWAY_BRIDGE` default-on (gated on the gate being green by default)
- [ ] **PLAN 195** — Builder-VM fingerprint narrowing · 🟡 planned — drop the redundant whole-workspace `Cargo.lock` from `builder_vm_source_fingerprint` (flake forbids buildRustPackage → L3 byte-hash already authoritative) to kill the ~9s Stage 0 re-materialize churn; Commit 2 tightens build.rs rerun triggers. Build-perf only, no claim impact. (194 reserved for ADR-081 A3)
- [x] **PLAN 197** — `WorkloadBackend` type-bar (core security features non-skippable) · ✅ **mvm-side DONE** — Phase 1 MERGED (#860); Phase 2a (vsock substitution channel) MERGED (#866) + **default-path plan-persist gap closed (#909)** so the substitution endpoint now actually spawns on a plain `up`/`invoke --hypervisor vz`/`libkrun` with secrets (no `MVM_GATEWAY_BRIDGE` needed) — **vz DATA PLANE PROVEN LIVE 2026-06-15** (driver `up --name -d` → `vm wait` → `invoke --attach`: httpbin reflects the real cred, guest holds only the placeholder, claim 12 refuses a non-allowed host, 6 dials prove the 5253 listener re-accepts; no code change). Phase 2a COMPLETE on vz. The lone residual, 2b (transparent :80/:443 terminator), is rehomed to **Plan 193/rvproxy** (cross-repo gate — macOS has no nft, so it can only live in the gateway); not a Plan 197 mvm-scope box. Marker trait gates the admitted launch path so qemu (a real dev/test VMM) is type-barred and a new backend can't reach the funnel without the shared enforcement (mock is permitted as the ADR-045 hermetic test double — carries no real workload). Arose from the Sprint 55 vz closeout finding.
- [ ] **PLAN 199** — Host runtime packaging + crate boundaries · 🟡 source-built `mvmctl` + host overlay complete; release-install policy/matrix/signature CI complete; crate-boundary audit complete; remaining = builder-VM-verified native VMM Nix recipes (`libkrunfw`/`libkrun`) in the source-built overlay shape (external prior-art pattern), plus `nix flake check` / `.#mvmctl` build follow-ups. Signed binary install remains primary; source-checkout Nix never fetches mvm release binaries
- [ ] **PLAN 200** — Machine UX/DX layer · 🟢 in progress — `machine run` shipped (#968); Session 3 item 1 `run --image <oci>` boots end-to-end (#1036: injected static guest agent/netinit + honest `overlay_aware` sidecar + vz ext4-geometry fix, live-verified macOS-26/vz); WS-B `--net`/`--allow-host` uniform FC/libkrun/Vz egress enforcement **MERGED (#1003)** with follow-ups through #1034 closed (MCP admitted, BridgeConfig.policy/AllowAll removed, uniform bare host:port L4, DHCP/ARP loopback-only posture, transient eth0 enabler, and `up` direct-boot network-policy threading). First-class `mvmctl machine` surface over existing runtime primitives; no-host-Nix binary-install DX, image-backed one-shot docs, explicit network opt-in, persistent named machines, SDK parity, verified portable artifacts, measured hot-start latency, friendly exec/shell wrappers, `mvm.toml` schema v2 with strict security defaults, and default-binary-closure dependency budgets
- [ ] **PLAN 201** — `WarmLease` borrow-handle + batched guest exec · 🔴 proposed — DX-ergonomics layer over the Plan 118 standby pool + Plan 169 agent-RPC: RAII claim/release that stops + replenishes a fresh standby, plus staged batched guest exec. Caller-convenience only; no new backend/transport, admission + audit untouched. Docs-only so far (#937).
- [ ] **PLAN 202** — Host services daemon (per-tenant, not per-VM spawn) · 🟡 in progress ([ADR-084](adrs/084-host-services-daemon-not-per-vm-spawn.md), #977) — re-architect the broker/audit-signer from the shipped per-VM subprocess fork (Plan 125 E5.3b — `2N` processes + a per-boot spawn, availability coupled to `MVM_GATEWAY_BRIDGE`) to **two long-lived per-tenant daemons** VMs register/deregister with: `O(active tenants)` processes not `O(VMs)`; the moat (keyless broker / key-holding signer) + claims 12/13 preserved; guest wire unchanged; registration driven by the admitted plan (decouples availability from the egress bridge); mvmd consumes the same daemon per tenant. Phase 1 broker daemon/control plane, Phase 2a signer-helper child + per-VM heads, Phase 2b helper forwarding, Phase 2c helper-backed admission signing, Phase 3a daemon default-on, and Phase 3c doctor daemon-state reporting landed. Remaining: Phase 2d restart/head rebuild, vz live-verify, supervision/restart journal, mvmd adoption, and retiring `spawn_broker_services_if_admitted`.

## Plan details

```
PLAN 121 — Crate consolidation (32→15)          ✅ DONE
PLAN 169 — Backend-agnostic agent RPC           ✅ DONE
PLAN 166 — QEMU Linux dev/test backend          ✅ DONE (Phase 2)
PLAN 165 — Sealed-prod interactivity (claim 15) ✅ DONE

PLAN 129 — Secrets / SigV4 substitution         ✅ COMPLETE (2026-06-11) — clean-room e2e GREEN on QEMU (secret set → build compile → up → invoke --attach; httpbin reflects the real key, guest placeholder-only); declared substitution (Bearer/Basic + SigV4/HMAC #796, bind-checked, key-never-leaves) + undeclared detection (E1 Step 2: entropy/IBAN/names + 17-vendor secret list + per-dest profiles) on the vsock endpoint AND the :80/:443 terminator (#791); claim-12/13 egress leak-gate (Phase F / claim 16 #790); endpoint self-confines Landlock+seccomp (#797, box-validated 6.1); audit recorder wired into the spawned endpoint; authoring via SDK secret() + up --redact (#785) + secret set --type sigv4. FC bringup fixes (#804); live-FC egress e2e spun out — next wall is builder-VM box infra, not plan logic (specs/prompts/129-fc-bringup-debug.md). Descopes (not dangling): guest https/CONNECT superseded by the terminator; signer/injector process-moat delivered by the jailer wrap; hardware-sealed signing out of ADR-002 scope
  [x] keyholder, resolver, binding store, `secret set`
  [x] host substitution endpoint (UDS + AF_VSOCK)
  [x] SigV4 canonical-request builder
  [x] in-guest substitution client + forward-proxy
  [x] guest↔host vsock transport, both directions   — PR #708/#709
  [x] workload env injection via RunEntrypoint proto — PR #711
  [x] e2e substitution over AF_VSOCK loopback        — PR #710
  [x] claim-13 audit (secret.substituted + secret.placeholder_dropped on endpoint refusal)
  [x] retire dead in-guest ADR-049 scaffolding       — PR #713
  [x] per-VM substitution-endpoint moat (mvm-hostd)  — PR #715
  [x] QEMU spawns endpoint at boot, fail-closed      — PR #717
  [x] invoke injects HTTP_PROXY+placeholders; guest forward proxy — PR #718
  [x] on-box endpoint validation: real AF_VSOCK + real encrypted store
      (placeholder mint, substitution success, claim-12 refuse) — 2026-06-08
  — SDK-free egress (transparent terminator) · direction 2026-06-08 · branch feat/plan-129-egress-terminator · draft PR #735 · plan: specs/notes/plan-129-stage1b-2-transparent-terminator-plan.md ("Resume state")
  [x] SDK secret() type/hosts + ADR-049 retire             — PR #722/#723
  [x] passt-redirect feasibility PoC (nft OUTPUT + SO_ORIGINAL_DST) — GREEN on box
  [x] terminator core (orig_dst, request parse, handler, reader) — reviewed — PR #735 (merged)
  [x] terminator listener + raw-http forward + EndpointConfig wiring — Task 4 — PR #735 (merged)
  [x] redirect mechanism box-validated: nft prerouting iifname<tap> REDIRECT + SO_ORIGINAL_DST (Task 0')
  [x] FC wiring: EgressRedirect (nft TAP redirect) + wire_egress_substitution + stop_vm reap — Task 5 — PR #744 (merged)
      (mechanism corrected: FC=TAP+nft NAT, not passt/skuid; passt path deferred to libkrun)
  [x] SDK-free egress e2e — Task 6 — QEMU leg GREEN end-to-end 2026-06-11
      (`secret set` → `build compile` value-clean → `up` endpoint-spawned,
      placeholder-only guest → `invoke --attach`, httpbin reflects the REAL
      `Bearer REALKEY-…`). The four FC follow-ups it surfaced are CLOSED:
      FC kernel-less-workload fallback + bridge gating + seccomp
      `sched_getaffinity` (#804); audit Recorder wired into the spawned endpoint
      (box-validated confined); `invoke` empty-stdin → `[[], {}]`. FC endpoint
      spawn is the microvm `wire_egress_substitution` path. (`live FC` boot e2e
      itself spun out — next wall is builder-VM box infra, not plan logic.)
  [~] live FC SDK-free egress e2e — SPUN OUT (backend bringup, not plan logic):
      3 real bugs found+fixed live (#804); next wall = cold builder-VM nix-build
      crash on the box. Wire path validated on QEMU; tracked in
      specs/prompts/129-fc-bringup-debug.md.
  [x] Stage 2 S2.1–S2.6: name-constrained per-VM CA (crypto::egress_ca) + host
      cert/key split + kernel-cmdline cert + placeholder-env delivery (mvm.egress_ca /
      mvm.secret_env) + SNI-gated TLS terminator (terminate bound / splice unbound,
      reqwest re-origination) + :443 nft redirect + ADR-006 Accepted / ADR-067
      proxy-native-primary — PR #761; TDD plan: specs/notes/plan-129-stage2-https-ca-tdd-plan.md
  [~] Stage 2 S2.7: live SDK-free https FC box e2e — spun out with the FC-live
      leg above (https terminator code + per-VM CA done #761; live box-boot is
      the same builder-VM-infra blocker, not plan logic)
  [x] Python `mvm.secret(type=,hosts=)` egress surface + retire `_runtime.py` — PR #722
  [x] TS `secret()` egress + retire `runtime.ts` + docs .mdx  — PR #723
  [x] secret-egress example workload (examples/python/secret-egress)
  [x] Phase E: undeclared secret/PII egress redact-to-XXX detector
      (RedactingSubstitution mask-and-continue; PiiRedactor/SecretsScanner
      redact()) wired always-on into the gateway bridge — PR #733
  [x] Phase E uniform coverage: same RedactingSubstitution wired into the
      per-VM substitution endpoint (request-level), so every backend routing
      egress through it scrubs identically; claim-13 `secret.redacted` audit
  [x] local secret-workload launch (mvm's domain): compile strips SecretRef
      from the baked image + emits workload.json; `up --flake <dir>`
      auto-discovers it → lowers plan.secrets → admits → endpoint spawn.
      Fixed: main `up` path only threaded the signed plan to the backend under
      MVM_GATEWAY_BRIDGE=1, so the QEMU endpoint never spawned — now QEMU
      threads it unconditionally (libkrun/Vz stay flag-gated)
  [x] box-validated on QEMU (dev-kvm): secret-free image (launch.env={}),
      guest holds ONLY the placeholder (substitution-env.json), endpoint
      spawns at boot + is reaped on `down`
  [x] `invoke <name> --attach` dispatches RunEntrypoint into the running `up`
      workload (reuses endpoint + placeholders); function body runs with the
      injected proxy+placeholder env
  [x] guest loopback made functional → PR #749: netinit must not blackhole its
      own `lo` (EINVAL) AND /init must bring `lo` up (ENETUNREACH) — both were
      broken, killing the forward proxy. The two together complete the loopback
  [x] FULL live-guest e2e CLOSED on QEMU (#745+#749+#755): destination (httpbin)
      reflects "Authorization: Bearer REALKEY-…" (REAL credential) while the guest
      holds only mvm-secret-… — workload→loopback proxy→guest-host vsock→endpoint
      substitute→real http forward→echo. "A raw secret never enters the microVM"
      proven end-to-end on a live guest
  [x] SSRF resolver port-443 bug FIXED → PR #755: forwarder resolves+SSRF-filters
      itself, pins the safe IPs on the URL's real port (resolve_to_addrs). This
      closed the e2e (http forwards no longer hit :443). web_fetch/MCP unaffected
  [~] ephemeral serverless `invoke <artifact>` (boot_session_vm through admission
      + endpoint) — HOST SIDE DONE: `invoke --from-workload-ir <ir>` lowers the
      workload's secrets + admits a plan inside boot_session_vm (closure seam) so
      the backend spawns the substitution endpoint; QEMU reads plan_json directly.
      Box e2e + FC plan.json stash are the remaining (box-gated) follow-ups
  E1 Step 2 — per-destination egress PII + entropy redaction (design approved
      2026-06-10, specs/notes/plan-129-e1-step2-pii-entropy-redaction-design.md;
      no ML/NER — anchored+gazetteer names; scoped to cleartext vsock endpoint)
    [x] design + honest threat-model framing (hygiene layer, not a boundary)
    [x] slice 1: EntropyScanner (Shannon entropy, audit-first, no echo)
    [x] slice 2: IBAN (mod-97) added to structured PII set
    [x] slice 3: name detector (field-label + PII co-occurrence + gazetteer)
    [x] slice 4: RedactionAction + redaction_profiles + resolve (mvm-core)
    [x] slice 5: destination-aware wiring; fail-closed over-cap/compressed bodies
    [x] admission carriage: redaction rides inline in signed ExecutionPlan →
        redaction_from_signed_json → backend EndpointConfig → from_plan →
        with_redaction_policy (a plan carrying redaction flows end-to-end);
        consume per-dest pii/secrets disposition (no longer RESERVED)
    [x] CLI authoring: `mvmctl up --redact HOST[=audit]` parses a per-destination
        RedactionPolicy → SynthesisInput → synthesize_plan sets ExecutionPlan.redaction
    [x] enriched always-on default secret list: +17 high-precision vendor token
        shapes (gitlab/fine-grained-PAT/stripe-test+restricted/sendgrid/npm/pypi/
        square/shopify/digitalocean/vault/postman/linear/figma/google-oauth/
        slack-webhook) in SecretsScanner DEFAULT_RULES — anchored prefixes, low-FP,
        masked on ALL egress by default (no flag). JWT deliberately excluded (legit bearer).
    [x] terminator-path redaction + fail-closed + audit (typed TerminatorError;
        both :80/:443 cores; adversarial fail-closed tests + security review)
    [x] live PII spans for name co-occurrence: PiiRedactor::match_spans threaded
        into NameScanner on the live redact_bytes_for path (names run pre-PII-mask)
    [~] IR/SDK developer-declared authoring — DESCOPED: CLI --redact + SDK
        secret() + mvmd bundle cover authoring. See plan §"Deferred follow-ups".
  [x] Phase F: egress no-secret-to-guest leak-gate (claim-12/13 backstop) —
      canary tests (handed_placeholders_never_contain_the_secret_value /
      substitution_endpoint_refuses_unbound_destination /
      audit_chain_carries_no_secret_value) in crates/mvm-hostd/tests/
      egress_secret_leak_gate.rs + claim doc claim-egress-no-secret-to-guest.md +
      catalog.md row 16 witnesses (Preview), gated on every PR (Test lane +
      check-claim-catalog)
  [x] substitution-endpoint jailer wrap: self-applied Landlock + seccomp-BPF
      (ConfinementSpec::substitution_endpoint — store dirs + TLS/DNS read-only,
      BRIDGE_SYSCALLS + tokio/rustls additions), fail-closed before serving the
      first guest byte; macOS stub no-op. Allowlist completeness box-validated
      (Linux runtime check) like the firecracker-bridge confinement
  [~] forward proxy https/CONNECT — DESCOPED (superseded): https is handled by
      the host name-constrained TLS terminator (Stage 2, #761); the guest can't
      substitute into its own TLS. HTTP_PROXY path stays http-only, fail-closed
      for https (a placeholder, never a real secret, would be tunneled)
  [x] forward-path signing integration (SigV4 + HMAC)  — prepare_request branches
      on the resolved auth_type, routes SigV4/HMAC through the bind-checked
      endpoint.sign (claim 12, key-never-leaves) and assembles the
      Authorization (AWS4-HMAC-SHA256) / x-mvm-signature header. Credential
      model: the secret value IS the secret-access-key (in the encrypted store,
      the signing key); access_key_id/region/service are non-secret operator
      metadata on the binding (mvmctl secret set --type sigv4
      --aws-access-key-id/--region/--service) reconstructed onto the SecretRef
      at admission. Security tests: sigv4_request_gets_a_valid_authorization_header,
      sigv4_forward_path_matches_the_aws_get_vanilla_signature,
      sigv4_unbound_destination_is_refused_before_signing,
      sigv4_without_params_is_refused, hmac_request_gets_a_signature_header +
      hmac_unbound_destination_is_refused_before_signing.

PLAN 152 — Rust-native VZ supervisor            🟢 native objc2; no Swift
  [x] WS-A exit channel (vsock + PID-1 helper) — PR #698 (merged)
  [x] WS-B threading decision (serial queue) — PR #697 (merged)
  [x] WS-B Swift→Rust rewrite (boot/vsock/control/snapshot/flow-audit) — PR #700 (merged)
  [x] WS-B parity gate (#703) → Rust-only after Swift deletion (plan-174)
  [x] WS-B finalize: resolver→Rust bin + DELETE Swift crate — plan-174
  [x] WS-E VZ-config hardening (validateSaveRestore, MAC pin) — folded into #700
  [x] SAVE pause-before-save regression fix (post-finalize) — PR #740 (merged)
  [x] post-finalize hardening: resource-cap check, self-sign codesign lock,
      terminal-error fidelity, SAFETY-comment accuracy, doc-truth — PR #772
  [x] WS-C fork primitive — SATISFIED by #700 snapshot/restore + the Plan 159
      WS-2 fork stack: two-copy `checkpoint fork --boot` (admitted child) and
      instant memory fork of a RUNNING parent (0.91s, claim-8 admitted,
      gvproxy-only invariant). No separate fork primitive remains.
  [~] WS-D nested KVM (/dev/kvm in guest) — OUT OF SCOPE for "100% vz". Sprint 55
      requires no nested path; vz hosts the Linux workload guest directly (the
      whole point of the backend). Nested KVM is a distinct future capability
      (workload-inside-workload), not a parity gap vs libkrun/FC. Recorded, not
      built.
  [x] Post-closeout dev-loop polish (#868/#870) — vz `up`/`down` taken sub-second
      (~0.45s each): startup orphan-sweep collapsed from a per-VM-dir `pgrep` +
      per-pid `ps` storm into one `ps -axww` snapshot, rootfs digest sidecar-cached
      on size+mtime (no ~230 MB re-hash per boot), and the supervisor escalates a
      graceful ACPI stop to a forced `stopWithCompletionHandler` so `down` exits
      clean instead of waiting out the host SIGKILL grace. `up --console` boots
      straight into the PTY-over-vsock console (dev image forced). Companion fix:
      the startup sweep no longer reaps live managed/dev VMs reparented to launchd.
  NOTE: Swift control socket self-deadlocked on async VZ ops; Rust fixes it
  (ADR-056 addendum). #772 deferred-robustness triage (2026-06-13 close-out):
  exit-listener 2nd-conn = correct-by-design (one-shot accept; long-running
  workloads never connect); control-verb single-flight = correct-by-design (all
  verbs serialize on the VM's libdispatch serial queue); validateSaveRestore on
  Restore = correct-by-design (a non-snapshotting Boot is fine, so it's a warn
  not a gate; SAVE/Restore surface the real framework error). No code change
  needed for these three. Still genuinely deferred (cosmetic, own PR):
  VzIngest/mvm-vz-drainer dead-code sweep — superseded by the Rust in-process
  `VzGvproxy` splice but not provably dead; delete in a dedicated sweep once the
  Rust path is confirmed stable.

PLAN 159 — vz-inspired macOS VZ DX               🟡 152-independent slice shipped
  [x] WS-3 mvmctl sign + doctor signing — PR #667 (plan-168)
  [x] WS-5 C shared --json (cache/network/snapshot/audit) — PR #667
  [x] WS-5 B session --continue/--resume/--ephemeral — PR #667
  [x] WS-4 resumable + honest-cost dev-image download — PR #667
  [x] WS-5 E streamed exec (ExecEvent) — PR #712 (plan-172)
  [x] WS-5 E follow-up: enforce exec timeout_secs — plan-173
  [x] WS-1 warm pool (Plan 118): libkrun + Vz saved-standby — see PLAN 118 block
      for the full workstream detail
  [x] WS-2 checkpoint+fork — fs_quick (#762) + vm_full (#770): mvmctl checkpoint
      create/ls/rm/fork + APFS-CoW capture + integrity-checked fork + lineage +
      checkpoint.created/forked/restored audit + fs_quick+vm_full capability +
      vm_full memory save/restore (saveMachineStateToURL) + vm_full fork arm +
      restore_checkpoint + retire snapshot save/restore. cache GC.
      PR3 (#780): checkpoint diff <a> <b> (metadata+manifest compare) + Vz
      pause/resume (native vCPU quiesce). WS-2 COMPLETE.
  [x] two-copy fork: checkpoint fork --boot (admitted child boot, fs_quick) —
      fresh claim-8 admission via boot_forked_child + admit_plan_for_boot reuse;
      no-clobber rootfs adoption; resource shape flags > parent plan > defaults (#826).
  [x] Vz workload liveness: /init detaches sealed-workload stdin from the
      input-less console (`</dev/null`) + examples/sleeper long-lived fixture
      (unblocks live Vz validation of WS-2 + the fork semantic-A spike);
      flake-locks-clean CI lane excludes the override-input examples.
  [x] AuditEmitter + host_keypair + plan_persist + pure checkpoint bind helpers
      hoisted to mvm_hostd::audit (mvmd-reachable library API); mvm-cli shimmed
  [ ] WS-5 D verb renames; curl|sh installer; --json remainder
  [ ] signed delta-image distribution (unowned — needs a home)
  [x] live Vz WS-2 round-trip validation + fork semantic-A spike — RUN
      2026-06-12 via Plan 183 WS-D: first live Vz workload boot; vm_full
      create + pause/resume proven; semantic-A ANSWERED (VZ pins machine-state
      restore to the saved device config → stay semantic B; live two-copy fork
      goes through fs_quick). Vz checkpoint-integration gaps → Plan 183
      follow-ups.
  [x] instant memory fork: vm_full fork of a RUNNING parent → second live VM in
      0.91s incl. claim-8 admission (same-identity clone model; recorded-sha admission; gvproxy-only invariant) (#833)

PLAN 118 — Supervisor standby pool              🟡 libkrun + Vz done; FC follow-up open
  [x] 1a primitive + 1b-i trait seam/registry/libkrun + 1b-ii reaper/doctor/`mvmctl pool`
      /bench-fix + 1b-iii up auto-claim (try_warm_claim/replenish/--warm-pool-size,
      fail-open) + bundled-kernel compat key — libkrun mkGuest warm claim FIRES
      end-to-end (live-validated "Claimed a warm standby")
  [x] Vz saved-standby warm pool: per-image spawn (seed boot → capture_vm_full →
      pid=0 handle), claim (verify_content → clone blobs → build_child_supervisor_config
      → VzChildSupervisorSpawner), image_sha256 compat key (mismatch = no-match, not
      error), TTL-only reap for pid=0 standbys, --rootfs CLI flag, doctor reports
      vz=true on macOS 14+. All libkrun pool tests untouched.
      LIVE-VALIDATED 2026-06-13: warm 6.5s, "Claimed a warm standby — skipping
      cold boot" FIRES, claimed VM alive + pause/resume responsive. Two bugs
      found+fixed live: gateway-bridge drainer decoded a bare plan where up
      threads the signed envelope (now decodes both shapes); spawn discarded the
      seed config instead of persisting it to the pool (claim then read a
      torn-down dir). HONEST latency: on the trivially-fast default image
      warm-claim 2.3s ~= cold 2.1s (restoring 512 MiB costs ~a tiny guest's cold
      boot); the reclaim is real for heavy-init workloads, marginal here.
  [x] Vz pool self-replenishes (#840): after a Vz claim drains the pool, `up`
      hands the re-warm to a DETACHED `mvmctl pool warm` subprocess (own process
      group, null stdio, inherits env, via current_exe) — `up` returns at once
      and the child re-warms only the deficit off the hot path. Live: claim
      drained 1→0, detached re-warm refilled to 1.
  [x] warm-pool overshoot flock — CLOSED in the vz close-out: `warm_to_target`
      now holds a `FileLock` on the pool dir across the read→decide→spawn region,
      so a second concurrent warmer blocks, re-reads the updated count, and
      spawns only the remainder (no more transient ~1 overshoot). Deterministic
      test verifies it (fails as 2×target without the lock).
  [x] Warm claim reuses the admission image sha (#846): the claim's compat key
      threads `ExecutionPlan.image.sha256` (already computed by claim-8
      admission) instead of re-hashing the rootfs a second time on the launch
      hot path. Byte-identical (sha256_file == kernel_sha256_hex on the same
      bytes — verified), so the compat match is unchanged; libkrun stays
      image-agnostic. Chosen over coupling to the WS-2 fingerprint (would weaken
      claim-8 byte-identity + tie pool.rs to dev_vz.rs). Live: claim still fires.
  [ ] Firecracker standby pool (the mvmd-facing deliverable) — gated on FC standby
      follow-up; not blocking current libkrun/Vz use
  [ ] Part C / PR-10c — density + concurrent-launch distribution bench (🔴 proposed,
      added 2026-06-16). Extends Part A's probe to two new metrics: per-instance host
      footprint (`bench microvm-density`, platform-split PSS/phys_footprint accessor)
      and launch P50/P95/P99 under concurrency (`bench microvm-launch --concurrency N`).
      libkrun → Vz → FC, staged. Read-only; every boot still goes through claim-8
      admission (no bypass), no new key/daemon/socket, `libkrun-live`-gated → zero new
      attack surface. Closes the no-published-numbers gap surfaced by external prior art
      (`specs/notes/external-agent-sandbox-runtime-prior-art.md`); proves the warm pool's
      payoff. Inherits Part A's blocker (needs a freshly-built default-microvm image for
      committed baselines); pure substrate (percentiles/footprint math/schema) lands
      VM-free now.

PLAN 183 — Builder-VM egress posture + net boot ✅ DONE (follow-ups tracked in plan)
  Last updated: 2026-06-15 (ALL deferred items now CLOSED: DHCP belt-and-suspenders
  resolved by WS-E2; persistent Vz builder VM gets gvproxy egress (live-validated
  DHCP lease 192.168.127.3, dev down reaps — #940); and the `doctor` builder-egress
  line lands — it parses the persistent builder VM's console.log for the last
  net-bootstrap outcome (lease/static-fallback/failed) + surfaces the per-arm posture,
  the earlier "needs host-side plumbing" premise was wrong since the outcome is already
  host-readable in console.log)
  [x] persistent Vz builder VM gvproxy egress (#940) — vz_builder.rs spawn+config+reap;
      live-validated (dev up lease 192.168.127.3 from gvproxy gw; dev down no leak)
  [x] doctor builder-egress line — guest_net::classify_builder_net_bootstrap +
      doctor builder_egress_check; live-validated (reports the DHCP lease)
  [x] follow-ups: fs_quick-on-Vz (pause-aware gate) + vm_full restore (gvproxy re-spawn, idempotent cleanup)
  Diagnosis proven 2026-06-11: boot-time install_egress_lockdown (OUTPUT DROP,
  proxy-uid-only) applied to the whole builder VM and dropped every nix fetch.
  WS-A moves the lockdown to the install arm (fail-closed) + opens egress for
  flake-build dispatches; the QEMU-only boot skip is deleted. Plus (WS-B/C):
  Vz builder gets no DHCP lease (eth0 unconfigured), and /etc/resolv.conf is a
  read-only baked file so leased DNS never lands. WS-E fixes two workload-boot
  defects: kernel fallback for kernel-less images (vz_objc Vz supervisor) and the
  unbound gvproxy datagram socket (root cause of the DHCP/DNS no-reply).
  [x] WS-A egress posture per arm (boot open; install-arm locked, fail-closed;
      per-job posture in persistent dispatch; drop QEMU-only boot skip) — landed
  [x] WS-B static gvproxy fallback when DHCP yields no lease — static fallback
      landed; shared guest_net module; DHCP root cause found + fixed in WS-E
  [x] WS-C writable /run-bind-mounted resolv.conf seeded with gateway resolver
  [x] WS-E vz workload boot: kernel fallback + bound gvproxy reply socket
  [x] WS-D E2E proven 2026-06-12: cold dev up green (703 in-builder fetches,
      0 resolve failures); Vz builder leases post-WS-E; claim-11 gates green;
      FIRST live Vz workload boot (sleeper, agent on vsock) + WS-2 round-trips:
      vm_full create ✅ pause/resume ✅; fs_quick-on-Vz, vm_full restore
      (gvproxy re-spawn), and Vz two-copy fork (fs_quick class; semantic-A
      answered: VZ pins restore to saved device config) → plan follow-ups

PLAN 124 — Lean guest agent                     ✅ core complete (D1.3 → Plan 125; own-efforts rehomed)
  [x] A1/A3 drop tokio+rtnetlink (-27 crates)
  [x] B universal agent in all images
  [x] C1 verity-sealed runtime overlay
  [x] D1.0/D1.1 schema SSOT
  [x] D1.2a protocol type stubs (protocol-v0.json → Python/TS via gen-stubs, drift-checked)
  [x] check-stubs drift gate wired into ci.yml + ci-full.yml Lint (Plan 128 C3 Step 2; Linux determinism verified)
  [x] D1.2 Step 2a machine-readable req→resp contract (Verb/ResponseVariant/response_contract in vsock.rs; drift-guarded)
  [x] D1.2 Step 2b contract-checked RPC client (call_unary/call_streaming/check_response; off-contract guard; PostRestore migrated)
  [x] D1.2 Step 2c mvm-cli unary call sites adopt call_unary (wait/readiness/session/console; commands/vm uncontended; −17 lines)
  [→] D1.3 SDK ergonomics veneer → Plan 125 (the new session)
  [✗] Phase E signed config-on-device — DESCOPED (premise superseded: runtime.json is build-time-baked + dm-verity-sealed; no vsock config round-trip to replace)
  [~] (own efforts — REHOMED out of Plan 124 scope) KVM live verity boot validation
      (live-KVM box-gated); libkrun/Vz overlay attach (its own plan); no_std agent core (stretch)

PLAN 184 — Backend descriptor registry          ✅ DONE
  [x] Promoted the catalog into a first-class `BackendDescriptor` registry
      (`descriptors`/`descriptor`/`descriptor_for_selector`/`_for_marker_file`/
      `started_vm_probe_descriptors`/`list_all`/`balloon`/`warm_start`
      `_descriptors`); macro stays one flat table; `VmBackend` untouched
  [x] Descriptor-driven construction for both consumers: `instantiate`
      (`AnyBackend`) + `into_dyn`/`instantiate_dyn` (`Arc<dyn VmBackend>`),
      with a dyn-vs-enum parity test across every backend
  [x] Migrated the clean generic site: doctor's balloon/warm-start collectors
      build via `descriptor.instantiate_dyn()` (no selector re-lookup, trait
      object). build.rs/exec.rs `auto_select()` sites stay on the enum (policy
      result + trivial `.name()`/`.stop()` — into_dyn would only add an Arc)
  [x] `AnyBackend` kept only for enum-specific ops (`auto_select`,
      `from_build_output`, `start_firecracker`, variant checks); no descriptor-
      shaped duplication remained to remove (182 + Task 1 already routed it);
      boundary test + ordering-freeze test added; supervisor comment + arch doc
      describe the shipped ownership split (behavior / discovery / dispatch)

PLAN 185 — Idiomatic Rust hygiene audit         🟢 started
  [x] Add `mvm_core::util::test_env::TestEnv` behind `cfg(test)` /
      `mvm-core/test-support`; migrate `mvm-core` keystore env tests; verify
      with focused tests + `cargo clippy -p mvm-core --all-targets -- -D warnings`
  [x] Migrate `mvm-backend::backend` selector/started-VM marker tests to
      `TestEnv` + `tempfile::TempDir`; keep the legacy backend env lock until
      the rest of that crate migrates
  [x] Expand test isolation into `mvm-cli` checkpoint/console env-mutating
      tests and `mvm-build` dev/Vz builder env-sensitive tests; replace
      shell-backed lifecycle-hook unit tests with deterministic runner fakes;
      remove a wall-clock assertion from an entrypoint cap test
  [x] Migrate `mvm-core`'s own env-mutating tests onto `TestEnv` — `config.rs`
      (incl. deleting its duplicate per-module `ENV_TEST_LOCK`/`env_lock` helper),
      `user_config.rs`, `policy/secret_binding.rs`; manual save/restore boilerplate
      removed; 1248 mvm-core tests + clippy green
  [x] Migrate `mvm-hostd` (reaper idle-timeout env + substitution_endpoint
      MVM_DATA_DIR; added the `test-support` feature to its mvm-core dev-dep) and
      `mvm-build` `runtime_overlay` (MVM_OVERLAY_BASE_URL; deleted its local
      duplicate `env_test_mutex` OnceLock)
  [x] Migrate `mvm-build` `libkrun_builder` (`ENV_LOCK`; MVM_NETWORKING/
      MVM_GATEWAY_BIN/XDG_CACHE_HOME tests — green under `--features builder-vm`)
      and `builder_vm_runtime` (`TIMEOUT_ENV_LOCK` + `GC_ENV_LOCK`; timeout +
      /nix-store GC-cap tests, dropping the let-old/match-old restore boilerplate)
  [x] Migrate `mvm-core` `domain/session` (`RuntimeDirGuard`→TestEnv, `ENV_LOCK`)
      + `domain/template_tags` (`DataDirGuard`→TestEnv, `DATA_DIR_LOCK`) and
      `libkrun-sys` `gvproxy`/`passt` (PATH + MVM_GATEWAY_BIN tests; deleted the
      crate-wide `TEST_ENV_LOCK`, added the mvm-core `test-support` dev-dep;
      lock-only reap tests keep a bare `TestEnv` guard)
  [x] `mvm-cli` batch (COMPLETE): `env/artifact_verify` (ENV_LOCK),
      `build/sandbox_record` (TsxGuard/ENV_LOCK), `vm/session`
      (RuntimeDirGuard/ENV_LOCK — added a `RuntimeDirGuard::set` helper so the
      guard-holding creator-pid tests mutate a 2nd var without a deadlocking
      nested `TestEnv::new()`), and `vm/up` (LOCK; `resolve_vz_workload_kernel`
      MVM_CACHE_DIR tests), and `template_cmd` (probe_test_lock + `clear_llm_env`
      now thread a `&mut TestEnv`), and `doctor` ts-runner tests (folded the
      holdout `ENV_LOCK` onto the shared TestEnv the EnvGuard already used —
      fixing a latent two-lock race), and `vm/tenant_resolution` (4 MVM_TENANT
      tests — also a no-lock latent race, now serialized) + `ops/mcp`
      (unique-name credential tests) migrated. **mvm-cli test env migration
      COMPLETE** — every remaining raw `std::env::set_var` in mvm-cli is
      production CLI-flag plumbing (`commands/mod.rs`, `build/build.rs`) or
      Linux+`builder-vm`-gated (doctor's `builder_backend`/`nested-kvm`, which go
      with the mvm-backend batch)
  [ ] `mvm-backend` env tests (host-gated: its test bin SIGKILLs under macOS
      amfid — migrate where CI/Linux runs them)
  [~] Phase 2 (poison-lock policy): policy decided + written into the plan —
      test/global *serialization* locks recover via `into_inner()` (fold env ones
      into TestEnv; cwd/signal ones use `unwrap_or_else(into_inner)`), runtime
      *state* locks stay fail-closed. Applied: folded the last two mvm-build env
      serializers (`builder_backend_select` `with_env`, `vz_builder`
      `with_supervisor_env`) into TestEnv; audited runtime `.lock().unwrap()` sites
      as intentionally fail-closed. Remaining: `mvm-cli::dev_vz` (hot) + mvm-backend
      test locks (host-gated)
  [x] Phase 3 (naming/typed-selectors) COMPLETE — Task 4 + Task 5 merged:
      • Task 4 renames: `storage::Backend` → `DeviceMapperBackend` (#892, models
        dmsetup thin-pool ops; also fixed a missed mvm-cli call site) and the two
        collided `EgressProxy` traits split by layer — runtime `VmEgressProxy` +
        supervisor `SupervisorEgressProxy` (#894, 773 supervisor tests pass).
      • Task 5 typed selectors: exposed `AnyBackend::kind()` `pub` and migrated
        pool.rs `name() == "vz"` → `kind() == BackendKind::Vz`, dropping the
        duplicated `"vz"||"virtualization"` alias literal the descriptor registry
        already owns (#895). The typed foundation (BackendKind + catalog registry)
        was already in place from Plan 184; network/storage `kind()` strings are a
        deliberate open-registry extension point, left as-is. Deferred follow-up
        (logged in the plan): the `&dyn VmBackend → &AnyBackend` signature ripple
        for the `kernel_identity`/`image_identity` sites in the hot pool.rs.
  [~] Phase 5 Task 8 (unsafe SAFETY invariants) — first pass: the simple-syscall
      mvm-guest files (entrypoint/volume/exec_stream/process_rpc/netinit/worker_pool,
      12 blocks) now carry a per-block `SAFETY:` naming the ownership/async-signal-
      safety/POD invariant; verified host + `aarch64-unknown-linux-musl` clippy.
      Deferred (logged in plan): the deeper clusters — console.rs PTY/termios (~16),
      mvm-verity-init dm-verity ioctls (~13), guest-agent (~5), and vz_objc.rs
      objc2 FFI (~100, do while Plan-152 vz is quiet).
  [x] Phase 5 Task 9 (feature/dep boundaries) — DONE by verification (no code
      change): `test-support` is dev-only across all 6 consumers + empty feature
      def; optional heavy stacks (egress-ca/hostd-transport/manifest-verify/
      schemars/attestation-*) are `dep:`-gated + documented inline; `cargo tree
      -p mvm-core -e no-dev` is tokio-free (with or without test-support) and the
      `check-core-runtime-free` Lint gate enforces it.
  [ ] Phase 4+ remain: function shape (Task 6/7), error shapes/fixtures/docs
      (Task 10-13), closeout (Task 14); Task 8 deeper unsafe clusters
      (console/verity/objc2) deferred — see plan follow-ups
  [ ] Audit long constructors, params structs, builders, and large functions
      only where the split adds testable structure
  [ ] Audit unsafe/platform/feature boundaries, standardize error shapes,
      consolidate repeated fixtures, check secret/debug exposure, and add
      Rustdoc verification to closeout

PLAN 170 — Host lifecycle convergence           ✅ mvm-side done (density → mvmd)
  [x] WS-A reconcile-on-entry — PR #688 (merged)
  [~] WS-B idle-reaper mechanism — PR #696 (merged, no consumer)
  [~] WS-C pressure reaper — PR #701 (closed unmerged)
  [~] WS-D wake-on-request — owned by mvmd
  (WS-B/C/D density belongs to mvmd, not mvm — see plan-170 banner)

PLAN 123 — Network / storage / warm-start        ✅ DONE — A/B/C1/C3/C4 done; C2 → Plan 175
  [x] Phase A claims-gated lift (A1/L1, A2, A3, A4, L3-A)
  [x] A2/A4 per-tenant enforce: libkrun PlanFlowPolicy deny-by-default
      (mirrors FC install_default_deny) + per-tenant DnsSinkholeScan
  [x] L3 slice B — workload site honors MVM_NETWORKING (#664)
  [x] L2 microvm_nix egress — DECIDED: QEMU is mvm-only dev/test (Tier 2),
      no enforcement; option (a) VmStartConfig plumbing deferred to a future
      promotion. Documented in ADR-002 + CLAUDE.md.
  [x] Phase B StorageProvider local/encrypted(macOS)/CAS/snapshot + MountProvider+S3
  [x] Phase B Linux LUKS2 arm (#729, live-verified on Linux VM) + S3 coverage
      S3-free (#732: from_s3_config validation + LocalFileSystem sync)
  [x] Phase C PostRestore host sender (#734) — the warm-start prerequisite
  [x] C1 SnapshotCapability enum + per-backend disposition
  [x] C4 warm-start operation seam: typed WarmStartError (ADR-053 hint) +
      SnapshotCapability::{label,satisfies} + fail-closed VmBackend::warm_start
      default; libkrun disk-only (SnapshotUpper clone of golden rootfs);
      doctor warm-start matrix + Linux NBD/HugeTLB substrate probe
  [~] C2 Firecracker live-memory fast-resume — CARVED to Plan 175 (live-KVM-gated; not a Plan 123 box)
  [x] C3 Vz save/restore (macOS 26+) — MET via Plan 159 WS-2 `vm_full`
      save/restore (`saveMachineStateToURL`/`restoreMachineStateFromURL`,
      #770): live-proven incl. responsive control plane on the restored VM,
      gvproxy re-spawn on restore, and restore-while-running refusal. The
      "owned by Plan 152 WS-C" pointer is resolved — WS-C itself is satisfied
      (see PLAN 152 block).

PLAN 182 — Trait hygiene + backend catalog      ✅ DONE
  [x] shared `mvm_core::time::{Clock,SystemClock}` replaces the three local copies
  [x] duplicate `KeyProvider` retired in favor of `mvm_core::crypto::keystore`
  [x] backend metadata catalog becomes the single source for `AnyBackend` selectors
      and `mvmctl doctor` backend support maps
  [x] macro scope stays narrow: land `backend_catalog!`, reject broader trait-impl/noop macros
  [x] architecture docs now describe the current trait seams and ownership rules
  [x] literal `cargo test --workspace` aggregate — closed as documented-environmental:
      package-by-package + `-E 'not package(mvm-backend)'` are green; the single-invocation
      aggregate only SIGKILLs the `mvm-backend` unit-test bin via macOS amfid codesign on
      this host (not an assertion failure), and CI runs the full aggregate green

PLAN 175 — Firecracker live-memory warm-start    🔴 NOT STARTED (live-KVM-gated; Plan 123 C2 carve-out)
  [ ] C4 warm-start CLI/RPC wiring — carved out → Plan 175 (rides C2)
  [ ] T1 VMGenID delivery on PostRestore (token payload + GenIdReseeder dispatch)
  [ ] T2 UFFD/NBD/hugepages fast-resume substrate (diff snapshot + lazy paging)
  [ ] T3 SIGUSR1 "primed" ready-barrier for a deterministic warm base
  [ ] T4 FirecrackerBackend::warm_start override + mvmctl verb + agent_ping e2e
  (Vz=152 WS-C; libkrun disk-only done #741; reflink clone = 123 C4 follow-up)

PLAN 126 — Dependency reduction                 🟡 ~25%
  [x] A1 re-baseline
  [x] B5 drop tokio from mvm-core (PR-1)
  [x] B2 opendal → object_store (mvm template registry); opendal GONE,
      lockfile 689→678 (−11)
  [ ] B1 sigstore — already off default; needs cross-repo mvmd decision (relocate cosign-verify)
  [ ] B3 pgp (168) — SUPERSEDED by plan 160 (drop Alpine seed); security decision
  [ ] B4 aws-lc-rs → ring — BLOCKED upstream (oci-client hardcodes aws-lc; needs a fork)
  [~] C1 reqwest unify — REJECTED/blocked on B4 (0.13 forces aws-lc + transitive 0.12 holdout; no tree collapse)
  [x] D2 duplicate-major lock-gate — cargo-deny multiple-versions=deny + 23-crate baseline (ratchet); also
      un-broke the red cargo-deny/cargo-audit jobs: wildcard-paths, mvm-verify license, 2 unmaintained ignores,
      and FIXED RUSTSEC-2026-0119 (hickory-proto DoS) by bumping hickory-resolver 0.24→0.26 (collapsed its dup)
  [ ] D1 forbidden-dep gate (check-forbidden-deps extension) — still open

PLAN 153 — CLI directory split                  ✅ DONE (subsumed into Plan 178)
  [x] image.rs → image/ ; catalog.rs → catalog/ (last two flat files)

PLAN 177 — Backend consolidation (8→4)           ✅ DONE — both phases merged; 4 backends + mock; one vz AVF path. DX-parity → Plan 189. Lone caveat = host-gated macOS-26 hardware smoke (validation of merged code)  (ADR-076)
  [x] Phase 1 delete docker (+ dead Tier-3 banner subsystem)
  [x] Phase 1 delete cloud_hypervisor (+ ch_runtime, ch-bootcheck)
  [x] Phase 1 fold microvm_nix → qemu
  [x] Phase 1 prune dead CI lane + Justfile setup recipe
  [x] Phase 1 verify: doctor lists {firecracker,libkrun,vz,qemu,apple-container,mock};
      4837/4837 workspace tests (excl mvm-backend SIGKILL bin); clippy/fmt clean
  [x] Phase 2 — AVF convergence onto supervisor vz — MERGED #806:
      apple_container backend + providers/ deleted; AnyBackend converted; macOS-26
      default→vz; CoW per-instance rootfs ported (#789); console/transport/codesign/
      port-proxy relocated; `mvmctl dev` + `up -d` converged onto VzPersistentBuilderVm
      (detached supervisor outlives CLI, `dev down` reaps by PID file — no launchd);
      `has_apple_containers`→`is_vz_default_tier`; all `"apple-container"` selectors
      collapsed to vz; backend.rs tests repointed; ADR-002 tier matrix pruned
      (docker/CH/apple-container rows dropped, microvm.nix→QEMU); CLAUDE.md updated.
  [x] Cosmetic rename slice — env module `apple_container.rs`, `AppleContainerEnv`,
      `MicrovmBackend::AppleContainer`, and the objc2 `mvm_apple_container_*` cdecl
      symbols deleted (#814 + #817).
  [x] Trailing dead `VsockProxyTransport` removed (zero callers post-convergence).
  [~] Lone caveat: live macOS-26 vz `dev up`/`up` hardware smoke — host-gated
      validation of already-merged code (vz boot path already exercised by Plan 152
      parity gate + Plan 159 workload-liveness); not a blocker for DONE.

PLAN 189 — VZ DX parity (post-convergence)        🟡 in progress  (ADR-076 §"Out of scope")
  Spun out of Plan 177's deferred DX-parity follow-on; sibling of Plan 159 (owns
  only the additive parity slice, cross-refs 159/140/148 for primitives).
  [x] WS-3: `dev status/down/up --json` (versioned, privacy-safe; all dispatch
      arms; lifecycle handlers return outcome; up forces chrome→stderr +
      conflicts_with shell; serde + CLI-parse + conflict tests)
  [ ] WS-3 remaining: snapshot/checkpoint --json, linux-native richer detail
  [ ] WS-1 save/restore verbs · WS-2 cached fast-boot default · WS-4 base pinning
  [ ] WS-1 surface save/restore verbs (gated by snapshot_capability tier)
  [~] WS-2 cached fast-boot default — who-calls audit DONE: surface already fast-boot-default (dev-image + builder-VM fingerprint fast-path, persistent-VM reuse, up cache-hit-only); Plan 195 fixed the builder-VM churn. Only remaining: live macOS-26 acceptance (converges w/ Plan 195 validation)
  [ ] WS-3 --json coverage across vz lifecycle verbs
  [ ] WS-4 base pinning (reuse artifact/template machinery, no parallel registry)

PLAN 178 — CLI surface consolidation (~56→~28)   ✅ DONE (dir-purity deferred)  (ADR-077)
  [x] lock tree (D1–D6) + hide internal subprocess commands
  [x] vm group (14 single-VM verbs)
  [x] ops group (metrics/bench/config/mcp)
  [x] build group (image/compile/validate/kernel; kernel.rs→build/)
  [x] env group (bootstrap/cleanup/uninstall/update/sign)
  [x] trust group (attest/receipt/audit folded into publisher trust)
  [x] image.rs/catalog.rs dir split (Plan 153)
  [x] docs: cli-commands.md + CLAUDE.md grouped forms
  [x] run-family merge (Task 7): exec→run (run was a strict superset via
      RunArgs::into_exec_args); `up` + `invoke` kept distinct (admission /
      no-shell entrypoint). `run --profile dev` covers exec.
  NOTE: audit taxonomy preserved across all groups (vm pause→cmd.pause,
  trust audit→cmd.audit, …) so claims 8/12/13 event names unchanged.
  Deferred dir-purity: dev/doctor/init modules still live in env/.

PLAN 180 — Strip spec refs from code comments    ✅ DONE
  [x] worklist + canonical detection regex (494 files / ~3,097 line-hits baseline)
  [x] pilot batch (7 heaviest files)
  [x] fan-out sweep — comment-only; ~1,000+ citations removed across ~280 files
      (string literals / wire data / `claim N` security-property names kept)
  [x] verify comment-only diff + workspace build green
  [x] check-no-spec-refs-in-comments lint gate (string-aware: skips raw
      strings; exempts the two self-referential lint files) wired into the
      Lint CI job

PLAN 181 — App-builder product surface           🔴 NOT STARTED  (ADR-079; mvm primitive ↔ mvmd product per ADR-070)
  [ ] WS-A preview ingress: published-ports model (signed in plan) + per-port
      routing label at gateway seam + wake-on-access VmBackend hook + local
      single-machine dev ingress (s-<id>-<port>.preview.localhost)
  [ ] WS-B lifecycle verbs: vm stop (free RAM, wake-on-access) / rm (keep
      workspace) / purge (delete workspace) / keepalive (extend idle TTL);
      workspace-data lifecycle in mvm_core::config; distinct cmd.* audit events
  [ ] WS-C task/files protocol: async streamable task over agent-RPC (169) reusing
      ExecEvent (172) + SSE-ready event shape + Files API parity on fs RPC + thin
      mvmctl verbs (agent-agnostic; mvmd owns HTTP/SSE transport)
  [ ] WS-D install DX: curl|sh installer (folds Plan 159 WS-5 D) + "next steps"
      output (endpoint + preview URLs + runnable cmds) + graduated env uninstall
      (--images/--data/--all; keep-workspaces default)
  NOTE: deliberately rejects the sibling app-builder's isolation model — no Docker
  socket, no host-path mounts into a workload, no auth-off/caps-off defaults, no
  baked-in agents, no multi-tenant HTTP/auth in mvm (mvmd per ADR-070 §5/Plan 33).

PLAN 188 — Capability projection seam (ADR-080 P5)  ✅ LANDED (#801) — was numbered 184 pre-merge; renumbered when main claimed 184
  [x] Proto + CanonicalRule atom (projection seam module created)
  [x] CanonicalEgress decision set with unconditional mandatory-deny
  [x] canonicalize_effective — L4 rules leg
  [x] canonicalize_effective — allow-list / DNS-pin leg
  [x] mandatory-deny overlap refusal at projection time (incl. rebinding fixture)
  [x] to_wasi_grants + wasi_allows — hostname-keyed WASI projection (separate walk)
  [x] clamp — intersection-only merge (requests attenuate, never widen)
  [x] cross-projection consistency + clamp-never-widens property witnesses
      (ADR-080 §8 P5 witness names: cross_projection_consistency_property,
       clamp_never_widens_property, rebinding_pin_into_metadata_range_refuses)
  [x] pub use re-exports from mvm-core::policy; ADR-080 P5 row updated
  [x] kernel-side wiring: canonicalize_l4 + CanonicalEgress::permits replace LiveL4Gate — LANDED (Plan 190)
  [ ] WASI-context mapping: WasiEgress → WasiCtxBuilder in the wasmtime runner — deferred
  NOTE: 41 tests (39 unit + 2 property witnesses), mutation-verified. No new dependencies.

PLAN 186 — Trace hardening (ADR-080 P1/P3/P4 + hardened P2 pin)  ✅ LANDED (#809)
  [x] P1: MAX_RECORDED_OPS (1024) + 8 MiB FilesWrite cap + DuplicateFilesWritePath refusal
  [x] P1: fuzz_runtime_recording harness in security.yml (crates/mvm-sdk/fuzz)
  [x] P2 (interim, HARDENED): the b64-alphabet pin caught a LIVE shell-injection in the
      FilesWrite→HookCmd::Shell lowering; fixed by base64-encoding the path too (was
      single-quote-interpolated); verified injection-safe by executing hooks vs /bin/sh
  [x] P3: recording_sha256_hex + verify_recording_digest + --recording-sha256; 64 MiB byte cap
  [x] P4: Divergence vocabulary + require_acknowledged gate on `run --mode plan` (--ack-divergence)
  [ ] P2 full (declarative IR file-materialization field, replacing the shell hook) — own plan
  NOTE: P2-full / P6 / P8 remain open in the ADR-080 §8 ledger.

PLAN 187 — Secret-scan admission gate (ADR-080 P7)  ✅ LANDED (#811)
  [x] scan_recording_for_secrets — env literals + argv + DECODED FilesWrite payloads (Plan 129 SecretsScanner)
  [x] refuse_embedded_secrets — HARD-refuses `run --mode plan` admission (not acknowledgeable; fix = SecretRef)
  [x] SecretRef values skipped (Sigv4Params.access_key_id = public AKIA half, correctly not flagged); compile warns
  [ ] paste-time detector — deferred with the browser preview tier

PLAN 190 — Kernel egress decision converges on CanonicalEgress (ADR-080 P5 close-out)  🟢 LANDED
  [x] canonicalize_l4 — lenient L4 lowering (no mandatory-deny-overlap refusal; runtime
      permits() + MandatoryDenyEgressScan enforce it; malformed-input refusals only)
  [x] L4PolicyScan holds CanonicalEgress, decides via CanonicalEgress::permits
  [x] build_egress_scan takes Option<CanonicalEgress>; gateway bridge builds via canonicalize_l4
  [x] L4Policy/L4Rule/L4Decision/LiveL4Gate/L4SpecError duplicate deleted from proxy/l4.rs
  [x] claim-10 witnesses migrated (same names, same assertions, zero behaviour change)
  [x] equivalence witness: kernel_egress_canonical_permits_agrees_with_hand_written_oracle
  [ ] WASI-context mapping (WasiEgress → WasiCtxBuilder) — deferred to runner plan

PLAN 191 — Declarative file materialization (ADR-080 P2-full)  🟢 LANDED
  [x] App.files IR field (MaterializedFile: path + base64 content)
  [x] FilesWrite lowers to App.files (no before_start shell hook)
  [x] mkFunctionService extraFiles bakes App.files into the rootfs at build time
      (base64 decoded at build; reserved /etc/mvm/* paths take precedence)
  [x] ADR-080 §8 P2 row + §2 prose updated to build-time bake, no shell

PLAN 192 — WASI capability projection (fs/env, ADR-081 A1)  ✅ LANDED
  [x] CanonicalFs preopen grants + segment-boundary `permits` (sibling != ancestor)
  [x] canonicalize_fs lowering — traversal/non-absolute/bad-access refusal + rw-supersedes merge
  [x] CanonicalEnv name-level projection + canonicalize_env (malformed-name refusal)
  [x] clamp_fs/clamp_env intersection-only merges (a request attenuates, never widens)
  [x] WASI preopen/env-name generator + denied-not-preopened negative witness
  [x] WasiCapPolicy bound on EffectivePolicy/PolicyBundle/TenantOverlay (deny-by-default)
  [x] clamp_fs_never_widens + clamp_env_never_widens property witnesses (512 iters each)
  [x] gate green: 1248 mvm-core tests, clippy -D warnings, fmt, check-core-runtime-free; zero new deps
  NOTE: A2 (`.wasm` admission, claim 8/9 provenance) + A3 (guest runner + Nix bake + AOT,
  consumes WasiPreopen/env-name output) are the remaining ADR-081 legs — their own plans.

PLAN 193 — rvproxy network substrate (replace gvproxy/passt)  🟡 WS-1 proven; WS-2.2d mvm-side landed (#1009); cross-repo
  Replace the external gvproxy (macOS libkrun-unixgram + Vz vfkit) + passt (Linux FC) gateways
  with the sibling-repo Rust-native `rvproxy` daemon (typed control API + native flow/audit
  pipeline). Three problems it removes: (1) BIGGEST — claim-10 egress + Plan 129 substitution +
  Plan 141 packet-observer currently WRAP the datapath in-line (splice + etherparse, per-backend)
  because gvproxy/passt have no native flow API; rvproxy exposes flow decisions/audit natively →
  collapses gateway_bridge.rs's PlanFlowPolicy into a contract. (2) gvproxy(macOS)/passt(Linux)
  divergence → one substrate. (3) Tracked bug: gvproxy logs ERROR-level "use of closed network
  connection / gvproxy exiting" on every one-shot builder-VM poweroff (benign, unfixable in the
  gvproxy model — VM self-exits before SIGTERM lands). Requirements authored into the rvproxy repo
  at specs/plans/014-mvm-adoption-requirements.md. Gated on WS-1: rvproxy confirming the
  libkrun-unixgram transport (mvm's default macOS backend). Not-a-fix findings recorded in the
  plan (gvproxy has no log-level flag; nix-seed already cached for normal use; build slowness is
  the base-VM fingerprint churn, a separate change).
  NEW REQUIREMENT (Plan 197 Phase 2b): rvproxy must add transparent :80/:443 interception → a host
  terminator port (the macOS analogue of FC's nft PREROUTING REDIRECT) so egress secret substitution's
  transparent half works on libkrun/vz — macOS has no nft and the in-process bridge sees only
  post-gateway frames, so this can only live in the gateway. Add to rvproxy's mvm-adoption requirements.
  Plan: specs/plans/193-rvproxy-network-substrate.md
  WS-2.2d (mvm-side, #1009): native rvproxy audit feed + native-enforcement parity, no splice.
    - tasks 1+2a (audit feed + deny-by-default witness) proven live on libkrun; the follower tails
      rvproxy's flow-audit JSONL into the chain-signed signer_task, emitting gateway.flow_* entries.
    - task 2b (this change): native allow/deny matrix witness. One [policy] with an L4 allow rule
      for a public /24 + deny-by-default, probed twice (rvproxy accepts one vfkit connection per
      spawn and reliably processes only the first post-handshake frame, so each dst gets its own
      spawn): unlisted dst denied for l4_allowlist_miss (proves the rendered allow-list is active),
      listed dst not denied (proves admission). Both witnesses share native_first_frame_probe; gated
      MVM_GATEWAY_NATIVE_E2E + MVM_GATEWAY_BIN. Parity gate step [2/4] runs the whole rvproxy_native
      family. All four gate arms green; both witnesses 5/5.
    - remaining: delete the splice + Plan-141 on_packet hooks, then flip MVM_GATEWAY_BRIDGE default-on
      (gated on the parity gate being green by default).

PLAN 197 — WorkloadBackend type-bar (core security features non-skippable)  ✅ mvm-side DONE (Phase 1 + 2a); 2b → Plan 193/rvproxy
  Arose from the Sprint 55 vz closeout: egress secret substitution (Plan 129) silently never
  reached libkrun/vz because it was a free function called ad-hoc in per-backend start paths.
  Fix is structural, not a capability matrix (rejected — documents holes, doesn't prevent them).
  Two moves:
  [x] Phase 1 — type-bar the funnel (no behavior change): `WorkloadBackend: VmBackend` marker; impl
      for FC/libkrun/vz + mock (mock = ADR-045 hermetic test double, carries no real workload);
      `AnyBackend::as_workload_backend` (exhaustive) + `require_workload_backend` guard wired into all
      three admitted up.rs launch arms so QEMU (a real dev/test VMM) is TYPE-BARRED from the
      untrusted-workload path (ADR-002 Tier-2 carve-out is now a type constraint — ADR-083 + ADR-002
      cross-ref). BackendSecurityProfile kept advisory. Spec+quality reviewed; CI Test lane caught that
      barring mock broke the ADR-045 hermetic lifecycle tests → mock permitted; workspace build/clippy/
      nightly-fmt green. MERGED #860 (code+ADR) / #861 (docs closeout+plan). (Landed against up.rs
      without a Plan 189 collision — that PR had not touched up.rs.)
  [x] Phase 2 design spike DONE: terminator → rvproxy (not gvproxy/standalone). Phase 2 SPLIT into:
  [x] 2a (mvm-side): register SUBSTITUTION_PORT 5253 on libkrun+vz supervisors; add no-default
      `egress_substitution_transport()` seam (FC=nft/TCP terminator, macOS=Uds vsock-5253 channel); lift
      spawn_substitution_endpoint into the funnel. Delivers explicit-HTTP_PROXY substitution on macOS.
      MERGED #866. Default-path plan-persist gap fixed #909: the endpoint reads `<state_dir>/plan.json`
      inside `start()`, but the CLI persisted it pre-start only for firecracker — so on a plain
      `up`/`invoke --hypervisor vz`/`libkrun` it silently no-opped without `MVM_GATEWAY_BRIDGE=1`. Now
      gated by `persists_plan_before_start(hyp) = matches!(hyp,"firecracker"|"vz"|"libkrun")` on both the
      `up` (up.rs) and `invoke`/`run` (invoke.rs admit-closure) launch arms; QEMU stays excluded
      (in-memory config). DATA PLANE PROVEN LIVE on vz (macOS-26, 2026-06-15): the 5252 early-boot race
      is sidestepped by `up --name N --hypervisor vz -d` → `vm wait N --for all` → `invoke N --attach`
      (RunEntrypoint into the running VM, injecting the boot-minted HTTP_PROXY + placeholder env; no
      `vm proc`, claims 4/15 intact). httpbin reflected the real Bearer credential while the guest held
      only `mvm-secret-…` (claim 13); a non-allowed host (`example.com`) was refused by the endpoint
      (claim 12); 6 guest→host dials across 2 invokes confirmed the 5253 `VZVirtioSocketListener` keeps
      accepting (the one-shot `if let Some(rx.recv())` is only on exit port 5251; the 5253 proxy loops with
      a re-arming delegate) — no supervisor bug, pure verification. Phase 2a COMPLETE on vz.
  [~] 2b (REHOMED to Plan 193/rvproxy, cross-repo): transparent :80/:443 terminator must live in rvproxy (no nft on
      macOS; the in-process bridge sees only post-gateway frames). Add to rvproxy's mvm-adoption
      requirements (Plan 193 / ADR-082); gated on the rvproxy migration.
  Design + spike output + bite-sized plan: specs/plans/197-workload-backend-core-trait.md

PLAN 199 — Host runtime packaging + crate boundaries  🟡 native VMM recipes remain
  Plan: specs/plans/199-host-runtime-packaging-and-crate-boundaries.md
  [x] Add optional source-built Nix host package for `mvmctl` without changing the Linux-only
      `mkGuest` image API.
  [x] Expose source-built `packages.<system>.mvmctl`, default package, and overlay package.
  [x] Test that source-checkout Nix packages do not fetch project release binaries.
  [x] Keep native VMM linkage explicit/opt-in in Nix packaging tests.
  [x] Document binary install as the primary user path and host Nix as optional.
  [ ] Add native VMM Nix recipes without making native linkage a default hidden dependency.
      Decision: use the useful external-prior-art overlay shape — pinned, source-built `libkrunfw`
      and `libkrun` packages exposed through the host overlay — but keep them builder-VM-verified.
  [x] Decide against an external-prior-art-style release-tarball Nix package for now: source-built
      `packages.<system>.mvmctl` is the Nix path; signed binary install is handled by `binaryNativeCode`.
  [x] Add release artifact matrix/signature CI.
  [x] Audit crate boundaries against default binary closure and security isolation goals.

PLAN 200 — Machine UX/DX layer  🟢 in progress — `machine run` shipped (#968) + WS-B `--net`/`--allow-host` egress enforcement MERGED (#1003)
  Plan: specs/plans/200-machine-ux-dx-layer.md
  This plan captures the full session learning set and the de-duplication decision:
  Plans 199/200 are the priority product path; older plans feed primitives into them
  rather than creating competing beginner surfaces. Binary-first install, no host-Nix
  prerequisite for normal use, image-backed one-shot UX, persistent named machines, strict
  `mvm.toml` schema v1, local image inputs, scenario-led docs with explicit
  limitations, verified portable artifacts, measured hot-start claims, managed
  macOS virtualization as the safer default, custom kernels as signed runtime/artifact
  payloads, SDKs that mirror the CLI without bypassing admission/audit, and dependency weight as a default-binary-closure
  DX/security goal.
  [x] Record reference-UX lessons without copying external names or implementation details.
  [x] Record that `machine run/create/start/exec/shell/stop/pack` is the beginner command group.
  [x] Record that `image` and `flake` are mutually exclusive source selectors in schema v1.
  [x] Record security defaults: network off, allow-host narrowing, SSH-agent socket forwarding
      only, dev init rejected for sealed/prod, read-only volumes by default, unknown keys
      rejected, effective policy visible in admission/audit/receipts, portable artifacts
      verify before launch and still pass admission.
  [x] Record performance posture: <200 ms can only be claimed for scoped cached hot paths after
      phase measurement; first pull/build is a separate product message.
  [x] Record dependency posture: default binary closure matters more than crate count; reduce
      duplicate OCI/TLS/native-crypto stacks, split dev/build/backend extras, replace heavy
      test fixtures, audit CLI UI deps, freeze native bindings, and preserve security deps.
  [x] Record final DX lessons: local image sources (registry refs, local OCI archives,
      stdin archive streams, unpacked rootfs directories) must share hardened extraction,
      provenance, admission, receipts, and audit; beginner docs are scenario-led; limitations
      are explicit; SDK wrappers prove CLI/admission parity and non-bypass; portable artifacts
      have a pack/verify/inspect/run/transfer/cleanup loop.
  [x] Add priority/de-duplication map: Plan 199 owns install/host packaging; Plan 200 owns
      beginner machine UX; Plan 125/114 feed SDK primitives; Plan 126/156 own dependency and
      size mechanics; Plan 155/136 feed portable-artifact internals; Plan 159/189 stay
      VZ-specific; Plan 193/197 stay security substrate; Plan 198 is completed perf input.
  [~] Implement `mvmctl machine` parser and command aliases over existing runtime primitives.
      `machine run` shipped (commands/machine/, translates into run_secure, deny-all egress
      preserved); create/start/exec/shell/stop/ls/inspect/rm + `--net`/`--allow-host` pending.
  [x] Make `run --image <oci>` boot end-to-end (Session 3 item 1). Cross-compile the guest
      agent+netinit to static musl and inject them + an overlay-preferring `/init` +
      `/mvm/runtime` into the OCI rootfs at materialize (`mvm_build::guest_agent_build` +
      `oci_runtime_inject`); honest `GuestSidecar::for_oci_run` passes `admit_overlay_aware`
      (overlay-attach is FC-only, so macOS bakes the agent). Fixed the vz virtio-blk ext4
      bad-geometry boot panic (1 MiB mkfs margin). Live-verified macOS-26/vz: alpine boots,
      agent answers vsock 5252, runs the command, streams output (exit 0). Smoke test drives
      the real CLI (gate + agent round-trip). Deferred: rootfs-dir inject, end-user agent
      source via overlay download, uid-901 setpriv hardening — see plan doc.
  [x] Implement transient network policy plumbing for image-backed runs.
  [x] Implement local image-source handling for registry refs, local OCI archive files,
      stdin archive streams, and unpacked rootfs directories with traversal, malformed archive,
      wrong-architecture, and missing-provenance negative tests.
  [ ] Implement persistent OCI-backed machine specs under existing data-dir helpers.
  [ ] Implement schema-v1 parser/tests with unknown-key and `image`/`flake` conflict rejection.
  [ ] Implement SDK parity for Python, TypeScript, and Rust, including non-bypass tests for
      admission, artifact verification, default-deny network, unknown keys, source conflicts,
      and receipt/audit summaries.
  [ ] Implement scenario-led machine docs plus limitations docs and source guards that prevent
      host-Nix, GPU, ICMP, or unsupported-architecture overclaims.
  [ ] Implement product-level portable artifact pack/verify/inspect/run/transfer/cleanup docs
      and tamper, wrong-key, wrong-architecture, traversal, unknown-version, and missing-verity
      tests.
  [ ] Add default-closure, duplicate-major, forbidden-heavy-dep, and binary-size CI budgets.
  WS-B post-merge deferred-list closeout (post-#1003):
  [x] Emit plan.launched/plan.failed on the transient-run path — #1013 (AdmissionContext
      stashed in a cell + reuse up::emit_launched_if/emit_failed_if).
  [x] Route MCP code-run (cold + warm) through admission so deny-all is enforced on the
      libkrun/Vz bridge — #1017 (cold) + #1023 (warm); FC already enforced via nftables.
  [x] Remove the vestigial BridgeConfig.policy field + the AllowAll type (run_bridge_inner
      no longer reads it; flow gate derives from bundle/network_policy, fails closed) — #1019;
      field + AllowAll FlowPolicy impl dropped, 4 supervisor-bin sites updated, tests use
      PlanFlowPolicy::from_network_policy(unrestricted) for allow-mode; cfg(linux)
      firecracker-bridge cross-compiled with cargo-zigbuild.
  [~] Superseded multi-PR #1014 closed — every commit landed elsewhere (OCI→#1010,
      #1→#1013, #2→#1017, #3→#1019); duplicate #1016 closed too.
  WS-B deferred items — ALL MERGED (uniform-egress session):
  [x] Uniform host:port L4 egress on the libkrun/Vz bare path — #1029 (admission-time DNS pin →
      canonicalize_network_policy → L4PolicyScan drops direct-IP/wrong-port dials; uniform with FC;
      receipt tier collapsed to <backend>:l4-host-port; UDP/53-only carve-out, adversarial-reviewed).
  [x] DHCP/ARP posture under deny-all — #1030 (decided loopback-only, NO carve-out; deny-all drops
      DHCP, guest self-assigns static gvproxy fallback; ARP/IPv6-ND are L2, forwarded; ADR-002 §"Deny-all
      control-plane posture", pinned by bare_deny_all_drops_dhcp_discover_through_the_live_bridge).
  [x] macOS transient-guest eth0 bring-up — #1020 (shared mvm-guest::guest_net) + #1031 (live-validated:
      examples/egress-probe boots on libkrun, verdict-0 egress reach). Open follow-up filed: up
      --network-allow doesn't enforce egress on the libkrun direct-boot path (up.rs VmStartConfig
      never sets .network_policy; the transient run path does) — pre-existing, not the WS-B work.

PLAN 202 — Host services daemon (per-tenant, not per-VM spawn)   🟡 IN PROGRESS (ADR-084, #977)
  Supersedes the Plan 125 E5.3b per-VM subprocess fork. Wire protocol unchanged.
  [x] ADR-084 + Plan 202 written (per-tenant daemon model; revises ADR-059).
  [x] Phase 1 kickoff prompt (plans/host-services-daemon-phase-1-kickoff.md).
  [ ] ADR-084 reviewed + accepted.
  [x] Phase 1 — broker daemon + host-signed Register/Deregister control plane + dynamic
      per-VM socket binding + server-derived vm_id; spawn_broker fork → ensure_daemon/register_vm.
  [ ] Phase 2 — audit-signer daemon (2a helper core + 2b forwarding + 2c helper-backed
      admission signing landed; 2d persisted-head restart remains).
  [ ] Phase 3 — decouple availability from MVM_GATEWAY_BRIDGE (3a default-on + 3c doctor
      daemon-state reporting landed; cost framing + vz live-verify remain).
  [ ] Phase 4 — supervision + crash/restart journal.
  [ ] Phase 5 — mvmd host agent owns the daemon per tenant (mvmd Plan 52).
  [ ] Phase 6 — retire spawn_broker_services_if_admitted; note ADR-059 superseded.
```

## Security claims

15/15 shipped, none regressed, + 1 `Preview` (claim 16, egress-substitution
leak-gate — witnesses machine-checked, ADR-002 promotion pending) (`specs/claims/catalog.md`,
gated by `xtask check-claim-catalog`).

## Sequencing note — 2026-06-17

Why the 11 open rollup boxes still show as open:

- `REFACTOR-STATUS.md` only ticks a plan when the whole plan is done. Partial progress is recorded in the long `Last updated` history and detail blocks, so progress is easy to miss.
- There is visible drift to clean up: Plan 126's summary says the forbidden-dep gate landed, but its detail section still has D1 unchecked.
- The Plan 125 closeout + Plan 200 checklist reconciliation are staged in PR #1047 and are not on `main` until that PR merges.

Open PRs at update time:

- `#1047` / `docs/plan-200-implementation-checklist`: carries the Plan 200 implementation checklist, MCP-admission bookkeeping reconciliation, and Plan 125 close/rehome rollup.
- `#1039` / `feat/plan-200-image-source-closeout`: merged.
- `#1041` / `docs/adr-bundle-posture`: merged.

Recommended sequence to close the remaining rollup items:

1. Merge `#1047` after post-rebase checks pass so the Plan 125 closeout and Plan 200 checklist reconciliation reach `main`.
2. Clean stale worktrees: several are old/behind or already landed (`mvm-202-3c-doctor`, `mvm-pr1009`, `mvm-p200-ociboot`, old status/170/vz100 branches). Do not sequence new work from them.
3. Finish Plan 202 next: Phase 2d restart/head rebuild unlocks the host-services model.
4. **Done:** Plan 125 is closed/rehome-only; remaining per-tenant daemon work belongs to Plan 202.
5. Continue Plan 200 product path: local image sources, persistent OCI-backed machine specs, schema parser, SDK parity, docs, CI budgets.
6. Do Plan 199 in parallel if builder VM time is available: native `libkrunfw`/`libkrun` Nix recipes and flake/build verification.
7. Do Plan 195 before Plan 189 acceptance: fingerprint narrowing reduces builder churn and supports cached fast-boot validation.
8. Continue Plan 193 only after rvproxy cross-repo slices are ready: delete splice, remove Plan-141 hooks, default-on bridge, transparent terminator.
9. Then Plan 189 VZ DX parity: save/restore verbs, JSON coverage, base pinning.
10. Resolve Plan 126 by correcting status first, then decide blocked deps (`sigstore`, `pgp`, `aws-lc-rs`) rather than treating them as normal TODOs.
11. Plan 118/175 are live-KVM gated; do density bench substrate first, then FC standby/warm-start once the KVM environment is ready.
12. Plan 159 and 201 are lowest priority: Plan 159 mostly needs residuals rehomed/descope, and Plan 201 is a convenience layer after warm-pool fundamentals.

Plan 200 implementation checklist after `#1039`:

- [x] Reconcile Plan 200 bookkeeping first: the rollup says MCP code-run admission is done via `#1017`/`#1023`, but the Plan 200 deferred checkbox still shows it open. Completed here: the Plan 200 deferred checkbox now points at #1017/#1023 and is ticked.
- [ ] Persistent machine UX: implement `machine create/start/exec/shell/stop/ls/inspect/rm`, persist `MachineSpec` under the existing data-dir helpers with atomic writes, and add state deletion/JSON tests.
- [ ] `mvm.toml` machine mapping: map `net`, `[network].allow_hosts`, `[auth].ssh_agent`, `[dev].init`, and volumes into the admitted machine path; preserve read-only volume defaults; reject dev init for sealed/prod; include effective policy in dry-run/receipt output.
- [ ] SDK parity: add Python, TypeScript, and Rust machine wrappers that reuse CLI/library admission paths; add parity tests and negative non-bypass tests for artifact verification, default-deny network, unknown keys, source conflicts, and receipt/audit summaries.
- [ ] Scenario-led docs: update binary-install-first docs, machine quickstart, limitations, old-verb mapping, source guards, completions, and first-run output without implying host Nix, GPU, ICMP, or unsupported architecture support.
- [ ] Portable artifacts: implement `machine pack`, `machine run <artifact>`, verify/extract/run docs, and tamper/wrong-key/wrong-arch/traversal/unknown-version/missing-verity tests.
- [ ] Performance and smoke coverage: add builder-VM/KVM `machine run --image alpine -- true`, `machine run --net --image alpine -- nslookup example.com`, phase timing, cached hot-start benchmark, and macOS backend measurements before making latency claims.
- [ ] Dependency and budget gates: add duplicate-major and binary-size budgets, finish default-machine-path dependency cleanup, reduce OCI/TLS stack duplication, slim heavy test fixtures, audit machine-path CLI UI deps, and move libkrun bindgen/libclang usage to regeneration-only.
