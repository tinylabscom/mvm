# Refactor status — rollup checklist

**Correction 2026-06-21:** Plan 193 is no longer blocked on rvproxy transparent-interception schema for libkrun. rvproxy has the contract, and this branch wires libkrun native rvproxy config to the host terminator. Vz remains intentionally guarded until its launch path emits/uses the same native rvproxy config; splice/Plan-141 deletion still waits on Vz wiring and live allow/deny proof.

**Latest update: 2026-06-21** Plan 126's last open item is resolved by decision: `aws-lc-rs` removal + the `reqwest`/`oci-client` major-unify (B4+C1) are rehomed to the dependency roadmap, with the durable fix filed upstream as [oras-project/rust-oci-client#274](https://github.com/oras-project/rust-oci-client/pull/274) (`rustls-tls-no-provider`, validated to drop `aws-lc-rs` from the tree) — refactor-close is no longer gated on Plan 126 (#1117/#1120). Plan 118's default-path Vz warm-claim is fixed (#1112/#1101): dev-rootfs standbys now pair the dev kernel, so `up --dev` / transient `run` consume the standby instead of silently cold-booting. Plan 189 WS-1 `vm save`/`vm restore` aliases landed (#1118). Plan 205 (resident builder control plane + residency model) is complete: WS-A/B/D/F merged (#1090/#1094/#1099/#1103), WS-E via #1102, WS-C's resident builder daemon delivered by Plan 204's `mvm-builderd` (#1091), the builder-tier trust gate (#1110) machine-checks all three tiers (`clean (3 rows)`), `MVM_RESIDENCY` and `mvmctl doctor` residency reporting are wired, Vz dev-builder park/restore + auto-park + invocation keeper are implemented, and the live macOS-26 Vz closeout runner passed in `/tmp/mvm-plan205-live-proof9` with warm reuse 130 ms, parked restore P50 643 ms / P95 1163 ms, zero command failures, final state `parked`, and live OCI `run --image docker.io/library/alpine:3.20 -- /bin/true` exit 0. FC live-memory remains delegated to Plan 175 and resident-daemon lifecycle refinements remain delegated to Plan 204; they no longer gate Plan 205. The builder-residency decision core carries `BuilderResidencyAction` plus builder snapshot freshness checks in `mvm-core::residency` (#1121). One correction from execution: workload-standby freshness is the existing `StandbyCompat` (kernel+image sha), not the builder fingerprint (Plan 195's fingerprint is builder-VM scope). The `host_signer` trust-gate false-positive is closed (#1123): builder/prod-agent gates now narrow their checks to the right authority-bearing crates, and persistent OCI machines document `warm_pool_size = 0` as intentional because named machines do not use the warm pool. Plan 193 transparent terminator wiring is explicitly blocked on rvproxy schema/support, not an mvm-only code slice: the local rvproxy config and `GatewayConfig` surfaces have no typed transparent `:80`/`:443` interception field or host-terminator destination, so mvm must keep libkrun/Vz at `VsockUdsChannel` and must not claim `supports_transparent_terminator()` until rvproxy lands the contract. Plan 193 already has the required rvproxy parity gate: `.github/workflows/rvproxy-parity.yml` runs on every PR and merge-group SHA, emits a stable `rvproxy gateway parity` job, skips unrelated PRs/merge groups through a cheap Ubuntu changes detector, and requires the macOS `rvproxy vs gvproxy parity` candidate/control run when gateway-contract files change; `rvproxy gateway parity` is in the `main` branch-protection required-status list. Remaining Plan 193 work is rvproxy transparent-terminator contract/implementation, mvm wiring once that exists, then splice/Plan-141 `on_packet` deletion. Plan 202 is complete. Plan 200 portable-artifact preview now has a reusable verified-admission gate: `machine check-artifact` derives admission only after `.mvm` signature/hash/format verification and host-arch acceptance, with machine-level wrong-key, tamper, and arch-mismatch refusal tests. Plan 200 SDK artifact-verification parity now exposes that CLI-owned `machine check-artifact` path through Python `Machine.check_artifact`, TypeScript `Machine.checkArtifact`, and Rust `MachineCheckArtifact`; shared-fixture/fake-CLI tests prove SDKs route to `mvmctl machine ...` instead of privately verifying `.mvm` artifacts. Plan 200 docs/source guards now cover the beginner machine story with scenario-led use cases, explicit limitations, and a CI-wired `xtask check-machine-doc-guards` gate against implying host Nix, GPU, ICMP, or unsupported architectures are default-supported. Remaining Plan 200 C2/auth proof is live admission/non-bypass proof and live VM SSH-agent round-trip after rerunning the Firecracker in-guest raw probe through the port-5301 runtime-UDS fix; remaining portable-artifact product work is live `machine run <artifact>` / `machine pack` plus workflow docs. Plan 159 is closed: VZ/macOS scope is shipped, verb/install/product polish is rehomed to Plan 181 / Plan 200, and signed delta-image distribution is descoped until an owning artifact/distribution plan is opened.

**Additional 2026-06-20 — Plan 206 on-host slices landed (UFFD + live-KVM tail remains):** the two Plan-206 pieces verifiable without a live KVM host are implemented and unit-tested; the macOS dev host cannot boot a KVM Firecracker VM, so every "proven on live KVM" acceptance line stays open. **Task 2 (primed barrier), host+guest wiring:** a new `GuestRequest::PrimedStatus` → `GuestResponse::PrimedStatusReport { primed }` RPC (mirrors `ProbeStatus`, wired through the whole verb/contract/profile surface, `deny_unknown_fields`); the workload asserts primed by creating `PRIMED_MARKER_PATH` (`/run/mvm/primed`, a no-privilege tmpfs write) and the agent reports presence via `workload_is_primed_at`; host-side `VsockPrimedSignalSource` polls the RPC over `vsock_transport::for_vm`, with the poll *policy* (`wait_for_primed_polling`) unit-tested against a fake "mock guest" and the per-poll vsock I/O left as the thin live-gated shell (mirrors `VsockPostRestoreSignal`); `mvmctl vm pause --primed-barrier [--primed-timeout=120]` calls `await_primed_barrier` before `pause_and_seal` and fails closed on timeout (no half-warmed snapshot; the hermetic `mock` hypervisor is never gated). **Task 3 (token-delivery polish):** S2 honest verb is done end to end — `post_restore_at` returns `PostRestoreReply { acknowledged, reseeded }`, `warm_restore_instance` returns a typed `ReseedStatus` (`Rotated`/`NotRotated`/`Undelivered`/`NotApplicable`, classified by the pure `classify_reseed`), `VmBackend::warm_start` returns `WarmStartOutcome { id, reseed }` (libkrun disk-only = `NotApplicable`), and `run_warm_start` prints `reseed.resume_summary()` so the line reflects the real outcome instead of unconditionally claiming "VMGenID rotated"; S1's fallback widens the post-resume agent-ready wait 30s→60s with a budget regression test. Remaining Plan 206 work is **Task 1** (the UFFD/NBD/hugepages substrate — Linux-kernel + live-KVM, unverifiable on a macOS dev host) and the three live-KVM acceptance proofs (T2-S3 seal-on-signal, T3-S1 root-cause of the ~30s latency, T3-S3 live reseed divergence). All on-host layers green: fmt + workspace clippy clean, doctests pass, `xtask check-no-spec-refs-in-comments` clean, ~30 new/related unit tests across `mvm-core`/`mvm-guest`/`mvm-backend`/`mvm`/`mvm-cli`.

**Additional 2026-06-19 — Plan 205 "instant" bar made a CI/live gate:** Plan 205's residency acceptance was hardened from "measured, not asserted" into an explicit latency budget (new "Latency budget" section). The PR matrix gates the deterministic no-boot invariant; the backend-bearing lane gates end-to-end `mvmctl` behavior on real hardware. The closeout gate is warm reuse under 250 ms and parked Vz restore P50 under 800 ms with P95 ≤ 2× P50. The earlier 100 ms figure remains the raw saved-state aspiration, not the shipping end-to-end CLI/supervisor/gvproxy budget. The first-ever image-download cost is explicitly out of the budget — paid once at install/prefetch time (`mvmctl bootstrap` prefetch / install-script prefetch), never on the per-command hot path.

**Additional 2026-06-21 — Plan 193 libkrun transparent terminator wiring:** the previous rvproxy-schema blocker is lifted for libkrun. rvproxy now exposes typed transparent `:80`/`:443` interception to a host terminator, and mvm wires libkrun native rvproxy config to that terminator: `[transparent]` is rendered, the libkrun supervisor carries the per-VM loopback port, and the substitution endpoint accepts rvproxy's original-destination preamble. Vz remains guarded at `VsockUdsChannel` until its launch path emits and uses the same native rvproxy config. Remaining Plan 193 work is Vz wiring, the live allow/deny matrix, then splice/Plan-141 hook deletion.

**Additional 2026-06-20 — Plan 205 parked-resume budget reconciled (#1141):** the parked (`min=0`) resume budget is not a hard `< 100 ms` full-memory-restore gate. Parked trades resume latency for zero idle RAM; the correctness bar is **no slower than a cold boot of the same closure**, while the shipped macOS/Vz closeout gate is the stricter measured target above (P50 under 800 ms, P95 ≤ 2× P50). The `< 50 ms` / sub-100 ms figures scope to the warm no-boot control path and raw resume signaling, not the full end-to-end memory restore. ADR-090 §2 was internally inconsistent (diagram `<100ms` vs prose "well under a second") and is now reconciled to match. Still deferred: a `bench residency-resume` harness + a force-park hook / idle override so the parked path is reachable without the 20-min TTL (tracked in Plan 205 §"Deferred follow-ups").

**Additional 2026-06-20 — Plan 205 Vz dev-builder snapshot park/restore slice:** the explicit Vz builder parked-state mechanism is now wired for the stable dev-builder session. `mvm-build::vz_builder` computes `state.vzsave` / `<snapshot>.machine-id`, sends host-only `SAVE` over the persistent Vz supervisor control socket, verifies the snapshot pair, stops the supervisor, and can respawn from the persisted `SupervisorConfig` in `StartupMode::Restore` with a fresh gvproxy. `mvmctl dev park` snapshots/stops the Vz dev builder; the next `mvmctl dev up` restores an existing snapshot before cold-boot fallback; `dev status` reports `parked`; `mvmctl doctor`'s `builder residency` line reports `parked (snapshot present)` vs `parked (no snapshot)`; parser + JSON shape + doctor wording are tested. The later proof9 closeout completes the idle/live/OCI acceptance lane.

**Additional 2026-06-20 — Plan 205 invocation-driven persistent-builder keeper:** the libkrun `persistent-builder` session now records `last_activity_unix_secs` in its shared JSON session record (backward-compatible for old records). Build dispatch touches the timestamp before/after persistent use, the CLI writes the same `MVM_DATA_DIR`-aware path that `mvm-build` reads, and the next build invocation applies the resolved residency policy before routing. `MVM_RESIDENCY=cold` now actively stops a live libkrun persistent-builder session before falling back to single-shot; idle `Park` decisions on this snapshot-incapable path degrade to teardown. CI-only tests cover JSON compatibility, activity touching, fresh-warm keep, cold teardown, and snapshot-unavailable idle teardown. The later proof9 closeout completes the Vz idle-timeout/live timing and live-coupled OCI lane.

**Additional 2026-06-20 — Plan 205 Vz dev-builder auto-park on down:** the Vz dev-builder parked-state path is now transparent for the normal lifecycle: `mvmctl dev down` auto-parks a live non-reset Vz dev builder when the resolved residency policy keeps a persistent builder, while `--reset`, rebuild, cache-clear, cold residency, and failed restore paths remove stale `state.vzsave` markers so the next `dev up` cold-boots instead of accidentally waking an unwanted builder. The resume side is residency-gated too: `dev up` restores only when the current policy still allows a resident builder. Focused gating tests cover cold/no-live/reset/resume truth-table behavior. The later proof9 closeout completes the idle-timeout live timing and live-coupled OCI proof.

**Additional 2026-06-20 — Plan 205 Vz dev-builder invocation keeper:** the Vz dev-builder now has the same no-background-daemon keeper shape as the libkrun persistent-builder path. `dev up`, restore/reuse, and `dev shell` touch a `last-activity-unix-secs` marker in the Vz builder state dir; `dev status` applies the resolved residency policy before reporting state, parking a warm builder after the idle threshold, parking any live builder under `parked`, and tearing down under `cold`. `dev up` also enforces cold at entry, so a stale live Vz builder cannot be reused when the policy says cold boot. Unit coverage pins not-running keep, cold teardown, parked park, warm threshold behavior, and timestamp persistence. The later proof9 closeout completes the live macOS-26 no-boot/restore timing proof plus live-coupled OCI `run --image` proof.

**Additional 2026-06-20 — Plan 205 live-gate runner:** `scripts/capture-plan-205-live-gates.sh` captures the remaining macOS/Vz Plan 205 acceptance lane in one opt-in command. It builds or uses a supplied `mvmctl`, isolates state under `/tmp` by default, records per-command stdout/stderr plus `timings.tsv`, writes `summary.json`, asserts warm reuse, parked restore samples, cold teardown setup, and `run --image` residency coverage, and fails if command execution or the latency budgets regress. The later proof9 closeout is the green target-host evidence for this runner.

**Additional 2026-06-20 — Plan 205 complete:** the live-gate runner is green on the target macOS-26 Apple Silicon host. Evidence: `/tmp/mvm-plan205-live-proof9/summary.json` reports `passed: true`, warm reuse 130 ms (budget 250 ms), restore samples `[643, 333, 1163, 351, 1066]` ms, restore P50 643 ms (budget 800 ms), restore P95 1163 ms (≤ 2× P50), and zero command failures; `final_status.stdout` reports `state: "parked"`; `oci_run.stdout` reports `exit_code: 0` and `success: true` for `docker.io/library/alpine:3.20`.

**Additional 2026-06-20 — Plan 175 Task 1 (VMGenID delivery) host/unit landed:** the `PostRestore` resume RPC now carries the host-minted generation token end to end so a snapshot restore actually rotates the guest CSPRNG. `GuestRequest::PostRestore` became a struct variant `{ token: [u8; GENID_BYTES] }` (`#[serde(default)]` → all-zero = "no rotation" for template-restore callers), `PostRestoreAck` gained `reseeded: bool`, and the guest agent feeds the token to a process-resident `GenIdReseeder` (snapshot-captured, baseline-zero seed) via a new zero-aware `on_post_restore_token` dispatch wrapper; `GenIdState::new`/`GenIdReseeder::new` are now `const fn`. Both host senders mint a fresh token per resume (`VsockPostRestoreSignal`, `post_restore_at`); `mvmctl resume` surfaces "VMGenID rotated". Unit-proven (zero-token no-op, fresh-token rotate, idempotent re-send, two-clone divergence, wire round-trip + `deny_unknown_fields` + serde defaults); fmt+clippy clean. Step 3 (live snapshot→restore `/dev/urandom`-divergence assertion) stays gated — it rides Task 4's FC restore driver. T2 (UFFD/NBD/hugepages substrate), T3 (SIGUSR1 primed barrier), and T4 (`FirecrackerBackend::warm_start` + verb + `agent_ping` e2e) remain.

**Additional 2026-06-20 — Plan 118 Firecracker standby pool live:** the non-vz Firecracker standby box is implemented and live-validated. Firecracker now reserves the normal slot at warm-spawn time, prestarts the daemon, records the live standby in `SupervisorStandbyPool`, and claim reuses that slot to configure the admitted launch shape before issuing `InstanceStart`. The `StandbyClaim` in-memory contract carries the original `VmStartConfig` for backends that must configure boot devices at claim time; libkrun/Vz keep consuming the explicit attach fields. `try_warm_claim` remains fail-open but now permits Firecracker claims without bridge-only `plan_json` while preserving libkrun/Vz's signed-plan requirement. `--up-json` now reports the claimed standby id. Remote proof on `rvproxy-firecracker` (2026-06-20): `pool warm 1` produced one live idle standby; `up --detach --warm-pool-size 1 --hypervisor firecracker --up-json` consumed `standby-6a263a7a4233599a`; replenish restored one fresh idle standby.

**Additional 2026-06-20 — Plan 118 Firecracker baselines + mvmd sizing:** committed Firecracker live bench artifacts under `specs/perf/plan-118/`. The reports are `HostDescriptor`-namespaced with `readiness_boundary=firecracker-pid`: single launch P50 `total_ready_ms=1899.851577`, concurrency-2 P95 `total_ready_ms=1273.05340545`, and density count-2 PSS `138852352` bytes total / `69426176` bytes per instance. Follow-up gated runs passed against those baselines: serial launch `-16.27%`, concurrency P95 `-23.13%`, density per-instance PSS `+0.35%`. Warm-pool launch through the bench harness produced P50 `total_ready_ms=803.596724` versus the gated cold P50 `1590.731061` (`49.48%` faster). The bench harness now asserts Firecracker VM cleanup after RAII teardown, remote cleanup proof found no named `mvm-bench-fc*` / `mvm-density-fc*` processes remaining after report capture, and `admit_probe_plan_generates_distinct_nonces_per_boot` covers per-boot nonce distinctness. Guest-agent-ready probes now persist `ReadinessReport.boot_millis` sidecars under `bench/boot-timing-<vm>.json` for BootTiming cross-checks; Firecracker remains fingerprinted as PID-boundary until its proof image exposes guest-agent ping. The Vz bench lane is implemented for serial launch, concurrent launch, and density through the same admitted-plan probe flow with macOS `phys_footprint` sampling and no-leak teardown assertions; live Vz artifacts remain host-gated. The companion mvmd worktree `feat/plan-118-sizing` now reconciles `desired_counts.warm` into fleet-level warm Firecracker instances; this is the real mvmd hook today because mvmd launches Firecracker directly rather than through mvm `VmStartConfig.warm_pool_size`. Final closeout evidence is green: `cargo test --workspace --no-fail-fast`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo fmt --all -- --check`.

**Additional 2026-06-19 — Stage 0 bootstrap performance follow-up:** the active branch also addresses the observed `[mvm] Materializing Stage 0 root dir` cold-path latency without overclaiming beyond the measured path. Host-side Stage 0 root materialization now reuses a marker-bound extracted root and prefers native `tar -xJf --strip-components 1` after SHA-256 verification, falling back to the prior pure-Rust extractor if the host tar path is unavailable. Firecracker-host measurement on branch `156391a4` with isolated cache/data dirs: cold builder-image cache miss reached `Fetching Stage 0 bootstrap assets … 0.7s` and `Materializing Stage 0 root dir … 1.7s`; immediate warm rerun reached `Fetching … 0.1s` and `Materializing … 0.1s`. The same host confirmed the current Nix seed contains no `mkfs.ext4`/`mke2fs`, so the branch now adds a host-side libkrun preformat path: when host `mkfs.ext4` is available, `nix-store-stage0-<arch>.img` is populated from the verified RootDir `/nix` before boot and marked with a `.stage0-seed` sidecar; Stage 0 PID 1 can adopt that prepopulated store and write its in-filesystem marker. Bounded libkrun proof on the Firecracker host reached and logged the host prepopulate step (`blocks_4k=16777200`, sparse image plus sidecar written) before the 180s timeout; it did not yet capture an in-guest `stage0-init` adoption line, so full libkrun boot/adoption timing remains gated.

**Additional 2026-06-19 — Plan 193 native-gateway cleanup:** the first cutover cleanup after Plan 199/195 removes the dead mvm-side open-policy slot before splice deletion. `BridgeConfig.policy` and the production `AllowAll` `FlowPolicy` are gone; the four supervisor-bin construction sites no longer pass an ignored policy; tests that need an intentional open gate now use `PlanFlowPolicy::from_network_policy(NetworkPolicy::unrestricted())`. This aligns the code with the already-landed Plan 200 WS-B status and reduces the chance of reintroducing an always-open fallback while Plan 193 deletes the splice. Plan 193 status is corrected: rvproxy R2 is shipped, WS-1.5 scaffold/native enforcement witnesses are in place, and remaining code work is splice/Plan-141 hook deletion plus transparent terminator support; the parity gate is now required as of the 2026-06-20 update below.

**Additional 2026-06-19 — Plan 193 macOS/libkrun native-default gate:** the native-default selection slice is implemented without deleting the splice. `resolve_networking_mode()` now chooses `NetworkingPreference::Native` by default on macOS when `MVM_GATEWAY_BIN` names the rvproxy candidate, so the existing libkrun supervisor native block renders `rvproxy.toml`, launches `rvproxy run --config`, and tails native flow-audit without requiring `MVM_NETWORKING=native`. Safety fallbacks remain explicit: no `MVM_GATEWAY_BIN` keeps the historical gvproxy default, Linux remains passt by default, and `MVM_NETWORKING=gvproxy` still pins the legacy gateway. Remaining Plan 193 code work: splice/Plan-141 `on_packet` deletion and transparent terminator support; the parity gate is now required as of the 2026-06-20 update below.

**Additional 2026-06-19 — Plan 193 admitted bridge default status:** reconciled the remaining-work list with the already-landed Plan 200 default handoff. Admitted libkrun/Vz workload starts already thread the signed plan by default (`should_thread_signed_plan(false, "libkrun"|"vz")`), so there is no separate future `MVM_GATEWAY_BRIDGE` default flip for those backends. Firecracker's bridge sidecar remains explicit because default Firecracker egress is enforced through nftables. Superseded by the follow-up requirement guard below: remaining Plan 193 code work is rvproxy transparent-terminator schema/support, mvm wiring once that exists, and splice/Plan-141 `on_packet` deletion; the parity gate is now required as of the 2026-06-20 update below.

**Additional 2026-06-19 — Plan 193 transparent terminator requirement:** the mvm-side deletion guard is explicit. `EgressSubstitutionTransport` now distinguishes proxy-aware substitution from transparent `:80`/`:443` terminator support, and `require_transparent_egress_terminator(&dyn WorkloadBackend)` is tested to accept Firecracker's nft terminator while refusing libkrun/Vz/mock. This does not implement macOS interception; it records the rvproxy capability that must exist before splice/Plan-141 hook deletion. Remaining Plan 193 work is rvproxy schema/support first, mvm wiring once that exists, then deleting the splice and Plan-141 hooks; the parity gate is now required as of the 2026-06-20 update below.

**Additional 2026-06-20 — Plan 193 required parity gate active:** the rvproxy parity workflow now exposes a stable `rvproxy gateway parity` job on every PR and merge-group SHA, and that context is required in `main` branch protection. A cheap Ubuntu detector decides whether gateway-contract files changed; unrelated PRs/merge groups pass without macOS spend, while relevant ones must pass the existing macOS `rvproxy vs gvproxy parity` run. Remaining Plan 193 code work is rvproxy transparent-terminator schema/support, mvm wiring once that exists, then splice/Plan-141 hook deletion.

**Additional 2026-06-20 — Plan 193 transparent terminator blocked on rvproxy schema:** mvm-side wiring cannot safely proceed yet. The local rvproxy checkout exposes `RvproxyConfig` sections for network/backend/transport/api/dns/policy/audit/transforms and `GatewayConfig` flow-policy fields, but no typed transparent `:80`/`:443` interception section or host-terminator destination. mvm therefore keeps libkrun/Vz declaring only `VsockUdsChannel`; flipping them to transparent support before rvproxy lands that contract would be a false security capability claim. Remaining Plan 193 sequence is rvproxy contract/implementation first, then mvm config/wiring + tests, then splice/Plan-141 deletion.

**Additional 2026-06-20 — Plan 189 JSON/stdout + Vz dev-shell hardening:** `mvmctl ls --all --json` no longer risks stdout corruption from pre-dispatch `[mvm]` chrome: the dispatcher routes chrome to stderr before reconcile-on-entry for structured-stdout commands (`ls --json`, `dev * --json`, `run --json`, `up --up-json`, and grouped Vz save/restore/snapshot JSON). The same pass fixes the reported Vz `dev shell` attach failure mode: `VzPersistentBuilderVm` now opens a bounded PTY data-port range (`20001..20128`) alongside guest-agent port 5252, matching `ConsoleOpen`'s `CONSOLE_PORT_BASE + session_id` data-channel contract, and the Vz `dev shell` arm now preserves the real attach error context instead of rewriting every failure as "owned by another process." Superseded by the Plan 189 closeout below: this was an implementation slice, and later live-only checks are shared validation.

**Additional 2026-06-20 — Plan 189 source-checkout Vz helper freshness:** fixed the reported `ExecutionPlan.auth` decode failure on `cargo run -- run -- ...` with the Vz backend. Source-checkout `mvmctl` now treats `mvm-vz-supervisor` and `mvm-vz-drainer` as same-workspace sidecars: before launching an adjacent/source-tree helper it checks the helper outputs against `Cargo.lock`, workspace `Cargo.toml`, `crates/mvm-vm-host/src`, `crates/mvm-core/src`, and `crates/mvm-build/src`, then runs the narrow `cargo build -p mvm-vm-host --bin mvm-vz-supervisor --bin mvm-vz-drainer` only when a helper is missing or stale. This prevents a fresh schema-v6 `mvmctl` from pairing with a stale schema-v5 drainer while leaving release-installed adjacent binaries and explicit `MVM_VZ_*_PATH` overrides unchanged. Superseded by the Plan 189 closeout below.

**Additional 2026-06-20 — Plan 189 linux-native JSON detail:** `mvmctl dev status --json` no longer collapses Linux-native readiness to only `ready` / `not-ready` / `no-kvm`. It keeps that top-level state and adds a typed `linux_native` object with safe `kvm`, `firecracker`, and `base_assets` readiness labels. Tests pin the privacy floor: no `/dev/kvm` path, host paths, artifact filenames, or raw digests leak into JSON. Plan 189 WS-3 JSON coverage is complete; superseded by the closeout below for the later live-validation scope decision.

**Additional 2026-06-20 — Plan 189 Vz dev base-ref pinning:** the first WS-4 implementation slice is landed for the Vz dev path. `mvmctl dev up --base <template[@revision]|slot[@revision]|bundle-sha>` now resolves through the existing template/manifest-slot/bundle artifact registry instead of adding a parallel base registry. Current refs reuse `template_artifacts_dispatched`; exact template/slot revision pins require existing `vmlinux` + `rootfs.ext4` artifacts, reject path-traversal components, and fail before launch on unknown/unbuilt bases. A running dev VM refuses `--base` rather than silently reusing a different base. Superseded by the Plan 189 closeout below: base-ref implementation is complete and follow-up proof moved to shared live validation.

**Additional 2026-06-20 — Plan 189 pinned-base fingerprint proof surface:** Vz `dev up --base` now writes a dev-state base provenance record with `{ id, revision, rootfs_fingerprint }`, and `dev status --json` exposes that optional `base` object without leaking host artifact paths. Default starts and `dev down` clear stale base provenance, and `dev up --base` refuses parked dev snapshots rather than restoring an older base while ignoring the requested ref. This gives shared live validation a direct comparison point against checkpoint/fork content hashes.

**Additional 2026-06-20 — Plan 189 closeout:** Plan 189 is closed as implementation-complete by scope decision. The shipped ADR-076 DX/UX layer now covers first-class save/restore aliases, stable Vz lifecycle JSON, structured-stdout hardening, Vz dev-shell reachability, source-checkout helper freshness, linux-native status detail, and pinned-base resolution/provenance. The macOS-26 exercises are hardware validation for already-shipped primitives, not Plan 189 code: save/restore aliases use the existing `vm-full` checkpoint path, warm `dev up` cache-hit behavior is covered by Plan 195 validation/tests, and pinned-base fork/rootfs content proof belongs with the shared Vz live-validation lane.

**Additional 2026-06-20 — final macOS-26 timing/content validation lane:** Plan 189 is complete; the post-Plan hardware lane that remains is evidence capture across the shared Vz live paths, not a Plan 189 blocker. Finish it as one quiet-box macOS-26 run with isolated `MVM_DATA_DIR` / `MVM_CACHE_DIR`: (1) `vm save` → stop/down → `vm restore` proves the alias path still round-trips the existing `vm-full` checkpoint primitive; (2) two warm `dev up` runs prove cache hit/no builder-VM rebuild and record guest-agent-ready timing; (3) pinned `dev up --base <ref>` plus `dev status --json.base` records stable rootfs fingerprint/provenance; (4) checkpoint/fork from that pinned base records matching content fingerprint after restore/fork. File the captured command transcript and timings against the shared Vz live-validation lane (Plans 118/205/189 evidence), then update this rollup with the measurement result only if the run finds a product bug or closes a broader Plan 118/205 live gate.

**Additional 2026-06-20 — macOS-26 live-validation result:** ran the shared Vz lane on macOS 26.3.1 with isolated `MVM_DATA_DIR=/tmp/mvm-plan189-data` and the shared cache. The first product-path `mvmctl dev up --no-shell --json` preconditioned Stage 0 and rebuilt the builder image (active kernel + `mvm-guest-agent` compile, then `stage0-init: done; halting`). After that, cache-hit Vz dev evidence was clean: `dev status --json` reported `builder_cache.kind="source"` / `state="ready"` / `reason_code="hit"`; parked restore `dev up --no-shell --json` returned `outcome="restored"` in **0.63s**; stopped cache-hit `dev up --no-shell --json` returned `outcome="started"` in **6.14s**; pinned `dev up --base hello-minimal --no-shell --json` returned `outcome="started"` in **1.24s** and `dev status --json.base` reported `{ id: "hello-minimal", revision: "1v2vbvq1s07qi1k6ppqlxpv9xz6gpxfi", rootfs_fingerprint: "e93d29cc22a009b170d051ed9ce9a400fafb82fd02f3eecdb6244b623601167d" }`, matching `shasum -a 256` of the isolated copied base rootfs. The alias round-trip remains blocked by a product-path live issue, not Plan 189 scope: `up --hypervisor vz --dev --name plan189-save -d --up-json` and the long-lived `examples/sleeper` fixture both admitted/launched and returned success JSON, but `mvmctl ls --all --json` immediately returned `[]`, the Vz supervisor/drainer/gvproxy PIDs in `/tmp/mvm-plan189-data/vms/plan189-sleeper/` were dead, and `vm save plan189-save --json` failed with `checkpoint --class vm-full requires a running VM`. Keep Plan 189 closed; track the remaining work as shared live-lane follow-up: detached Vz workload persistence/registry visibility first, then rerun `vm save`/`vm restore` and checkpoint/fork content proof from the pinned base.

**Additional 2026-06-20 — detached Vz visibility/fail-fast slice:** started the shared live-lane follow-up. `mvmctl ls --all` now merges durable VM-name registry entries that are absent from backend probes as stopped rows, so a detached Vz workload that exits after reservation no longer disappears into an empty `[]`; non-`--all` listings continue to hide stopped rows. `VzBackend::start` now adds a short post-PID stability window: after `mvm-vz-supervisor` writes `vz.pid`, the parent refuses launch success if the supervisor immediately exits or removes the PID file. This closes the false-success/empty-list observability gap and should make the next live run fail with an actionable Vz error if the sleeper still exits immediately. Remaining shared live-lane work: rerun the macOS Vz `examples/sleeper` / `vm save` / `vm restore` proof after this lands, then capture pinned-base checkpoint/fork content proof if the guest stays resident.

**Additional 2026-06-20 — detached Vz registration/listing follow-up:** the next live retry found one more registry timing bug before the save/restore proof can proceed. Launch reservations now fill the concrete `<MVM_DATA_DIR>/vms/<name>` runtime directory before backend start, and `ls --all` / `ls --all --json` skip destructive reconcile-on-entry so registry-only stopped rows can render before convergence sweeps them. Focused tests pin reservation completion and the `ls --all` convergence exception. Live macOS retry with isolated state returned success JSON for `examples/sleeper`, then `ls --all --json` correctly reported `plan189-sleeper4` as `Stopped` with `readiness="launch_accepted"` instead of `[]`; `vm save plan189-sleeper4 --json` now fails with the accurate product error `checkpoint --class vm-full requires a running VM; start 'plan189-sleeper4' first`. Remaining shared live-lane blocker is actual Vz detached workload persistence: the sleeper guest boots through root mount/DHCP start, but the supervisor and drainer exit shortly after accepted launch, so save/restore and pinned-base checkpoint/fork content proof still require a resident guest.

**Previous update: 2026-06-18** Plan 202 Phase 5 mvmd adoption has started in the companion mvmd Plan 52 workstream while Plan 202 remains open, and the first delegated `host.cost.v1::tenant` slice is now landed and recorded across the rollups: `mvm-core` exposes typed `HostCostTenantQuery` / `HostCostTenantResult` wire messages, `mvmd-agent` resolves the request against the gateway tenant infrastructure-cost route over the existing ALPN transport, and hostile cross-tenant queries are refused before any gateway hop. mvmd now starts/reuses the shared `mvm-host-agent` + `mvm-signer-helper` unit per tenant from instance lifecycle events, registers/deregisters VMs against the resident tenant daemon, binds Firecracker guest-to-host broker traffic on `runtime/v.sock_5300`, and hardens the lifecycle seam so tenant/pool/instance IDs are path-safe validated before deriving daemon registration paths or replaying `host-agent.tenant` marker state. Remaining Phase 5 work is the broader cross-VM endpoint/authz surface, density proof, per-tenant key-boundary proof, and ADR-084 acceptance. In parallel, mvmd PR `#160` carries the CI plumbing needed to keep that cross-repo slice green: the sibling checkout is pinned to `tinylabscom/mvm`, `zigbuild` is installed before sibling builds, and embedded-binary PR gates are skipped in the PR lane. Plan 202 vz live verification is complete on top of Phase 4b supervised daemon restart: a direct-boot `audit-probe` VM on vz (`tenant=p202vz`, `vm=p202vzprobe`) ran with no `MVM_GATEWAY_BRIDGE` and no daemon env override, emitted 22 workload entries through `host.audit.v1`, verified clean with `mvmctl trust audit verify --tenant p202vz` (4 lifecycle entries + 22 workload entries), and deregistration left the per-tenant registration journal empty. The flake builder path was blocked by a builder-VM `BadActivate` before workload boot, so the vz runtime proof used a previously built `audit-probe` rootfs copied into isolated state plus `MVM_DIRECT_BOOT=1`. Plan 126 / Plan 200 bookkeeping drift was reconciled. Plan 126's default-closure gate and final measurement are landed: `sigstore`, `opendal`, and `pgp` are out of the `mvmctl` default closure, `opendal` is replaced by `object_store`, D1's forbidden-dep closure ban is wired, and the final measure is recorded in `docs/investigations/dep-baseline.md`; remaining Plan 126 scope is the still-blocked OCI/TLS stack decision (`oci-client` fork/replace/upstream path, `aws-lc-rs` removal, and `reqwest`/`oci-client` major unification) plus documented follow-up sweeps. Plan 203 was added as a proposed opt-in forensic network transcript capture follow-on to claim 10. The default claim-10 posture stays metadata-only; raw transcript capture is a separate, explicitly armed/exported forensic mode with its own manifest and encrypted payload store. Plan 200 manifest-to-machine mapping and machine auth advanced on top of the earlier persistent-machine, lifecycle, parser, runtime-mapping, policy-surfacing, and ADR-088 slices: `machine create --manifest <path>` plus current-directory image-manifest discovery persist `mvm.toml` / `Mvmfile.toml` fields into durable `MachineSpec`s, including image, network defaults, allow-hosts, CPU/memory sizing, `mem_initial`, dev-init declarations, ssh-agent declarations, and volumes; `machine start --name` threads network policy, `mem_initial`, admitted volume shares, dev-init execution, and dev-tier `ssh_agent` socket forwarding through the admitted OCI-backed launch path. `machine start --name` accepts `ssh_agent = true` only on dev-capable profiles, requires host `SSH_AUTH_SOCK` to be a Unix socket, spawns a detached per-machine proxy that connects only to that socket, registers the existing guest→host vsock host-listen path on libkrun/Vz, and asks the dev guest agent to expose `/run/mvm/ssh-agent.sock`. `machine exec`, `machine shell`, and `dev.init` inject only that guest socket path; stop/failure paths reap proxy PID/socket state. Dry-run/receipts/audit report `ssh-agent-socket`, and no private key files, `~/.ssh`, or known-hosts material are copied or mounted. SSH-session hardening now removes built-in `github.com:22` preset grants, rejects explicit `--allow-host ...:22`, denies TCP/22 even under open egress, and makes `mkGuest` fail Nix evaluation when templates try to add SSH packages/config/material through `packages` or `extraFiles`; non-standard-port SSH protocol-denial remains an explicit follow-up because TCP/22 blocking alone is not a complete protocol ban. The remaining Plan 200 auth gap is a distinct signed-plan admission field plus live VM SSH-agent round-trip and non-standard-port SSH-denial proof, not the socket transport itself. Plan 125 is closed/rehome-only: its SDK/CLI veneer work is complete, and the remaining host-services daemon/process-model work now lives in Plan 202.

**Additional 2026-06-19 — Plan 200 C2 Python/TypeScript SDK wrappers:** Python and TypeScript now expose thin `Machine.run/create/start/exec/shell/stop` wrappers that shell only to `mvmctl machine ...`, return structured `MachineError`s, and have fake-CLI lifecycle/error tests. Rust builders and deeper SDK/CLI admission, receipt/audit, artifact-verification, default-deny-network, unknown-key, and source-conflict non-bypass parity remain open.

**Additional 2026-06-19 — Plan 200 C2 Rust SDK builders:** Rust `mvm-sdk` now exposes `MachineRun`, `MachineCreate`, persistent `Machine` lifecycle builders, `MachineClient`, and structured `MachineError`. The builders shell only to `mvmctl machine ...` and fake-CLI tests pin argv parity, lifecycle routing, source-conflict/empty-command validation, and failed-process error metadata. Remaining Plan 200 SDK parity is the deeper admission-input, receipt/audit-summary, artifact-verification, default-deny-network, unknown-key, and live non-bypass proof set.

**Additional 2026-06-19 — Plan 200 B2 phase timing (measure-first):** the first B2 task landed — `commands::vm::phase_timing` (`RunPhaseMarks`→`RunPhaseTimings`, pure + unit-tested) is wired at the `exec::run_inner` seams (resolve, drives, admit, backend-start, run, teardown) and emits one greppable stderr line behind `MVM_PHASE_TIMING=1` (default off, zero behavior change). The boot micro-benchmark substrate (`bench microvm-launch`) is reused, not rebuilt. The frozen "Stage 0 install cache / faster-first-boot" pivot was rejected as redundant with Plan 196 (warm-store/kernel-cache, WS-2 descoped) + Plan 198 (build cache) + the existing persistent /nix store. The `run` phase is now split into `vsock_wait` (boot→agent reachable) and `command`, and the line reports `dispatch_window` (admitted→agent-reachable) — the `<200 ms` bar window. First live vz numbers recorded (`mvmctl run -- true`, warm, N=3): `resolve≈0 · backend_start≈200 ms warm · vsock_wait≈1061 ms · teardown≈6140 ms · total≈7.5 s`. Findings redirect B2: `resolve≈0` empirically kills the "install cache" thesis; **teardown is ~82% of total** (vz guest doesn't honor graceful stop → sequential `SIGTERM→2 s→SIGKILL` for VM then drainer) and is the biggest lever; the `<200 ms` dispatch bar is missed by guest boot (`vsock_wait`), not host overhead. Teardown is now fixed: `VmBackend::stop_transient` (vz: SIGKILL supervisor+drainer+gvproxy up front, no 2s grace; persistent stop stays graceful) cut **teardown 6140 ms → ~0.5 ms, total ~7.5 s → ~1.36 s** (vz, warm, N=3). The hot path is now the ~1.06 s guest boot (`vsock_wait`). Tightening the `wait_for_agent` poll 500 ms → 50 ms further cut total to a best of ~1.08 s; the residual `vsock_wait` (~0.8–1.1 s) is now genuine guest boot with no host-side slack left. Remaining B2: hide guest boot via the warm/standby pool for run/machine run (the lever to ~150 ms "instant" — same-image standby + a pre-fill lifecycle; overlaps active Plan 118, coordinate), capture the upstream OCI cache-resolve span, the cached-`machine run` benchmark + `<200 ms` bar wiring, and a release/Linux-KVM lane.

**Additional 2026-06-19 — Plan 200 C2 Rust SDK/CLI parity proof:** Rust SDK machine builder argv now round-trips through the CLI machine parser and `mvmctl run` dry-run/preflight/receipt helpers without invoking Nix or booting a VM. Coverage proves SDK default-deny and `--allow-host` network posture matches the CLI receipt path, and SDK `MachineCreate --manifest` reaches the CLI strict-manifest unknown-key gate. Remaining: full admission-input equivalence, artifact-verification non-bypass, audit-summary parity, and live admission proof.

**Additional 2026-06-19 — Plan 200 C2 Python/TypeScript parser/preflight proof:** Python and TypeScript `Machine.run` argv construction now flows through explicit helper seams and shared checked-in fixtures. Python, TypeScript, and Rust tests all assert the same default-deny and allow-host+receipt fixtures; the Rust CLI tests parse those fixtures through `machine run` and the `mvmctl run` dry-run/preflight + receipt-summary seam, proving default-deny and allow-host receipt posture stay CLI-owned without invoking Nix or booting a VM. Remaining: full admission-input equivalence, artifact-verification non-bypass, audit-summary parity, and live admission proof.

**Additional 2026-06-19 — Plan 200 C2 admission-input / unknown-key parity:** Rust, Python, and TypeScript now share a richer `machine run` argv fixture that is asserted by SDK tests and parsed by Rust CLI tests through the same dry-run/preflight + receipt-summary seam. Coverage proves CPU/memory/profile, sorted env-key redaction, host-path hashing for volume shares, timeout propagation, command hashing, effective policy, and receipt-input parity stay CLI-owned without Nix or a VM. Python/TypeScript `Machine.create --manifest` now uses helper seams plus a shared fixture that reaches the CLI strict-manifest unknown-key gate. Remaining C2 proof: artifact-verification non-bypass and live admission/non-bypass proof.

**Additional 2026-06-21 — Plan 200 C2 SDK artifact-verification parity:** Python, TypeScript, and Rust now expose artifact-admission preview wrappers that shell to `mvmctl machine check-artifact` (`Machine.check_artifact`, `Machine.checkArtifact`, and `MachineCheckArtifact`). A shared checked-in argv fixture plus fake-CLI tests prove the SDKs do not implement a private `.mvm` verifier or bypass the CLI-owned verify-before-admission path. Remaining C2 proof: live admission/non-bypass coverage.

**Additional 2026-06-21 — Plan 200 machine docs/source guards:** scenario-led machine docs are now public (`guides/machine-use-cases.md`) and linked from quickstart/happy-path flows, covering untrusted-code sandboxing, image-backed one-shot runs, local image archives, persistent dev machines, SSH-agent forwarding, `mvm.toml`, and artifact verification. The paired `guides/machine-limitations.md` page explicitly scopes no-host-Nix normal use, network protocol behavior, volumes, SSH-agent prerequisites, macOS signing/entitlements, GPU status, and host/guest architecture support. `xtask check-machine-doc-guards` is wired into CI Lint to require those pages and reject beginner-doc overclaims that imply host Nix, GPU, ICMP, or unsupported architectures are default-supported.

**Additional 2026-06-19 — Plan 200 WS-B egress matrix hardening (follow-up c):** Re-audited the `up` libkrun/Vz egress path after follow-up (b)'s fix landed — threading chain, bridge-vs-legacy dispatch, data-path socket wiring, and `flow_policy` routing all read correct, and the bare lowering is correct for all three matrix verdicts (unrestricted forward / allow-list narrow / deny-all drop). Added deterministic live-bridge coverage for the previously-untested arms: `bare_unrestricted_policy_forwards_egress_through_the_live_bridge` (libkrun + Vz) and `live_bridge_relays_ingress_reply_back_to_the_guest` (first full-duplex internet→guest return-path test). Remaining: the live VM matrix re-run on a quiet macOS-26 box (deferred — dev box saturated with parallel live benchmarks).

**Additional 2026-06-19 — Plan 200 WS-B follow-up (d), live matrix exposed + fixed a real libkrun bridge bug:** The deferred live matrix returned verdict 3 for ALL policies (incl. unrestricted). The chain-signed audit proved the bridge policy was correct but the internet→guest return frames never reached the guest: `run_libkrun_gvproxy_bridge` replied to the recvfrom source instead of libkrun's derived `<listen>-krun.sock` reply listener (not a usable reply target on macOS), silently dropping every inbound frame. Fixed (reply to the derived path; matches the rvproxy native-gateway precedent); the duplex test was rewritten to model real libkrun so it catches the regression. **Live matrix now passes 0 / 3 / 2** on current origin/main. follow-up (c)'s bound-client test had masked it — only the live VM run caught it. Branch `fix/plan-200-libkrun-bridge-ingress-reply`.

**Additional 2026-06-19 — Plan 200 WS-B follow-up (e), Vz `up --wait` verdict-capture implemented:** Extracted the `wait()` poll into a shared backend-agnostic `mvm_backend::workload_wait` module; libkrun + Vz backends both delegate to it (the vz supervisor already persists `workload.exit`); relaxed both `up.rs --wait` gates to `libkrun|vz`. Unit-tested + clippy/fmt/spec/linux-cross-compile clean. **Live-vz `0/3/2` not yet proven** — surfaced a separate vz one-shot workload-boot failure (`supervisor exited before writing PID file`, empty console.log, fails at boot before `wait`), filed as a deferred follow-up. The `wait()` logic rides the shared path already proven live `0/3/2` on libkrun. Branch `feat/plan-200-vz-up-wait`.

**Additional 2026-06-19 — Plan 195 closeout:** Builder-VM fingerprint narrowing is complete. `builder_vm_source_fingerprint` ignores unrelated workspace `Cargo.lock` churn, keeps flake / `nix/lib` / embedded-host-binary byte identity as invalidation inputs, and `mvm-cli/build.rs` watches `Cargo.lock` + `crates/mvm-build/src` so those embedded bytes rebuild when their real inputs change. Closeout fixed stale comments that still described the removed lockfile layer and recorded verification: focused fingerprint tests (6/6), real non-stub embedded-binary build, `mvm-build/src` touch causing `cargo zigbuild` rerun, full `mvm-cli` nextest (1088 passed, 1 skipped), clippy, and fmt. The live `mvmctl dev up` manual was not re-run in this session because runtime commands must run inside the project builder VM and this checkout has no wrapper for that; deterministic cache-key tests cover the hit/mismatch behavior without booting a VM.

**Additional 2026-06-19 — Plan 200 auth-proof live follow-up:** the Firecracker-host proof now reaches guest boot on branch-local `mvmctl`: a dev-profile `alpine:latest` persistent machine with `[auth].ssh_agent = true` starts, signed receipt/dry-run/audit surfaces report `ssh-agent-socket`, and direct raw `SSH_AGENTC_REQUEST_IDENTITIES` probes to the throwaway host agent and spawned per-machine proxy UDS both return an SSH-agent identities answer. The proof remains unclaimed because the in-guest raw probe copied to `/tmp/mvm-agent-probe-c` reaches `/run/mvm/ssh-agent.sock` but reads `Connection reset by peer`, narrowing the blocker to Firecracker guest-to-host host-listen forwarding for port 5301. Follow-up code now routes Firecracker SSH-agent proxy traffic through the per-port runtime UDS (`vm_vsock_port_socket(..., 5301)`) instead of raw host AF_VSOCK, with unit coverage pinning backend socket transport; the live in-guest raw probe still needs rerun before the smoke is claimed. Runtime packet enforcement now drops inbound SSH identification banners on any TCP port via `ssh-banner-protocol-deny` and reverse-flow kill matching, but a live non-22 guest witness is still needed before claiming the SSH-banner smoke.

**Additional 2026-06-19 — Plan 199 native VMM recipes:** Workstream B implementation landed in the source-built overlay shape: pinned Linux host recipes for `libkrunfw` v5.5.0 (including Linux 6.12.91 source) and `libkrun` v1.18.1 (including Cargo vendor hash), Linux-only `libkrunfw` / `libkrun` / opt-in `mvmctl-native-libkrun` package and overlay attrs, and structural tests proving source pins, `BLK=1` / `NET=1`, non-native default `mvmctl`, and the no-mvm-release-binary rule. The builder-VM Nix verification follow-up is closed in the Plan 199 closeout entry below.

**Additional 2026-06-19 — Plan 199 closeout:** Plan 199 is complete. The final builder-VM Nix verification passed through the approved builder boundary: `nix flake check` evaluated the `nix/` flake package set, `.#mvmctl` built and checked to `/nix/store/68xqmybxxlpckymlfqfvc1ka0x2yqvhx-mvmctl-0.16.1`, and the opt-in native path `.#mvmctl-native-libkrun` built and checked to `/nix/store/0sg78jmbiv0yll6csmv8201ap167sm6m-mvmctl-0.16.1`. The closeout fixed the native package link boundary by requiring explicit `libkrunfw` alongside `libkrun`; microVM guest images still do not install `mvmctl`, and source-checkout Nix still never fetches mvm release binaries.

**Additional 2026-06-19 — Plan 204 / ADR-089 proposed:** Draft PR #1082 records the long-term builder VM direction: `mvmctl` remains the single host-facing UX, normal use does not require host Nix, and the builder VM grows a resident internal `mvm-builderd` service that accepts typed vsock `BuilderRequest`s for Nix/build work. The stable API is allowlisted operations with structured progress/provenance, not a generic remote shell; workload guest images still do not include `mvmctl` or `mvm-builderd`.

**Additional 2026-06-19 — Plan 204 WS-A protocol pair landed:** the first implementation slice is the typed wire protocol, `mvm_build::builderd_protocol`. `BuilderRequest` is the stable allowlist (`Handshake`, `Probe`, `FlakeCheck`, `BuildGuestImage`, `BuildHostTool`, `PrefetchSource`, `QueryStorePath`, `CancelJob`) — there is deliberately no generic shell variant; `BuilderResponse` streams `Progress`/`LogChunk` then one terminal `ArtifactReady`/`StorePathReady`/`Failed`/`Cancelled` (plus `Accepted` for handshake/probe). Each operation carries an `OperationId` for correlation/cancellation, `Failed` carries a stable `FailureCategory` so the host shows actionable errors without parsing stderr, and version negotiation (`PROTOCOL_VERSION` + `negotiate()` + `handshake_reply()`) is exact-match v1 and refuses unknown versions fail-closed with `FailureCategory::Version`. The wire mirrors the sibling `builder_protocol` idioms (externally-tagged snake_case + `deny_unknown_fields` everywhere, 256 KiB framing inherited from `mvm_guest::vsock`), so an unknown peer field or kind is rejected, not silently dropped. This is a new module beside the legacy controlled-shell-job channel (`builder_protocol`), which Plan 204 keeps as the WS-D compatibility adapter. 26 unit tests: per-variant roundtrip, kind-tag/category-tag stability, unknown-field + unknown-kind rejection, and version-negotiation refusal.

**Additional 2026-06-19 — Plan 204 WS-A daemon request-handling core:** `mvm_build::builderd` adds the cross-platform, unit-testable heart of `mvm-builderd`: a stateless `dispatch(&BuilderRequest) -> BuilderResponse` (serves `Handshake` via version-negotiated `handshake_reply`, `Probe` echoing the op, and a no-op `CancelJob` ack; the recognized-but-unimplemented build ops — `FlakeCheck`/`BuildGuestImage`/`BuildHostTool`/`PrefetchSource`/`QueryStorePath` — fail closed with the new `FailureCategory::Unsupported`, an honest typed "this daemon build does not implement that op" rather than a hang) and a `serve_connection(&mut UnixStream)` read-dispatch-write loop over the 256 KiB `mvm_guest::vsock` framing that returns `Ok` on clean EOF. Driven from `UnixStream` pairs in 9 tests (handshake accept/refuse, probe echo, cancel ack, all unimplemented ops → `Unsupported`, multi-request-then-EOF, immediate-EOF). The bin entrypoint + Linux AF_VSOCK listener are deferred to land with the builder-VM boot wiring (a listener with no boot path is untestable dead code). `FailureCategory` gained an `Unsupported` variant (pre-release, no back-compat). clippy `-D warnings` + fmt + `check-no-spec-refs-in-comments` clean.

**Additional 2026-06-19 — Plan 204 WS-A doctor readiness visibility:** the host gets a readiness probe and a `mvmctl doctor` line. `mvm_build::builderd` adds `probe_builderd_readiness(socket_path, timeout)` — connect + typed `Handshake` → `BuilderdReadiness::{Ready{version},VersionMismatch,NotRunning,Unreachable}` — plus `readiness_summary` and `builderd_control_socket_path(vm_state_dir)` (mirrors `persistent_builder::dispatch_socket_path` on the new `mvm_guest::builder_agent::BUILDERD_CONTROL_PORT` = 21473). `mvmctl doctor` gained an informational `builder daemon` platform check (`builderd_daemon_summary`/`builderd_daemon_check`) that scans the persistent builder-VM `~/.cache/mvm/builder-vm/vms/` root and probes each present control socket with a 300 ms bounded handshake; it is always `ok` (an absent socket is the normal "builder VM down" first-run state, mirroring the Plan 202 `host-agent daemon` check). The probe + summary + doctor scan are tested end-to-end against a real `UnixListener` driving `serve_connection` (no VM boot), with a NotRunning/empty-root path and an `Unsupported`-not-applicable stale-socket arm. This probe leg also lands the first piece of WS-B (host client). `tempfile` added to `mvm-build` dev-deps for the listener-path tests. 43 builderd tests across mvm-build + mvm-cli; clippy `-D warnings` + fmt + `check-no-spec-refs-in-comments` clean.

**Additional 2026-06-19 — Plan 204 WS-B host client:** `mvm_build::builderd_client::BuilderdClient` is the host-side counterpart to the daemon core. `connect(socket, timeout)` reuses the now-factored-out `connect_with_timeout` + `perform_handshake` (the readiness probe was refactored onto the same shared helpers — `HandshakeOutcome` is interpreted in exactly one place). `run_operation(request, sink)` is one-operation-per-connection: it writes the typed request, correlates every response frame to the request's `OperationId` (a mismatched or out-of-band frame is a `Protocol` error), streams `OperationEvent::{Progress,Log}` to the caller sink, and returns a typed `OperationOutcome::{Artifact,StorePath,Failed,Cancelled}`. Errors are the typed `BuilderdClientError::{NotReady,VersionMismatch,Transport,Timeout,Protocol}` — a read timeout before the terminal frame maps to `Timeout`, a missing/refused socket to `NotReady`. `request_cancel(op)` writes a `CancelJob`; the `Cancelled` terminal flows back through `run_operation` (full mid-flight async cancellation from a second handle is a transport concern that lands with the listener). The client is transport-only: it starts/stops no VM and does no git, so the lifecycle/data-dir-isolation and git-host-side WS-B boxes stay open for the lifecycle owner. 11 client tests (every streamed/terminal/error path via `UnixStream` pairs + a live integration against the real `serve_connection`), 51 builderd tests in mvm-build, full mvm-build suite 614 green; clippy `-D warnings` + fmt + `check-no-spec-refs-in-comments` clean.

**Additional 2026-06-19 — Plan 204 WS-C FlakeCheck core + WS-A §5 structural gate:** the first typed Nix operation and the guest-image trust-boundary gate. WS-C: `mvm_build::builderd` gains `flake_check_argv` (`nix flake check --no-build path:<flake>`), `flake_check_outcome` (clean exit → the new `BuilderResponse::Completed` terminal; non-zero → `FailureCategory::NixEval`; spawn error → retryable `Internal`), an injectable `OpExecutor` trait (`CommandExecutor` for the daemon; fakes for tests), `dispatch_flake_check` / `dispatch_with_executor`, and `serve_connection_with_executor` so the daemon serve loop actually runs the op. The protocol grew `BuilderResponse::Completed` (ops that pass without an artifact/store path) and the client grew `OperationOutcome::Completed`; both pre-release, no back-compat. The real in-VM `nix` execution is boot-gated, but every code path around it (argv shape, all classification arms, routing, over-the-wire serve) is unit-tested. WS-A §5: `xtask check-guest-images-no-builder-tools` — a comment-stripping source-grep over `nix/lib/mk-guest.nix` asserting the workload/dev image builder bakes neither `mvmctl` nor `mvm-builderd` (source-grep not a build, mirroring `check-guest-agent-in-all-images`; `mvm-host-vm-init` excluded since the builder-VM image injects it via mkGuest's generic `extraFiles`). Wired into the `ci.yml` Lint job. 60 builderd tests in mvm-build + 2 xtask stripper tests; the full mvm-build suite + xtask gates green; clippy `-D warnings` + fmt + `check-no-spec-refs-in-comments` clean. The remaining `mvm-builderd` bin + AF_VSOCK listener + rootfs baking + boot launch + lifecycle owner are one boot-gated on-box slice: the `mvm-build` lib pulls `reqwest`/`tokio`, so the bin must `#[path]`-include the daemon modules and musl-cross-compile (the established builder-bin pattern), none of which is verifiable from a non-Linux host.


**Additional 2026-06-15 planning rollup:** Plan 200 de-duplication pass completed — Plans 199/200 are the priority product path; Plan 200 maps ownership against Plans 114/125/126/136/155/156/159/189/193/197/198 so `machine` owns beginner UX, Plan 199 owns install/host packaging, Plan 126/156 own dependency and binary-size mechanics, Plan 155 owns low-level artifact execution, Plan 159/189 stay VZ-specific, Plan 193/197 stay security substrate, and Plan 198 is completed perf input. Plan 200 also records binary-first install, optional source-built Nix, current image-backed one-shot docs before flakes/manifests, future `mvmctl machine`, local image sources, scenario-led beginner docs, explicit limitations docs, verified portable artifacts, measured hot-start claims, no crate-count reduction across security boundaries, `mvm.toml` schema v1 with `image`/`flake` mutual exclusion and strict default-deny network/auth/volume rules, managed macOS virtualization as the safer default, custom kernels as signed runtime/artifact payloads, SDKs mirroring the CLI without bypassing admission/audit, and dependency weight as a first-class DX/security goal measured by default binary closure. Plan 199 Workstream A is complete: source-built Nix `mvmctl` package + host overlay, project-release binary download refused by tests, native libkrun linkage explicit/opt-in, and host Nix remains optional. Plan 201 adds a proposed WarmLease borrow-handle + batched guest exec docs-only workstream over the standby pool and agent-RPC, with no new backend/transport or admission/audit changes.

**Additional 2026-06-16 security rollup:** Template-identifier path-traversal hardening from the prior-art audit note is complete. Legacy `template_load` now validates template names before any `template_spec_path` read, legacy `template_create` validates before writing through `template_dir` / `template_spec_path`, and `manifest export-oci` validates the legacy-name fallback before dispatch so traversal input fails as an invalid template name rather than a file-existence oracle. Regression coverage pins traversal rejection, valid legacy-name load, write-side rejection before directory creation, and 64-char slot-hash dispatch through the manifest-slot path.

**Additional 2026-06-16 — Plan 202 (ADR-084) proposed, merged #977:** grounding the first live in-guest `host.audit.v1` round-trip (Plan 125 E5.3b-4 — in-guest `audit-probe` proven on libkrun, #973) surfaced that the shipped broker/audit-signer model forks two host subprocesses *per VM* and couples `host.audit.v1` availability to `MVM_GATEWAY_BRIDGE`. ADR-084 + Plan 202 re-architect this to two long-lived **per-tenant** daemons (register/deregister, `O(active tenants)` not `O(VMs)`, moat + claims 12/13 preserved, guest wire unchanged, mvmd consumes the same daemon). The vz broker-socket bug found alongside it landed as #971. Plan 202 is proposed/not-started; Phase-1 kickoff prompt committed.

**Additional 2026-06-17 — Plan 202 Phase 3c landed:** `mvmctl doctor` now reports per-tenant host-agent daemon state as an informational platform check. It enumerates `<MVM_DATA_DIR>/host-agent/<tenant>/`, reports warm daemons from live `daemon.pid` + `control.sock`, flags stale pid/socket artifacts, and treats first-run absence as non-blocking. Phase 1 (broker daemon/control plane), Phase 2 (signer-helper daemonization), Phase 3a (daemon default-on), Phase 3b (`O(active tenants)` cost framing), and Phase 3c (doctor daemon-state reporting) are landed; vz live-verify landed 2026-06-18.

**Additional 2026-06-17 — Plan 202 Phase 2a/2b landed:** the resident per-tenant signer-helper path is in place. `mvm-signer-helper` runs as a child of `mvm-host-agent`, owns `vm_id → Chain` workload-audit heads, opens/closes per-VM chains on register/deregister, and receives only the tenant key path from the keyless host-agent. The shared helper wire (`register_vm` / `deregister_vm` / `append_entry` / `probe`), host-agent audit forwarding by server-derived `vm_id`, and cross-VM chain isolation tests landed; remaining Phase 2 work after 2c is restart/head rebuild.

**Additional 2026-06-17 — Plan 202 Phase 4a landed:** the host-agent daemon now has durable registration recovery. It snapshots the live registration set to `<MVM_DATA_DIR>/host-agent/<tenant>/registrations.json`, removes entries on deregister, and restores by replaying registrations after signer-helper readiness. Focused tests pin stable snapshot order, deregister cleanup, and daemon restart rebinding a journaled socket.

**Additional 2026-06-17 — Plan 202 Phase 4b landed:** `mvm-host-agent` now runs under a supervising wrapper that restarts a crashed local daemon worker, reuses the Phase 4a registration journal to restore still-running VM registrations, and keeps crash-mid-flight semantics bounded: at most the in-flight `host.audit.v1` call is lost, and the workload chain remains append-only and verifies clean. Focused tests cover worker restart, wrapper restart via `ensure_host_agent_daemon`, and crash recovery during dispatch.

**Additional 2026-06-18 — Plan 202 Phase 5 started in mvmd:** mvmd Plan 52 now consumes the Plan 202 daemon surface for the first fleet slice: one resident host-agent/signer-helper unit per tenant, VM register/deregister from instance lifecycle, Firecracker `uds_path_PORT` broker binding, agent startup recovery from `host-agent.tenant` markers, and path-safe tenant/pool/instance validation before any marker-derived daemon/control registration. The rollup keeps Phase 5 open because per-tenant key-boundary tests, cross-tenant reach/forge proof, and the fleet density check are still outstanding.

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
- [x] **PLAN 118** — Supervisor standby pool · ✅ **DONE** (saved-standby warm pool live-validated + self-replenish #840 + overshoot flock closed; density/concurrent-launch schemas, platform footprint accessors, `bench microvm-density`, and `bench microvm-launch --concurrency` landed; **default-path Vz warm-claim fixed #1112 / #1101**; **Firecracker standby pool live-validated 2026-06-20** with warm-spawn → claim → replenish and `--up-json` returning the claimed standby id; Firecracker launch/concurrency/density proof JSON and gated reruns live under `specs/perf/plan-118/`; guest-agent-ready probes write BootTiming sidecars; Vz serial/concurrency/density bench lane is implemented and compiled; mvmd `desired_counts.warm` sizing lives in companion branch `feat/plan-118-sizing`; final aggregate `cargo test --workspace --no-fail-fast`, workspace clippy, and fmt gates are green).
- [x] **PLAN 159** — vz-inspired macOS VZ DX · ✅ **DONE** — VZ/macOS scope shipped (warm pool, checkpoint/fork/diff, two-copy + instant memory fork, live Vz validation); non-VZ residuals closed by scope decision: verb/install/product polish rehomed to Plan 181 / Plan 200, signed delta-image distribution descoped until a future artifact/distribution plan owns it
- [x] **PLAN 123** — Network / storage / warm-start · ✅ **DONE** — Phase A/B done; C1/C4 done; C3 (Vz save/restore) MET via 159 WS-2; the lone residual, C2 (FC live-memory), is carved to **Plan 175** (live-KVM-gated), not a 123 box
- [x] **PLAN 124** — Lean guest agent · ✅ **core complete** — full D1.2 RPC thread landed (stubs + check-stubs gate + 2a contract + 2b client + 2c adoption); D1.3 SDK veneer → Plan 125; Phase E signed config-on-device DESCOPED (baked + verity-sealed, no vsock round-trip); the residual KVM-live-verity / libkrun-Vz overlay-attach / no_std items are explicit **own-efforts**, rehomed out of 124 scope
- [x] **PLAN 125** — CLI surface + SDK DX veneer · ✅ **CLOSED / rehomed** — Phases B/C/D shipped in both SDKs; Phase A closed as "grouped surface + deliberate conveniences"; Phase E shipped `--secret NAME:host`, decorator coherence, doctor backend matrix, named security profiles, guest broker transport, typed `host.audit.v1` / `host.time.v1` / `host.cost.v1` clients, Python/TypeScript cdylib shims, host-spine coverage, and libkrun live `host.audit.v1` proof. The remaining host-services daemon/process-model work is explicitly **Plan 202** (per-tenant daemon, signer-helper admission signing, restart/head rebuild, mvmd adoption, and retirement of `spawn_broker_services_if_admitted`), not Plan 125.
- [~] **PLAN 126** — Dependency reduction · 🟢 mvm-side default-closure cuts/gates measured and landed; `sigstore`/`opendal`/`pgp` are out of the default closure, D1 forbidden-dep gate and D2 duplicate-major ratchet are live, and `dep-baseline.md` has the final measure. **Step-0 decision made 2026-06-20: the `aws-lc-rs` removal + `reqwest`/`oci-client` major-unify (B4 + C1) are rehomed to the dependency roadmap, not closed in this refactor cycle.** Rationale: `aws-lc-rs` enters *solely* via `oci-client → reqwest 0.13` (mvm's own reqwest 0.12 is already ring); `oci-client` 0.16 **and** 0.17 hardcode the aws-lc provider in their only rustls option with no ring/no-provider feature, so removal needs a feature on `oci-client` itself, not a config change. That feature is now filed upstream as **[oras-project/rust-oci-client#274](https://github.com/oras-project/rust-oci-client/pull/274)** (`rustls-tls-no-provider` = `reqwest/rustls-no-provider` + `jsonwebtoken/rust_crypto`); validated against upstream `main` that it drops `aws-lc-rs` from the tree (`cargo tree -i aws-lc-rs` empty, builds clean — `rustls-platform-verifier` is provider-agnostic and does *not* re-drag aws-lc). Rehomed rather than carried as a fork. **Bridge spike (2026-06-20) found B4 is bigger than a bump + flip:** a full in-tree `[patch.crates-io]` to the proven fork *does* remove `aws-lc-rs` + its C/cmake build (workspace `cargo tree -i aws-lc-rs` empty, mvm-oci builds + 96 tests green after a ring-provider install in `new_client`), **but** the aws-lc-free path (`jsonwebtoken/rust_crypto`) pulls the **RustCrypto 0.11 line** (`sha2`/`digest`/`block-buffer`/`crypto-common`/`const-oid`), duplicating the workspace's pinned **0.10** stack and tripping the **D2 duplicate-major ratchet**. This is not bridge-specific — `oci-client` 0.17 uses `jsonwebtoken` 10.x, so the *released* post-#274 version drags the same split. So completing B4 additionally needs a **workspace-wide RustCrypto 0.10→0.11 migration** (or accepting/skipping 5 duplicate majors) — landing a dependency-*reduction* PR that adds 5 duplicate majors would be self-defeating, so the bridge was abandoned. **Feasibility checked 2026-06-20: that migration is itself blocked upstream** — `aes-gcm` (AEAD for snapshot/secret_store) and `ed25519-dalek` (host signer / audit chain / attestation) have **no stable** digest-0.11 release, only RCs (`aes-gcm 0.11.0-rc.4`, `ed25519-dalek 3.0.0-rc.1`); `sha2`/`hmac`/`hkdf`/`aead`/`cipher` are stable on the new line but a partial migration just recreates the split. RC crypto is a non-starter under ADR-002, so **B4 is gated on upstream stable `aes-gcm 0.11` + `ed25519-dalek 3.0`** (revisit trigger). The D1/D2 gates keep the regression closed meanwhile. Refactor-close is **no longer gated** on this item.
- [x] **PLAN 177** — Backend consolidation (8→4) · ✅ both phases merged (#806/#789/#812/#814/#817); DX-parity → Plan 189; lone caveat = host-gated hardware smoke
- [x] **PLAN 182** — Trait hygiene + backend catalog · ✅ DONE — Clock/KeyProvider unified, `backend_catalog!` single-source, doctor sourced from it, arch docs current (all via #802). The lone open box (literal `cargo test --workspace`) is closed as documented-environmental: package-by-package + `-E 'not package(mvm-backend)'` are green; the aggregate only SIGKILLs the `mvm-backend` unit-test bin via macOS amfid codesign on this host (CI runs it green)
- [x] **PLAN 184** — Backend descriptor registry · ✅ DONE — catalog promoted to a `BackendDescriptor` registry (descriptor-named helpers); dual `instantiate`/`instantiate_dyn` constructors with dyn↔enum parity test; doctor migrated to `instantiate_dyn`; `AnyBackend` narrowed to enum-specific ops (no duplication remained); boundary + ordering-freeze tests; arch/supervisor docs describe the behavior/discovery/dispatch split
- [x] **PLAN 185** — Idiomatic Rust hygiene audit · ✅ COMPLETE (Phases 1–7, all tasks closed): Phase 1 TestEnv migration (mvm-core/mvm-hostd/mvm-build/libkrun-sys/**mvm-cli complete** — duplicate local env-test locks deleted; only host-gated mvm-backend env tests remain for CI/Linux); Phase 2 poison-lock policy decided + applied (env serializers folded into TestEnv, runtime state locks fail-closed); Phase 3 naming/typed-selectors COMPLETE (#892 `DeviceMapperBackend` + #894 `VmEgressProxy`/`SupervisorEgressProxy` + #895 typed `BackendKind` selectors). Phase 5 Task 8 DONE (SAFETY invariants on the 12 simple-syscall mvm-guest blocks; `mvm-verity-init` dm-verity bin done — 13 blocks annotated + fixed-payload ioctls isolated behind a safe `dm_ioctl_fixed` wrapper with a `const _` size assertion; `mvm-guest/console.rs` done — every unsafe block annotated + the post-fork `putenv`/`execvp` malloc path replaced with a pre-built `execve` since the agent is multithreaded at console-fork time; `mvm-guest-agent` bin done — four remaining close/signal-test blocks annotated; `vz_objc.rs` objc2 cluster done #976 — every unsafe block now annotated). Phase 5 Task 9 DONE-by-verification (test-support dev-only + optional stacks gated/documented, check-core-runtime-free enforced). Phase 4 Task 6 DONE — every hand-written `#[allow(clippy::too_many_arguments)]` eliminated: `boot_builder_vsock` → `BuilderVsockBoot` (#920); the two claim-12 paths → builders, bodies byte-preserved via top-of-fn destructure (`sign_into_headers` → `SignRequest` #926, `terminate_and_substitute` → `TlsTermination` #927); and the `compile_error!`-confirmed dead FC instance/pool/tenant cluster (`vm/instance|pool|tenant`, `bridge.rs`, `disk_manager.rs`) deleted with `security/jailer.rs` trimmed to its live `jailer_available()` probe (#931, ~3.8k lines, last allow removed by deletion). No hand-written `too_many_arguments` allow left (only bindgen FFI). Phase 6 STARTED — Task 13 doc-gen run: the Phase 3 renames introduced **zero** broken intra-doc links (verified), but the run surfaced ~115 *pre-existing* broken intra-doc links across every crate; `mvm-core` cleared (16 sites, #939) + `mvm-build` unconditional path bugs fixed (45→32 under `--all-features`, #941). **Refined Task 13 finding:** the doc-link count is feature/platform-sensitive — many targets are `#[cfg(feature)]` modules (need `--all-features`) and a cluster is `#[cfg(target_os="linux")]` builder-VM bins that resolve only on a Linux doc build (backticking them would degrade valid Linux docs), so the Phase 7 doc gate must run on **Linux + `--all-features`, per-crate**; only links broken there are real bugs. Task 12 (secret/debug exposure) DONE (#943) — audit clean (gate + `SecretBox` + zeroize + redacting Debug already cover it; field-sweep found no unprotected types), closed the Step 3 gap with negative redaction tests for `HostSigner`/`ResolvedBinding`/`EgressCa`. Task 10 (typed errors in tests) DONE-by-audit — surface is tiny: typed-error paths already use `matches!`, the rest is `anyhow`/`serde` string-matches where the string is the only handle; converted the one genuine candidate (`load_master_key` now downcasts to `RotationError::KeyFilePerms` + matches the structured `mode`). Task 11 (fixture consolidation) DONE (#953) — six near-identical minimal `ExecutionPlan` fixtures collapsed into a shared `mvm_core::plan::test_support::PlanFixture` builder (cfg/test-support-gated, no new deps), the mvm-hostd audit cluster migrated to thin wrappers, net −156 lines + 2 builder unit tests. **Phase 6 Tasks 10/11/12 + Task 13 (mvm-core, mvm-build) done.** Phase 7 closeout VALIDATED on the x86_64 Linux box: `cargo test --workspace` green — 3720+ tests across the heavy crates alone (mvm-core 1244, mvm-hostd 962, **mvm-backend 914** — the latter SIGKILLs under macOS amfid, so Linux is the only place it runs) + the rest, **zero genuine failures**. The Linux run surfaced + fixed a real test-isolation bug (`mvm-host-vm-init` leaked a non-existent `TMPDIR` to 15 parallel tests; `cfg(linux)` so macOS never ran it — `TestEnv`-fixed, #960, 151/151); the only other non-green is `each_embedded_binary_starts_with_elf_magic` which fails by design under `MVM_SKIP_EMBED_BINARIES=1` (stub payloads). clippy green in the required macOS CI env (all 185 changes). **`cargo doc --workspace --all-features --no-deps` now GREEN on Linux** under `-D rustdoc::broken_intra_doc_links` — all **122** pre-existing broken intra-doc links fixed (mvm-core/mvm-build via #939/#941, then the full sweep across every crate + xtask on `docs/plan-185-task13-doclinks`; backticked `<placeholder>`/literal-bracket prose, private/method/cross-crate refs, and module-doc `//!` overview lists; valid `///` item links preserved). **Task 13 DONE.** The pre-existing Linux-only `mvm-host-vm-init` clippy lints (12: `doc_lazy_continuation` + empty-line-after-doc + collapsible if-let) are also **fixed** — the `ci-full` `clippy -p mvm-build -p mvm-backend --all-targets` Linux lane is green on the box (no cascade). **Task 8 (`vz_objc.rs` objc2 SAFETY audit) DONE (#976)** — the ~16 gap SAFETY notes filled citing the serial-dispatch-queue / single-guest invariant (the file already had 89 + uses typed objc2); comment-only, verified on macOS arm64 (the only host that compiles it). **PLAN 185 COMPLETE — all phases and tasks closed, no remaining deferrals.**
- [x] **PLAN 189** — VZ DX parity (post-convergence) · ✅ COMPLETE — WS-1 `vm save`/`vm restore` aliases landed (#1118) over the `vm-full` checkpoint and are Vz `save-restore`-tier-gated; WS-3 `dev status/down/up --json`, checkpoint/snapshot JSON, structured-stdout hardening, Vz dev-shell data-port reachability, source-checkout Vz helper freshness, and linux-native typed JSON detail landed; WS-4 base-ref design, Vz `dev up --base` artifact resolution, and pinned-base rootfs fingerprint proof surface landed. Post-Plan macOS-26 timing/content evidence is tracked as shared Vz live validation, not Plan 189 scope.
- [x] **PLAN 175** — Firecracker live-memory warm-start · ✅ **CORE COMPLETE** — T1 (#1150) + T4 (#1155) merged + live-proven on KVM (cold-boot → pause-seal → `vm resume --warm` fresh-FC `/snapshot/load` 204/~0.5s, agent reachable, `WARM_RC=0`; reseed *dispatch* unit-proven but live token *delivery* raced the agent-ready window → Plan 206 polish), T3 barrier protocol (#1165); UFFD ~1s perf-substrate (T2) + primed-barrier live wiring (T3-S2) **rehomed → Plan 206**
- [ ] **PLAN 206** — FC warm-start UFFD substrate + primed-barrier wiring · 🟡 on-host slices landed; UFFD + live-KVM tail remains — Task 2 (primed barrier) host+guest wiring DONE & unit-tested (`PrimedStatus` RPC + `/run/mvm/primed` marker + `VsockPrimedSignalSource` + `vm pause --primed-barrier`, fail-closed); Task 3 honest-verb DONE (`ReseedStatus`/`WarmStartOutcome` threaded; verb prints real reseed outcome) + agent-ready wait widened 30→60s; remaining = Task 1 UFFD/NBD/hugepages substrate + all live-KVM proofs
- [x] **PLAN 183** — Builder-VM egress posture + network bootstrap · ✅ (E2E-proven 2026-06-12; Vz checkpoint-integration follow-ups tracked in the plan)
- [x] **PLAN 180** — Strip spec refs from code comments · ✅ (lint-gated, #786)
- [x] **PLAN 188** — Capability projection seam (ADR-080 P5) · ✅ LANDED (#801); kernel-side wiring spec'd as Plan 190; WASI-context mapping deferred
- [x] **PLAN 186** — Trace hardening (ADR-080 P1/P3/P4 + hardened P2 pin) · ✅ LANDED (#809; caught + fixed a live shell-injection in the FilesWrite lowering)
- [x] **PLAN 187** — Secret-scan admission gate (ADR-080 P7) · ✅ LANDED (#811)
- [x] **PLAN 190** — Kernel egress decision converges on CanonicalEgress (ADR-080 P5 close-out) · 🟢 LANDED (kernel leg; lenient L4 lowering; zero claim-10 behaviour change; WASI-context mapping deferred to runner plan)
- [x] **PLAN 191** — Declarative file materialization (ADR-080 P2-full) · 🟢 P2-full LANDED (FilesWrite lowers to the declarative `App.files` IR field, baked into the rootfs at build time via `mkFunctionService` `extraFiles`; the `before_start` shell hook is removed — file content/paths never reach a guest shell)
- [x] **PLAN 192** — WASI capability projection (fs/env, ADR-081 A1) · ✅ LANDED — `mvm-core::policy::projection_fs_env` (`CanonicalFs`/`CanonicalEnv`, traversal-refusing canonicalizers, intersection-only `clamp_fs`/`clamp_env`, backend-agnostic WASI preopen/env-name shapes) + `WasiCapPolicy` bound on `EffectivePolicy` + 2 clamp-never-widens property witnesses; no new deps, runtime-free gate green. A2 (`.wasm` admission) + A3 (guest runner) are follow-on plans
- [ ] **PLAN 193** — rvproxy network substrate (replace gvproxy/passt) · 🟡 in progress — WS-1 transport proven; WS-1.5 parity scaffold + CI lane live; rvproxy R2 shipped; mvm-side native config emission/launch, native flow-audit refeed, and binary-discriminating native enforcement witnesses are landed. Current cleanup removed the dead `BridgeConfig.policy` / production `AllowAll` open-policy slot so the bridge has one live source of enforcement (`bundle` or threaded `NetworkPolicy`, otherwise fail-closed deny-all), macOS/libkrun now selects native by default when `MVM_GATEWAY_BIN` names the rvproxy candidate while preserving gvproxy/no-candidate fallbacks, admitted libkrun/Vz workload starts already thread the signed plan by default, the transparent terminator requirement is explicit as a tested workload-backend deletion guard, and the parity workflow's stable `rvproxy gateway parity` job is required in branch protection on PR and merge-group SHAs. Remaining: rvproxy transparent-terminator schema/support, mvm config/wiring once that exists, then delete the splice + Plan-141 `on_packet` hooks.
- [x] **PLAN 195** — Builder-VM fingerprint narrowing · ✅ COMPLETE — the redundant whole-workspace `Cargo.lock` is out of `builder_vm_source_fingerprint` (builder-VM flake forbids `buildRustPackage`; embedded host-bin byte hashes are authoritative for baked Rust), and `mvm-cli/build.rs` now watches `Cargo.lock` + `crates/mvm-build/src` so L3 reflects dependency/lib changes. Build-perf only, no claim impact. Verified with focused fingerprint tests, real non-stub embedded-binary build, rerun-trigger proof, full `mvm-cli` nextest, clippy, and fmt; live `dev up` manual not re-run due the builder-VM runtime-command boundary.
- [x] **PLAN 197** — `WorkloadBackend` type-bar (core security features non-skippable) · ✅ **mvm-side DONE** — Phase 1 MERGED (#860); Phase 2a (vsock substitution channel) MERGED (#866) + **default-path plan-persist gap closed (#909)** so the substitution endpoint now actually spawns on a plain `up`/`invoke --hypervisor vz`/`libkrun` with secrets (no `MVM_GATEWAY_BRIDGE` needed) — **vz DATA PLANE PROVEN LIVE 2026-06-15** (driver `up --name -d` → `vm wait` → `invoke --attach`: httpbin reflects the real cred, guest holds only the placeholder, claim 12 refuses a non-allowed host, 6 dials prove the 5253 listener re-accepts; no code change). Phase 2a COMPLETE on vz. The lone residual, 2b (transparent :80/:443 terminator), is rehomed to **Plan 193/rvproxy** (cross-repo gate — macOS has no nft, so it can only live in the gateway); not a Plan 197 mvm-scope box. Marker trait gates the admitted launch path so qemu (a real dev/test VMM) is type-barred and a new backend can't reach the funnel without the shared enforcement (mock is permitted as the ADR-045 hermetic test double — carries no real workload). Arose from the Sprint 55 vz closeout finding.
- [x] **PLAN 199** — Host runtime packaging + crate boundaries · ✅ COMPLETE — source-built optional host `mvmctl`, host overlay, release-install policy/matrix/signature CI, crate-boundary audit, pinned source-built native VMM recipes (`libkrunfw`/`libkrun`), opt-in `mvmctl-native-libkrun`, and builder-VM `nix flake check` / `.#mvmctl` / `.#mvmctl-native-libkrun` verification are done. Signed binary install remains primary; source-checkout Nix never fetches mvm release binaries; microVM guest images do not install `mvmctl`.
- [ ] **PLAN 200** — Machine UX/DX layer · 🟢 in progress — `machine run` shipped (#968); Session 3 item 1 `run --image <oci>` boots end-to-end (#1036: injected static guest agent/netinit + honest `overlay_aware` sidecar + vz ext4-geometry fix, live-verified macOS-26/vz); WS-B `--net`/`--allow-host` uniform FC/libkrun/Vz egress enforcement **MERGED (#1003)** with follow-ups through #1034 closed (MCP admitted, BridgeConfig.policy/AllowAll removed, uniform bare host:port L4, DHCP/ARP loopback-only posture, transient eth0 enabler, and `up` direct-boot network-policy threading). Persistent spec substrate and lifecycle wrappers landed (`machine create` / `start` / `exec` / `shell` / `stop` / `ls` / `inspect` / `rm --yes`, strict JSON under `<MVM_DATA_DIR>/machines/<name>/machine.json`, existing admitted launch/attach/down paths), image-backed `mvm.toml` / `Mvmfile.toml` manifests now map into durable specs and admitted starts (`net`, allow-hosts, CPU/memory, `mem_initial`, volumes, dev init, ssh-agent), persistent image-backed `start` works, dev-tier persistent-machine `ssh_agent` socket forwarding is implemented without key-file mounting, signed-plan auth metadata is explicit in `ExecutionPlan.auth.mode` plus admitted audit labels, and Python/TypeScript/Rust SDK machine lifecycle wrappers now shell only to `mvmctl machine ...` with structured errors and fake-CLI lifecycle coverage. Rust/Python/TypeScript SDK -> CLI parser/preflight proof covers dry-run receipt posture for default-deny/`--allow-host`, richer admission/receipt inputs, and strict-manifest unknown-key rejection through shared fixtures. Portable `.mvm` preview now has a verified-admission gate: `machine check-artifact` returns admission only after signature/hash/format verification and host-arch acceptance, with wrong-key/tamper/arch refusal tests. Remaining: live SSH-agent smoke, SDK/live non-bypass proof, scenario/limitations docs, live `machine run <artifact>` / `machine pack` workflow, measured hot-start latency/smokes, and duplicate-major/binary-size budgets.
- [~] **PLAN 201** — `WarmLease` borrow-handle + batched guest exec · 🟡 in progress — DX-ergonomics layer over the Plan 118 standby pool + Plan 169 agent-RPC: RAII claim/release that stops + replenishes a fresh standby, plus staged batched guest exec. Caller-convenience only; no new backend/transport, admission + audit untouched. **WS-A `WarmLease` landed** (`crates/mvm/src/vm/lease.rs`): `acquire` (claim a compatible idle standby via `select_idle_compatible`/`mark_claimed`/`claim_standby`/`remove`, else cold-boot fallback) + `id()`/`transport()`/`release()`/`Drop`; replenish is an injected `ReplenishFn` (no upward dep on the CLI's `pool warm`); release/Drop of a claimed lease stops + replenishes, a cold-boot lease only stops; `MockBackend` gained opt-in `with_standby` + `with_failing_stop` test knobs; 4 mock-backend tests (no live boot). **WS-B `ExecBuilder` Tier 1 + WS-C `ExecOutcome` landed** (`crates/mvm/src/vm/exec_builder.rs`): `WarmLease::exec()` → `ExecBuilder` (`stage_file`/`argv`/`chain`/`timeout`/`output`/`run_entrypoint`) pipelines `FsWrite` staging then the `Exec`/`RunEntrypoint` frame(s) over **one** stream via `call_unary`/`call_streaming` (reusing the mvm-guest host plumbing, no upward dep); `ExecOutcome { status, stdout, stderr, duration, peak_rss_kib }` (duration host-measured; peak_rss arrives with Tier 2); `mock_guest_agent` gained `Exec`/`RunEntrypoint` handlers; 4 tests. **WS-E re-export landed** (`mvm` root re-exports `WarmLease`/`AcquireSpec`/`ExecBuilder`/`ExecOutcome`). **WS-D `ExecBatch` Tier 2 landed**: `GuestRequest::ExecBatch {stages, commands, timeout_secs}` + unary `ExecBatchResult {outcomes}` carrying agent-measured `ExecOutcomeWire {status, stdout, stderr, duration_ms, peak_rss_kib}` (`deny_unknown_fields`); in-guest `do_exec_batch` (stage→`stream_exec` buffered, stop-on-first-failure, `getrusage` peak_rss), `dev-shell`-gated so the prod agent ships the not-feature arm (prod-no-default build + `check-prod-agent-no-exec/-console` green); `fuzz_guest_request` (serde-based) auto-covers it; host `ExecBuilder::batch()` maps it to `Vec<ExecOutcome>`; mock answers per-command; 4 tests. **Plan 201 is functionally complete** — only the optional WS-E `verification_loop` example remains (a live-host demo, deferred).
- [x] **PLAN 202** — Host services daemon (per-tenant, not per-VM spawn) · ✅ COMPLETE ([ADR-084](adrs/084-host-services-daemon-not-per-vm-spawn.md), #977; mvmd #162) — re-architected the broker/audit-signer from the shipped per-VM subprocess fork (Plan 125 E5.3b — `2N` processes + a per-boot spawn, availability coupled to `MVM_GATEWAY_BRIDGE`) to **two long-lived per-tenant daemons** VMs register/deregister with: `O(active tenants)` processes not `O(VMs)`; the moat (keyless broker / key-holding signer) + claims 12/13 preserved; guest wire unchanged; registration driven by the admitted plan (decoupled from the egress bridge); mvmd consumes the same daemon per tenant. Local `mvm` landed Phases 1–4 and 6, including Vz live verification; mvmd PR #162 closed Phase 5 with per-tenant daemon lifecycle ownership, Firecracker broker substrate, the reusable delegated host-services route/authz surface, tenant-key/boundary proof, and density evidence. ADR-084 is accepted.
- [~] **PLAN 203** — Opt-in forensic network transcript capture · 🟡 in progress — request-only byte-exact network transcript capture for a specific tenant / VM / session. Keeps the default claim-10 posture metadata-only, then arms/disarms/export a separately encrypted transcript store at the host boundary for incident response and compliance evidence. **Slice-1 core landed** (`mvm_core::transcript`): sealed `TranscriptManifest` (+ `ChunkRecord`/`CaptureBinding`/`CaptureBounds`, serde `deny_unknown_fields`), `CaptureBudget::try_add` (fail-closed max-bytes/max-chunks before any payload lands), and `verify_chunks` (re-hash + unsafe-name/size/missing/tamper/format-version refusals); 9 unit tests. **Capture+encryption+export core landed** (`mvm_core::transcript::{TranscriptWriter, TranscriptWriterConfig, export}`): `push` budget-checks before writing, AEAD-encrypts each chunk at rest with the per-capture key (`crypto::aead::seal`, reused) recorded by ciphertext-sha256, `seal()` finalizes the manifest, `export()` runs `verify_chunks` then `aead::open` failing closed on wrong-key (`Decrypt`)/tamper (`HashMismatch`); 4 tests (round-trip/tamper/wrong-key/budget); `check-core-runtime-free` green. Remaining: the hostd capture sink + boundary tap that fans bridge bytes into the writer + the claim-gated lifecycle audit kinds (arm/seal/export/refusal); the `mvmctl audit transcript arm/disarm/list/export` CLI + per-capture key wrapping (host keypair). **Key-wrapping landed**: `aead::Key::{wrap_under,unwrap_under,persist,load}` (bytes stay encapsulated) + `transcript::{load_or_init_kek,wrap_data_key,unwrap_data_key}` manage a host KEK (`<keys_dir>/transcript-kek.bin`, 0600) and the manifest `wrapped_data_key_b64`; 5 tests incl. end-to-end wrap→capture→unwrap→export; `check-core-runtime-free` green. **CLI + lifecycle audit kinds landed**: `mvmctl trust audit transcript {arm,disarm,list,export}` (`commands/ops/transcript.rs`) — arm provisions a capture (key wrapped under the host KEK), list/disarm/export, export = unwrap→`transcript::export` failing closed on tamper/wrong-key; 4 new `LocalAuditKind` (`TranscriptArmed`/`Sealed`/`Exported`/`Refused`) emitted per step with `audit_total_coverage` updated in lockstep (`AUDIT_SUB`/`TRANSCRIPT_SUB`+`KNOWN_TOKENS`); captures under `mvm_transcripts_dir()`; 6 CLI tests. **Only remaining: the live byte-capture sink + bridge tap (`gateway_bridge::bridge_copy_bidirectional`) — live-only-testable.** Proposal doc: `specs/plans/203-forensic-network-transcript-capture.md`.
- [ ] **PLAN 204** — Builder VM resident control plane · 🟢 in progress ([ADR-089](adrs/089-builder-vm-resident-control-plane.md), #1082) — keep `mvmctl` as the single host UX, keep host Nix optional, and move builder execution behind a resident internal `mvm-builderd` service inside the builder VM over typed vsock requests. Stable API = allowlisted build/eval operations with structured progress/provenance; no user-facing builder shell; guest images do not include host/builder tools. **WS-A protocol pair landed**: `mvm_build::builderd_protocol` typed `BuilderRequest`/`BuilderResponse` allowlist (`Handshake`/`Probe`/`FlakeCheck`/`BuildGuestImage`/`BuildHostTool`/`PrefetchSource`/`QueryStorePath`/`CancelJob` → `Accepted`/`Progress`/`LogChunk`/`ArtifactReady`/`StorePathReady`/`Failed`/`Cancelled`), `OperationId`, stable `FailureCategory`, `deny_unknown_fields`/snake_case fail-closed wire reusing the 256 KiB vsock framing, plus `PROTOCOL_VERSION`/`negotiate()`/`handshake_reply()` version negotiation (26 tests). **WS-A daemon-core + doctor readiness landed**: `mvm_build::builderd` `dispatch()` (Handshake/Probe/CancelJob served; unimplemented build ops fail closed `Unsupported`) + `serve_connection()` framed loop, plus the host-side `probe_builderd_readiness`/`readiness_summary`/`builderd_control_socket_path` over `BUILDERD_CONTROL_PORT` 21473 and an informational `mvmctl doctor` "builder daemon" platform check that scans the builder-VM `vms/` root and probes each control socket (real-`UnixListener` end-to-end tests; 43 tests). **WS-B host client landed**: `mvm_build::builderd_client::BuilderdClient` (connect+handshake, one-operation-per-connection `run_operation` streaming `OperationEvent` to a sink → typed `OperationOutcome`, op-id correlation, typed `BuilderdClientError`, `request_cancel`; live integration against `serve_connection`). **WS-C FlakeCheck core + WS-A §5 structural gate landed**: `flake_check_argv`/`flake_check_outcome`/`OpExecutor`/`dispatch_with_executor`/`serve_connection_with_executor` + new `BuilderResponse::Completed` terminal (real `nix` exec boot-gated); `xtask check-guest-images-no-builder-tools` proves mkGuest bakes no `mvmctl`/`mvm-builderd` (CI-wired). 78 builderd-related tests. **WS-A boot wiring landed (code, CI-validated; one live boot check pending on-box)**: `[[bin]] mvm-builderd` (`#[path]`-included daemon modules + Linux AF_VSOCK accept loop on port 21473 → `serve_connection_with_executor(&CommandExecutor)`); embedded into the builder/dev rootfs at `/sbin/mvm-builderd` via `HOST_BINARIES` (manifest + nix attrset, sync gate green); `mvm-host-vm-init` `spawn_builderd()`s it at boot; persistent libkrun + Vz launchers forward vsock 21473 to `<vm_state_dir>/vsock-21473.sock` (the path doctor + the client use). Follow-up PR merged (#1091). **WS-C build-op handlers landed**: `nix_build_argv`/`dispatch_nix_build` (BuildGuestImage + BuildHostTool → `ArtifactReady` from the `--print-out-paths` store path; `NixBuild`/`Internal` failures), `prefetch_source_argv`/`dispatch_prefetch_source` (`StorePathReady` from `nix flake prefetch --json`; retryable `Fetch`), `query_store_path_argv`/`dispatch_query_store_path` (`StorePathReady`, `already_present = nix path-info exit==0`); `OpExecResult` gained `stdout`; all routed via `dispatch_with_executor`/`serve_connection_with_executor` (764 mvm-build tests, live `nix` exec boot-gated). Remaining: the live `dev up` → `doctor ready` → typed `FlakeCheck` on-box check; the **WS-D lifecycle owner is Plan 205 §C** (active in parallel — `feat/plan-205-ws-b-residency-policy` worktree), coordinate there. **WS-E docs (mostly landed):** `guides/builder-vm.md` gained a "Resident builder control plane" section (host control plane vs builder execution — `mvm-builderd` resident daemon, typed allowlisted vsock requests, no builder shell, guest images stay tool-free, host Nix optional, `mvmctl doctor` "builder daemon" readiness line) and `guides/troubleshooting.md` gained builder-daemon readiness/cancellation troubleshooting; the only remaining WS-E item is the `getting-started/installation.md` edit, deferred to the live Plan 200 docs session to avoid a collision.
- [x] **PLAN 205** — Resident builder control plane + residency model (umbrella) · ✅ COMPLETE ([ADR-090](adrs/090-resident-daemon-trust-gradient-and-residency.md)) — umbrella over Plans 118/152/159/196/202/204 that removes the per-session builder boot (top latency pain) without moving authority into a guest. **WS-A/B/D/F merged (#1090/#1094/#1099/#1103), E via #1102, C resident via Plan 204 #1091; builder-tier gate #1110; builder-residency Step 1/2 via #1114/#1121; gate cleanup via #1123.** The **three-daemon trust gradient** (host=keys/admission/audit TCB; builder `mvm-builderd`=dev-tier resident build-only; workload agent=prod-stripped runt) is machine-checked across all three tiers (`check-trust-gradient: clean (3 rows)`); the **residency slider** (`MVM_RESIDENCY` warm⇄parked, per-host default, doctor line) + parked-standby demotion are wired, `MVM_RESIDENCY=cold` forces the ephemeral builder path and tears down live persistent builders on the next invocation, the Vz dev-builder explicit park/restore plus auto-park-on-`dev down` path is wired, and the builder-residency decision core covers keeper actions plus builder snapshot freshness. The macOS/Vz evidence runner at `scripts/capture-plan-205-live-gates.sh` is green on the target host (`/tmp/mvm-plan205-live-proof9`, `passed=true`, zero command failures, final state `parked`, and live OCI `run --image docker.io/library/alpine:3.20 -- /bin/true` exit 0); FC live-memory remains delegated to Plan 175 and resident-daemon lifecycle refinements remain delegated to Plan 204.

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

PLAN 159 — vz-inspired macOS VZ DX               ✅ DONE
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
  [x] WS-5 D verb renames / curl|sh installer / product polish — rehomed to
      Plan 181 / Plan 200; no remaining Plan 159-owned implementation box.
  [x] signed delta-image distribution — descoped until a future
      artifact/distribution plan owns it.
  [x] live Vz WS-2 round-trip validation + fork semantic-A spike — RUN
      2026-06-12 via Plan 183 WS-D: first live Vz workload boot; vm_full
      create + pause/resume proven; semantic-A ANSWERED (VZ pins machine-state
      restore to the saved device config → stay semantic B; live two-copy fork
      goes through fs_quick). Vz checkpoint-integration gaps → Plan 183
      follow-ups.
  [x] instant memory fork: vm_full fork of a RUNNING parent → second live VM in
      0.91s incl. claim-8 admission (same-identity clone model; recorded-sha admission; gvproxy-only invariant) (#833)

PLAN 118 — Supervisor standby pool              🟡 pool done; FC baselines gated; Vz lane implemented
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
  [x] Plan 118 closeout cleanup: `pool status` now reports dead non-saved
      standbys separately instead of showing them as idle, while Vz saved-state
      standbys remain live without a pid; the libkrun supervisor audit-substrate
      signing-key prefix check already routes through `mvm_core::config::mvm_keys_dir()`
      so `MVM_DATA_DIR` isolation is honored.
  [x] Firecracker standby pool (the mvmd-facing deliverable) — live-validated on
      `rvproxy-firecracker` 2026-06-20: warm-spawn reserved the normal slot,
      claim configured the admitted launch shape, `InstanceStart` booted from
      the standby, `--up-json` returned the claimed standby id, and replenish
      restored target capacity.
  [x] Part C / PR-10c — density + concurrent-launch distribution bench (code/proof slice,
      added 2026-06-16). Extends Part A's probe to two new metrics: per-instance host
      footprint (`bench microvm-density`, platform-split PSS/phys_footprint accessor)
      and launch P50/P95/P99 under concurrency (`bench microvm-launch --concurrency N`).
      libkrun live-gated CLI wiring, platform accessors, concurrency orchestration,
      and cap tests are landed. Firecracker baselines are committed under
      `specs/perf/plan-118/` with `readiness_boundary=firecracker-pid`, the serial /
      concurrency / density baseline gates pass, and warm-pool launch is 49.48% faster
      than the gated cold run. Vz serial/concurrency/density harness lanes are
      implemented through the same admitted-plan flow with BootTiming sidecars and
      no-leak teardown assertions; live Vz artifacts remain host-gated. Read-only;
      every boot still goes through claim-8 admission (no bypass), no new
      key/daemon/socket, backend-gated → zero new attack surface. Closes the
      no-published-numbers gap surfaced by external prior art
      (`specs/notes/external-agent-sandbox-runtime-prior-art.md`); proves the warm pool's
      payoff for Firecracker. Inherits Part A's libkrun blocker only for a
      guest-agent-ready libkrun baseline image.

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

PLAN 175 — Firecracker live-memory warm-start    ✅ CORE COMPLETE — capability shipped + live-proven on KVM; UFFD perf-substrate tail rehomed → Plan 206 (Plan 123 C2 carve-out)
  [x] C4 warm-start CLI/RPC wiring — landed via T4 (FirecrackerBackend::warm_start + `mvmctl vm resume --warm`)
  [x] T1 VMGenID delivery on PostRestore — DONE #1150 (token payload + GenIdReseeder dispatch, both senders mint); live restore on KVM rotates the token
  [x] T4 FirecrackerBackend::warm_start + `mvmctl vm resume --warm` + unit gate — DONE #1155, live-proven (single clean run): cold-boot examples/sleeper under FC → vm pause seals 512MiB snapshot → warm path boots a FRESH VMM + PUT /snapshot/load (204/~0.5s) → agent reachable (vsock CONNECT 5252→OK) → WARM_RC=0. Token *delivery* is best-effort + raced the agent-ready window (reseed dispatch unit-proven; live reseed-through-warm → Plan 206 polish). Fixed 2 real bugs: fc.socket-vs-runtime/firecracker.socket path; load-into-fresh-VMM (FC 400s on the paused one). libkrun→typed Unsupported (unit). Cmd-injection in the load path fixed #1168.
  [x] T3 "primed" ready-barrier PROTOCOL — DONE #1165 (await_primed_barrier + PrimedSignalSource, fail-closed, unit-tested)
  [→] T2 UFFD/NBD/hugepages ~1s substrate + T3-S2 primed live wiring — REHOMED to Plan 206 (perf + determinism tail; capability already ships via full-mem-load)
  (Vz=152 WS-C; libkrun disk-only done #741; reflink clone = 123 C4 follow-up)

PLAN 206 — FC warm-start UFFD substrate + primed-barrier wiring   🟡 ON-HOST SLICES LANDED; UFFD + live-KVM tail remains (Plan 175 T2/T3 carve-out)
  [ ] T1 UFFD page-fault handler + diff/layered snapshots + NBD rootfs + 2MB hugepages (the ~1s, O(working-set) resume; layers under warm_restore_instance) — NOT STARTED (Linux-kernel + live-KVM, unverifiable on a macOS dev host)
  [~] T2 primed-barrier live wiring — HOST+GUEST DONE & unit-tested: `GuestRequest::PrimedStatus`→`PrimedStatusReport{primed}` RPC (mirrors ProbeStatus) + workload marker `/run/mvm/primed` (`PRIMED_MARKER_PATH`/`workload_is_primed_at`) + host `VsockPrimedSignalSource` (poll policy `wait_for_primed_polling` unit-tested vs a fake "mock guest"; vsock I/O = thin shell like `VsockPostRestoreSignal`) + `vm pause --primed-barrier [--primed-timeout=120]` gating `await_primed_barrier` before `pause_and_seal`, fail-closed. Live seal-on-signal proof (Step 3) remains live-KVM-gated.
  [~] T3 token-delivery polish — S2 honest verb DONE: `post_restore_at`→`PostRestoreReply{acknowledged,reseeded}`, `warm_restore_instance`→typed `ReseedStatus` (pure `classify_reseed`), `VmBackend::warm_start`→`WarmStartOutcome{id,reseed}`, `run_warm_start` prints `reseed.resume_summary()` (libkrun disk-only=NotApplicable). S1 fallback DONE: agent-ready wait widened 30→60s with a budget test (root-cause investigation + S3 live divergence proof stay live-KVM-gated).

PLAN 126 — Dependency reduction                 🟢 cuts+gates landed; aws-lc/reqwest-unify rehomed (oci-client-upstream-gated)
  [x] A1 re-baseline
  [x] B5 drop tokio from mvm-core (PR-1)
  [x] B2 opendal → object_store (mvm template registry); opendal GONE,
      lockfile 689→678 (−11)
  [~] B1 sigstore — already off default; prod cosign verify decision rehomed to mvmd
      (mvmctl keeps the OCI provenance audit-label path)
  [~] B3 pgp (168) — SUPERSEDED by Plan 160 (drop Alpine seed); no Plan 126
      implementation target remains
  [ ] B4 aws-lc-rs → ring — BLOCKED upstream (oci-client hardcodes aws-lc; needs a fork)
  [~] C1 reqwest unify — REJECTED/blocked on B4 (0.13 forces aws-lc + transitive 0.12 holdout; no tree collapse)
  [x] D2 duplicate-major lock-gate — cargo-deny multiple-versions=deny + 23-crate baseline (ratchet); also
      un-broke the red cargo-deny/cargo-audit jobs: wildcard-paths, mvm-verify license, 2 unmaintained ignores,
      and FIXED RUSTSEC-2026-0119 (hickory-proto DoS) by bumping hickory-resolver 0.24→0.26 (collapsed its dup)
  [x] D1 forbidden-dep gate (check-forbidden-deps extension) — closure ban on
      sigstore/opendal/pgp is wired; final measure recorded in dep-baseline.md

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

PLAN 189 — VZ DX parity (post-convergence)        ✅ COMPLETE  (ADR-076 §"Out of scope")
  Spun out of Plan 177's deferred DX-parity follow-on; sibling of Plan 159 (owns
  only the additive parity slice, cross-refs 159/140/148 for primitives).
  [x] WS-3: `dev status/down/up --json` (versioned, privacy-safe; all dispatch
      arms; lifecycle handlers return outcome; up forces chrome→stderr +
      conflicts_with shell; serde + CLI-parse + conflict tests)
  [x] WS-3: snapshot/checkpoint JSON coverage — `vm checkpoint restore/rm/fork
      --json` + `vm snapshot rm --json`; create/ls/diff already covered; parser
      tests pin every flag; CLI reference corrected to grouped `vm` commands
  [x] WS-3: structured-stdout + Vz dev-shell hardening — entry convergence
      routes chrome to stderr before structured stdout, and the persistent Vz
      dev VM exposes the console data-port range (`20001..20128`) needed by
      `ConsoleOpen`
  [x] WS-3: source-checkout Vz helper freshness — local `cargo run` workflows
      auto-build stale/missing `mvm-vz-supervisor` + `mvm-vz-drainer` sidecars
      before launch so schema-v6 plans with `auth` cannot be decoded by stale
      schema-v5 helper binaries
  [x] WS-1 save/restore aliases · WS-2 cached fast-boot default · WS-4 base
      pinning are closed for Plan 189 scope; post-Plan macOS-26 timing/content
      proof belongs to the shared Vz live-validation lane.
  [x] WS-1 surface save/restore verbs — `vm save` / `vm restore` are thin
      aliases over `vm-full` checkpoint create/restore, gated by the Vz
      `save-restore` snapshot_capability tier; alias-specific live proof is
      rehomed because this path reuses the existing checkpoint primitive.
  [x] WS-2 cached fast-boot default — who-calls audit DONE: surface already fast-boot-default (dev-image + builder-VM fingerprint fast-path, persistent-VM reuse, up cache-hit-only); Plan 195 fixed and validated the builder-VM cache-hit path. Further live timing/no-boot proof is shared validation, not Plan 189 code.
  [x] WS-3 --json coverage across vz lifecycle verbs — checkpoint/snapshot
      JSON, structured stdout hardening, source-checkout helper freshness, and
      linux-native typed readiness detail are covered
  [x] WS-4 base pinning — design + Vz `dev up --base` resolution + pinned-base
      rootfs fingerprint proof surface landed (template/slot/bundle refs,
      exact template/slot revision pins, fail-closed artifact checks, optional
      `dev status --json.base`, no parallel registry); live pinned-base
      rootfs fingerprint/fork proof is rehomed to shared Vz validation.

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

PLAN 193 — rvproxy network substrate (replace gvproxy/passt)  🟡 WS-1 proven; WS-2.2d mvm-side native parity landed; parity gate required; libkrun transparent terminator wired; Vz + splice deletion remain
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
  post-gateway frames, so this can only live in the gateway. The mvm-side requirement is now encoded
  as a tested `require_transparent_egress_terminator(&dyn WorkloadBackend)` deletion guard; actual
  rvproxy interception support remains the implementation prerequisite.
  Plan: specs/plans/193-rvproxy-network-substrate.md
  WS-2.2d (mvm-side, #1009): native rvproxy audit feed + native-enforcement parity, no splice.
    - tasks 1+2a (audit feed + deny-by-default witness) proven live on libkrun; the follower tails
      rvproxy's flow-audit JSONL into the chain-signed signer_task, emitting gateway.flow_* entries.
    - task 2b: native allow/deny matrix witness. One [policy] with an L4 allow rule
      for a public /24 + deny-by-default, probed twice (rvproxy accepts one vfkit connection per
      spawn and reliably processes only the first post-handshake frame, so each dst gets its own
      spawn): unlisted dst denied for l4_allowlist_miss (proves the rendered allow-list is active),
      listed dst not denied (proves admission). Both witnesses share native_first_frame_probe; gated
      MVM_GATEWAY_NATIVE_E2E + MVM_GATEWAY_BIN. Parity gate step [2/4] runs the whole rvproxy_native
      family. All four gate arms green; both witnesses 5/5.
    - task 2c: dead mvm-side open-policy slot removed. `BridgeConfig.policy` and the production
      `AllowAll` FlowPolicy are gone; supervisor-bin construction sites no longer pass ignored
      policy values; tests use `PlanFlowPolicy::from_network_policy(NetworkPolicy::unrestricted())`
      for intentional open-mode coverage. This keeps the pre-deletion bridge enforcement source
      singular: resolved bundle or threaded bare NetworkPolicy, otherwise fail-closed deny-all.
    - task 2d: macOS/libkrun native-default selection landed when `MVM_GATEWAY_BIN` names the
      rvproxy candidate; no-candidate and explicit-gvproxy fallbacks remain.
    - task 2e: admitted libkrun/Vz starts already thread the signed plan by default, so there is
      no separate future `MVM_GATEWAY_BRIDGE` default flip for those backends. Firecracker's bridge
      sidecar remains explicit because default Firecracker egress is already enforced by nftables.
    - task 2f: transparent terminator requirement captured as a tested workload-backend deletion
      guard: Firecracker's nft terminator satisfies it; libkrun/Vz/mock do not.
    - remaining: rvproxy transparent-terminator schema/support, mvm config
      wiring once that exists, then delete the splice + Plan-141 on_packet hooks.

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

PLAN 199 — Host runtime packaging + crate boundaries  ✅ COMPLETE
  Plan: specs/plans/199-host-runtime-packaging-and-crate-boundaries.md
  [x] Add optional source-built Nix host package for `mvmctl` without changing the Linux-only
      `mkGuest` image API.
  [x] Expose source-built `packages.<system>.mvmctl`, default package, and overlay package.
  [x] Test that source-checkout Nix packages do not fetch project release binaries.
  [x] Keep native VMM linkage explicit/opt-in in Nix packaging tests.
  [x] Document binary install as the primary user path and host Nix as optional.
  [x] Add native VMM Nix recipes without making native linkage a default hidden dependency.
      Pinned, source-built `libkrunfw` v5.5.0 and `libkrun` v1.18.1 packages now expose through
      Linux host packages/overlay attrs, plus opt-in `mvmctl-native-libkrun`; default `mvmctl`
      stays non-native.
  [x] Run builder-VM Nix verification: `nix flake check` and Linux package builds for
      `.#mvmctl` / `.#mvmctl-native-libkrun`.
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
  [x] Record the dev/prod promotion boundary: mutable dev-machine state is not a prod input;
      prod/sealed builds consume declared host-side inputs only, and future SSH-agent support
      stays dev-tier only (ADR-088).
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
  [x] Implement `mvmctl machine` parser and command aliases over existing runtime primitives.
      `machine run` translates into run_secure with deny-all egress preserved; create/start/
      exec/shell/stop/ls/inspect/rm persist specs or reuse existing admitted launch/attach/
      down paths. `pack` remains in the portable-artifact workstream.
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
  [x] Implement persistent OCI-backed machine specs under existing data-dir helpers:
      `MachineSpec` persists via `mvm_core::config::machine_spec_path`, atomic writes,
      strict JSON, safe-name validation, and `machine create` / `ls` / `inspect` /
      `rm --yes` state operations. Running-VM wrappers `machine exec` / `shell` /
      `stop` also landed through existing console/down paths; persistent image-backed
      `start` remains.
  [x] Implement schema-v1 parser/tests with unknown-key and `image`/`flake` conflict rejection.
  [ ] Implement SDK parity for Python, TypeScript, and Rust, including non-bypass tests for
      admission, artifact verification, default-deny network, unknown keys, source conflicts,
      and receipt/audit summaries. Python, TypeScript, and Rust now have
      `Machine.run/create/start/exec/shell/stop` wrappers that shell only to
      `mvmctl machine ...`, expose structured `MachineError`s, and carry fake-CLI
      lifecycle/error tests; VM-free parser/preflight, admission-input,
      receipt-summary, unknown-key, and artifact-verification parity now run
      through the CLI seam. Live non-bypass proof remains.
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

PLAN 202 — Host services daemon (per-tenant, not per-VM spawn)   ✅ COMPLETE (ADR-084, #977; mvmd #162)
  Supersedes the Plan 125 E5.3b per-VM subprocess fork. Wire protocol unchanged.
  [x] ADR-084 + Plan 202 written (per-tenant daemon model; revises ADR-059).
  [x] Phase 1 kickoff prompt (plans/host-services-daemon-phase-1-kickoff.md).
  [x] ADR-084 reviewed + accepted.
  [x] Phase 1 — broker daemon + host-signed Register/Deregister control plane + dynamic
      per-VM socket binding + server-derived vm_id; spawn_broker fork → ensure_daemon/register_vm.
  [x] Phase 2 — audit-signer daemon (helper core, helper forwarding, admission
      signing through the helper, and persisted-head restart landed).
  [x] Phase 3 — decouple availability from `MVM_GATEWAY_BRIDGE` (3a default-on,
      3b active-tenant process-cost proof, 3c doctor daemon-state reporting, and
      3d Vz live/default re-verify landed; two admitted `vz` launches exited `0`,
      both workload chains verified clean, and the same daemon/helper PIDs were reused).
  [x] Phase 4 — registration journal + local restart semantics landed: retry on register
      control failure, reconcile-on-entry re-ensure, and crash-mid-dispatch chain-clean proof.
  [x] Phase 5 — mvmd daemon-lifecycle + Firecracker substrate slices landed
      (shared `/var/lib/mvm`, lifecycle register/deregister, startup replay
      from `host-agent.tenant` markers, path-safe tenant/pool/instance validation,
      and guest→host `BROKER_PORT` on `runtime/v.sock_5300`), and mvmd PR #162
      closed the remaining cross-repo surface: the reusable delegated host-services
      route/authz layer now carries `host.cost.v1::tenant`,
      `host.catalog.v1::tenant`, `host.peers.v1::tenant`,
      `host.config.v1::tenant`, and `host.rate_budget.v1::tenant` over the
      native typed ALPN protocol with hostile-tenant refusal, strict
      malformed-response rejection, tenant-key-boundary proof, and
      `O(active tenants)` density evidence.
  [x] Phase 6 — retire `spawn_broker_services_if_admitted`; ADR-059 supersession
      note + CLAUDE process-moat update landed.

PLAN 203 — Opt-in forensic network transcript capture   🔴 PROPOSED
  [ ] Add transcript manifests and lifecycle audit kinds for arm/disarm/export/refusal.
  [ ] Add host-boundary capture sink and encrypted transcript payload storage.
  [ ] Add `mvmctl audit transcript` CLI to arm, disarm, list, and export a capture.
  [ ] Add tests for tamper refusal, bounded overflow, and export round-trips.

PLAN 204 — Builder VM resident control plane   🟢 IN PROGRESS (ADR-089)
  Plan: specs/plans/204-builder-vm-resident-control-plane.md
  [x] Add builder request/response protocol types with version/refusal tests.
      (mvm_build::builderd_protocol — typed allowlist + FailureCategory +
      PROTOCOL_VERSION/negotiate/handshake_reply, deny_unknown_fields, 26 tests)
  [~] Add resident `mvm-builderd` in the builder VM with Handshake/Probe.
      (mvm_build::builderd dispatch+serve_connection core landed, 9 tests;
      bin entrypoint + AF_VSOCK listener deferred to the boot-wiring box)
  [x] Add `mvmctl doctor` builder-daemon readiness visibility.
      (host probe_builderd_readiness/readiness_summary over BUILDERD_CONTROL_PORT
      + informational "builder daemon" doctor check scanning the vms/ root;
      real-UnixListener end-to-end tests; also the first WS-B host-client leg)
  [x] Add host-side `mvmctl` builder client over vsock.
      (mvm_build::builderd_client::BuilderdClient — connect+handshake,
      one-op-per-connection run_operation streaming OperationEvent → typed
      OperationOutcome, op-id correlation, typed errors, request_cancel;
      11 tests incl. live integration against serve_connection. WS-B
      residuals data-dir-isolation + git-host-side land with the lifecycle owner)
  [~] Move flake check, guest image build, and host-tool build to typed requests.
      (FlakeCheck typed-op core landed: argv/classify/OpExecutor/Completed
      terminal/serve_connection_with_executor; live nix exec + build-image/
      host-tool ops boot-gated)
  [ ] Retire normal-path raw shell jobs behind a gated debug-only adapter.
  [x] Add structural tests proving workload guest images do not include `mvmctl`
      or `mvm-builderd`.
      (xtask check-guest-images-no-builder-tools, comment-stripping source-grep
      over nix/lib/mk-guest.nix, wired into ci.yml Lint job)

PLAN 205 — Resident builder control plane + residency model (umbrella)   ✅ COMPLETE (ADR-090)
  Plan: specs/plans/205-resident-builder-control-plane.md
  Umbrella over Plans 118/152/159/196/202/204 — owns the trust gradient + residency.
  A. Trust-gradient invariant — ✅ #1090 (+ builder tier #1110)
  [x] Codify the three-class model + invariant in arch docs (#1103 architecture.md + ADR-090).
  [x] Structural test: workload guest image has no key / admission / prod do_exec / console
      (check-prod-agent-no-authority + existing no-console/no-exec lanes, #1090).
  [x] Structural test: builder daemon links no host-signer key path / admission entrypoint
      (check-builderd-no-authority, #1110 — unblocked by Plan 204's mvm-builderd #1091).
  [x] Host control daemon stays per-tenant (per_tenant_isolation test, #1090).
      → `xtask check-trust-gradient` machine-checks all three tiers: clean (3 rows).
  B. Residency policy over the standby pool — ✅ #1094
  [x] Residency policy (`min` warm + idle) over the Plan 118 pool (`mvm-core::residency`).
  [x] warm→parked idle demotion + parked→warm on claim — delivered by WS-D #1099.
  [x] Per-host default (AS dev = warm, CI = parked) + `MVM_RESIDENCY` override.
  [x] `mvmctl doctor` reports residency state + source.
  C. Resident builder daemon — ✅ delivered by Plan 204 (#1091)
  [x] `mvm-builderd` is the resident builder-VM control daemon (typed vsock, no shell).
  [x] Session reuse proof for Plan 205 acceptance: Vz/macOS live gate captured warm
      reuse in 130 ms with no builder boot; readiness/crash-recovery remain Plan 204 domain.
  D. Snapshot park/resume — ✅ #1099 plus Vz live closeout
  [x] Idle saved-state (vz) standby demotes to `StandbyState::Parked`; claim resumes via the
      existing saved-state path; libkrun reaps to cold; `pool status` shows the parked count.
  [~] Firecracker leg (Plan 175) — FC/libkrun stay reap-to-cold; live-memory gated in Plan 175.
  [x] Freshness = existing `StandbyCompat` (kernel+image sha), NOT the builder fingerprint
      (corrected: Plan 195's fingerprint is builder-VM scope, not workload-standby).
  E. Cold acquisition — ✅ #1102 (`mvmctl bootstrap`)
  [x] `mvmctl bootstrap` pre-fetches the builder VM image (instant first run).
  [x] Source-checkout path stays free of mvm-release artifacts (ADR-046/089).
  F. Docs and posture — ✅ #1103
  [x] "What runs where" table (`reference/architecture.md`).
  [x] Residency default / override / RAM-vs-latency tradeoff (architecture.md).
  [x] Threat-model delta (ADR-090 §"Threat-model delta").
  Builder-specific follow-ups: `MVM_RESIDENCY=cold` routes builds to the ephemeral builder
  (#1114); `BuilderResidencyAction` + builder snapshot freshness landed in `mvm-core::residency`
  (#1121); and the benign `host_signer` gate false-positive is fixed (#1123). Closeout
  proof `/tmp/mvm-plan205-live-proof9`: warm reuse 130 ms, parked restore P50 643 ms,
  P95 1163 ms, zero command failures, final state `parked`, and live OCI `run --image`
  exit 0.
```

## Security claims

15/15 shipped, none regressed, + 1 `Preview` (claim 16, egress-substitution
leak-gate — witnesses machine-checked, ADR-002 promotion pending) (`specs/claims/catalog.md`,
gated by `xtask check-claim-catalog`).

## Sequencing note — 2026-06-19

Why the remaining open rollup boxes still show as open:

- `REFACTOR-STATUS.md` only ticks a plan when the whole plan is done. Partial progress is recorded in the long `Last updated` history and detail blocks, so progress is easy to miss.
- The prior Plan 126 drift is now reconciled: its summary and detail section both
  show the forbidden-dep gate and final measurement as landed, with the remaining
  blocker narrowed to the OCI/TLS stack decision.
- Plan 200 is actively landing in slices. The persistent spec + running-VM wrapper slice landed in #1048; persistent image-backed `machine start`, manifest-to-machine runtime mapping, policy surfacing, dev-tier SSH-agent forwarding, Python/TypeScript/Rust SDK machine wrappers, Rust SDK -> CLI parser/preflight parity proof for default-deny/allow-host/unknown-key, Python/TypeScript shared-fixture parser/preflight proof for default-deny/allow-host receipt posture, SDK admission-input/receipt-summary/unknown-key parity, and VM-free SDK artifact-verification parity are now landed or in the active PR lane. The next open slices are live SDK non-bypass proof, scenario/limitations docs, portable artifacts, perf/smoke coverage, and dependency/binary budgets.
- Plan 202 is closed. Local `mvm` landed Phases 1–4 and 6; mvmd PR `#162` closed Phase 5 with the full delegated host-services surface, tenant-key/boundary proof, and `O(active tenants)` density evidence; ADR-084 is now accepted.
- Stage 0 bootstrap performance has an active branch-local fix: cached materialized root reuse, native verified tar extraction, and persistent `/dev/vda` Stage 0 Nix-store reuse are implemented with host tests/clippy. Do not make a public latency claim until Linux PID-1 compile/proof and live builder timing are captured.
- Plan 195 and Plan 199 are closed. Plan 195 already removed the builder-VM fingerprint churn that could distort validation, and Plan 199 now has native `libkrunfw` / `libkrun` recipes plus builder-VM Nix/package verification recorded.

Historical open PRs from the 2026-06-17 update:

- `#1048` / `feat/plan-200-persistent-machine`: Plan 200 persistent `MachineSpec` storage plus `machine create` / `ls` / `inspect` / `rm --yes` and running-VM `exec` / `shell` / `stop` wrappers. Its lifecycle-command state is now reflected above as landed; verify the PR/branch state before sequencing any new work from it.
- Historical note: `mvmd#160` / `fix/ci-mvm-sibling-ref` carried the CI sibling-checkout + `zigbuild` plumbing that unblocked the cross-repo Plan 202 mvmd slice; the slice ultimately closed in merged `mvmd#162`.
- Already merged: `#1039` Plan 200 local image-source closeout, `#1041` ADR bundle/GPU posture, `#1046` Plan 202 Phase 2c signer-helper-backed admission signing, `#1047` Plan 125 close/rehome plus Plan 200 checklist reconciliation, `#1049` Plan 202 Phase 2d signer-helper restart/head rebuild, `#1051` Plan 202 Phase 4a registration journal, `#1052` Plan 202 Phase 3b cost framing, `#1053` Plan 202 Phase 4b supervised restart, `#1054` Plan 202 Phase 4b cleanup, and `#1058` Plan 200 persistent OCI-backed start path.

Recommended sequence to close the remaining rollup items:

1. Continue Plan 200 with the remaining C2 live non-bypass proof. Python/TypeScript/Rust lifecycle wrappers plus VM-free parser/preflight, admission-input, receipt-summary, unknown-key, and artifact-verification proofs are landed.
2. Clean stale worktrees: several are old/behind or already landed (`mvm-202-3c-doctor`, `mvm-pr1009`, `mvm-p200-ociboot`, old status/170/vz100 branches). Do not sequence new work from them.
3. Confirm Plan 125 remains closed/rehome-only; remaining per-tenant daemon work belongs to Plan 202.
4. Continue Plan 193 only after rvproxy cross-repo slices are ready: land rvproxy transparent-terminator schema/support first, wire mvm once that exists, then delete the splice and remove Plan-141 hooks.
5. Keep Plan 189 closed; the shared Vz live lane now has detached-workload visibility and durable stopped-row reporting. Next fix actual detached Vz workload persistence after accepted launch, then rerun public `vm save`/`vm restore` and pinned-base checkpoint/fork content proof.
6. Resolve Plan 126's remaining blocked deps (`oci-client`, `aws-lc-rs`, `reqwest` major unification) rather than treating rehomed `sigstore` or superseded `pgp` work as normal TODOs.
7. Plan 118/175 are live-KVM gated; do density bench substrate first, then FC standby/warm-start once the KVM environment is ready.
8. Plan 159 and 201 are lowest priority: Plan 159 mostly needs residuals rehomed/descope, and Plan 201 is a convenience layer after warm-pool fundamentals.

Plan 200 implementation checklist after `#1039`:

- [x] Reconcile Plan 200 bookkeeping first: the rollup says MCP code-run admission is done via `#1017`/`#1023`, but the Plan 200 deferred checkbox still showed it open. Completed in #1047: the Plan 200 deferred checkbox points at #1017/#1023 and is ticked.
- [x] Persistent machine UX: `MachineSpec` persists under existing data-dir helpers with atomic writes and strict JSON; `machine create` / `ls` / `inspect` / `rm --yes` plus running-VM `exec` / `shell` / `stop` wrappers are implemented with parser/state/JSON/deletion/spec-guard tests; and `machine start --name` now resolves the persisted spec, emits OCI provenance/admission, and boots through the admitted launch path.
- [ ] `mvm.toml` machine mapping: parser/model slice, runtime pass, policy surfacing, signed-plan auth/admission metadata, and dev-tier SSH-agent transport are landed — `machine create --manifest <path>` now persists `net`, `[network].allow_hosts`, `cpus`, `mem`, `mem_initial`, `[dev].init`, `[dev].volumes`, and `[auth].ssh_agent` into `MachineSpec`; `machine start --name` now applies `mem_initial`, admitted volume shares, dev-init execution, and `SSH_AUTH_SOCK` Unix-socket forwarding to `/run/mvm/ssh-agent.sock`; `machine start --dry-run` / `--receipt` surface the effective policy; and `ExecutionPlan.auth.mode` plus admitted audit labels make `ssh_agent_socket` explicit in signed admission. ADR-088 fixes the design boundary: mutable dev-machine state is never an implicit prod input, SSH-agent forwarding is dev-tier only, and Nix templates cannot add SSH packages/config/material. Remaining is sealed/prod policy follow-up and live SSH-agent round-trip validation after Firecracker guest-to-host host-listen forwarding works for dev `SSH_AGENT_PORT` 5301 or on an equivalent backend whose port 5301 host-listen path is already registered; the non-standard-port SSH protocol-denial proof for the runtime SSH-banner classifier / Firecracker bridge-TAP banner drop passed on Firecracker KVM at `4ce7d938`.
- [ ] SDK parity: Python, TypeScript, and Rust machine wrappers now reuse the CLI path by shelling only to `mvmctl machine ...`, expose structured `MachineError`s, and have fake-CLI lifecycle/error tests. Rust and Python/TypeScript VM-free parser/preflight proofs now cover default-deny and allow-host receipt posture, richer admission/receipt inputs, strict-manifest unknown-key rejection, and SDK-exposed artifact verification through the real CLI seam. Remaining: live non-bypass tests.
- [x] Scenario-led docs: update binary-install-first docs, machine quickstart, limitations, old-verb mapping, source guards, completions, and first-run output without implying host Nix, GPU, ICMP, or unsupported architecture support. Coverage: scenario `machine-use-cases.md` + `machine-limitations.md` + the CI-wired `xtask check-machine-doc-guards` source guard landed in #1186; machine quickstart (`getting-started/quickstart.md`) and first-microvm already lead with `machine run`; old-verb mapping + dropped-`completions`→`shell-init` documented in `reference/cli-commands.md`. This slice corrected the binary-install-first backend docs: `getting-started/installation.md`, `quickstart.md`, and `first-microvm.md` no longer claim a non-existent "Apple Container" or Docker/Tier-3 container backend — the runtime backends are Firecracker (Linux KVM), Vz / Apple Virtualization.framework (macOS 26+ Apple Silicon), and libkrun (macOS 13–25 Apple Silicon), with `qemu` (microvm.nix) marked dev/test-only and never auto-selected, and the `--hypervisor` examples reduced to the real selectors (`firecracker`/`vz`/`libkrun`/`qemu`). Deeper historical "Apple Container" mentions in ADR/reference/security pages are intentionally left as records. NB: the distinct *CLI* first-run-output feature (image-pull/network-posture explainer) is a separate code item still tracked in the Plan 200 doc.
- [~] Portable artifacts: the **verify-before-extract primitive + `mvmctl artifact extract` CLI landed** — `mvm_build::packed_artifact::extract` verifies signature/hashes/format-version/sealed-prod-verity first, then writes only manifest-listed files through the existing `entry_path_string` traversal guard (absolute/`..` rejected), so a tampered or traversal-laden archive never lands a byte; covered by unit tests (happy-path + no-write-on-verify-failure) and a `pack → extract` CLI round-trip. The lower-level verifier covers traversal, unknown-version, missing-verity, hash, and signature refusals. **The runner security core + `machine check-artifact` preview also landed** — `commands::machine::portable` adds the **wrong-arch gate** (`ensure_runnable_on_host`) and a **fail-closed posture→admission mapping** (`admission_for`: `Standard` seccomp for every profile, network = requested ∧ artifact-egress so a no-egress artifact is deny-all regardless of `--net`/`--allow-host`, volumes only if declared — the artifact may only restrict, never escalate), unit-tested for posture narrowing; `mvmctl machine check-artifact <art.mvm>` now routes through a single verified-admission helper that verifies first, arch-gates second, and only then returns the admission preview. Machine-level tests prove wrong-key, tampered payload, and arch mismatch are refused before admission preview; a `pack → check-artifact` CLI round-trip already covers the happy path. Remaining: the live `machine run <artifact>` boot (de-risked — extract → `ImageSource::Prebuilt` + an `admission_for`-driven admit closure; hardware-gated), `machine pack` (materialize a `MachineSpec`'s image → kernel+rootfs via the builder VM, then `pack`), and verify/extract/run docs.
- [ ] Performance and smoke coverage: add builder-VM/KVM `machine run --image alpine -- true`, `machine run --net --image alpine -- nslookup example.com`, phase timing, cached hot-start benchmark, and macOS backend measurements before making latency claims.
- [ ] Dependency and budget gates: add duplicate-major and binary-size budgets, finish default-machine-path dependency cleanup, reduce OCI/TLS stack duplication, slim heavy test fixtures, audit machine-path CLI UI deps, and move libkrun bindgen/libclang usage to regeneration-only.
