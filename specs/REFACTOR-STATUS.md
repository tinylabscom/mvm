# Refactor status — rollup checklist

**Last updated: 2026-06-13** (Plan 185 test-isolation sweep advanced; ADR-080 program batch landed: Plans 188/186/187; Plan 189 WS-3 `dev status/down/up --json`; Plan 190 kernel egress close-out; Plan 191 declarative file materialization — ADR-080 P2-full; Plan 159: instant memory fork vm_full productized — admitted child, gvproxy-only invariant; Plan 193 rvproxy network substrate proposed + gvproxy teardown/build-perf findings)

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
- [ ] **PLAN 152** — Rust-native VZ supervisor · 🟢 native objc2, Swift deleted; WS-C/D separate workstreams
- [ ] **PLAN 118** — Supervisor standby pool · 🟡 libkrun + Vz done; FC follow-up open
- [ ] **PLAN 159** — vz-inspired macOS VZ DX · 🟡 warm pool + checkpoint/fork shipped; WS-5 D + delta-image remain
- [ ] **PLAN 123** — Network / storage / warm-start · 🟢 Phase A/B done; C2/C3 (FC/Vz warm-start) gated
- [ ] **PLAN 124** — Lean guest agent · 🟡 ~65%; SDK codegen + signed on-device config remain
- [ ] **PLAN 126** — Dependency reduction · 🟡 ~30%; duplicate-major lock-gate landed (+ supply-chain CI restored); sigstore/aws-lc/forbidden-dep-gate remain
- [x] **PLAN 177** — Backend consolidation (8→4) · ✅ both phases merged (#806/#789/#812/#814/#817); DX-parity → Plan 189; lone caveat = host-gated hardware smoke
- [ ] **PLAN 182** — Trait hygiene + backend catalog · 🟡 code+docs done locally; aggregate workspace-test SIGKILL remains
- [ ] **PLAN 184** — Backend descriptor registry · 🔴 not started
- [ ] **PLAN 185** — Idiomatic Rust hygiene audit · 🟢 shared TestEnv expanded into mvm-cli/mvm-build; guest hook tests de-shelled
- [ ] **PLAN 189** — VZ DX parity (post-convergence) · 🟡 in progress — WS-3 `dev status --json` landed; remaining: save/restore verbs, cached fast-boot default, more --json coverage, base pinning (spun out of 177; sibling of 159)
- [ ] **PLAN 175** — Firecracker live-memory warm-start · 🔴 not started (live-KVM-gated)
- [x] **PLAN 183** — Builder-VM egress posture + network bootstrap · ✅ (E2E-proven 2026-06-12; Vz checkpoint-integration follow-ups tracked in the plan)
- [x] **PLAN 180** — Strip spec refs from code comments · ✅ (lint-gated, #786)
- [x] **PLAN 188** — Capability projection seam (ADR-080 P5) · ✅ LANDED (#801); kernel-side wiring spec'd as Plan 190; WASI-context mapping deferred
- [x] **PLAN 186** — Trace hardening (ADR-080 P1/P3/P4 + hardened P2 pin) · ✅ LANDED (#809; caught + fixed a live shell-injection in the FilesWrite lowering)
- [x] **PLAN 187** — Secret-scan admission gate (ADR-080 P7) · ✅ LANDED (#811)
- [x] **PLAN 190** — Kernel egress decision converges on CanonicalEgress (ADR-080 P5 close-out) · 🟢 LANDED (kernel leg; lenient L4 lowering; zero claim-10 behaviour change; WASI-context mapping deferred to runner plan)
- [x] **PLAN 191** — Declarative file materialization (ADR-080 P2-full) · 🟢 P2-full LANDED (FilesWrite lowers to the declarative `App.files` IR field, baked into the rootfs at build time via `mkFunctionService` `extraFiles`; the `before_start` shell hook is removed — file content/paths never reach a guest shell)
- [ ] **PLAN 193** — rvproxy network substrate (replace gvproxy/passt) · 🔴 proposed, cross-repo — gated on rvproxy confirming libkrun-unixgram transport; biggest win = native flow API replaces the in-line claim-10 datapath wrapper (Plan 141)

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
  [ ] WS-C fork primitive (snapshot/restore done in #700) — separate workstream
  [ ] WS-D nested KVM (/dev/kvm in guest) — separate workstream
  NOTE: Swift control socket self-deadlocked on async VZ ops; Rust fixes it
  (ADR-056 addendum). Deferred: VzIngest/mvm-vz-drainer dead-code sweep; +
  lower-priority supervisor robustness (exit-listener 2nd-conn, control-verb
  single-flight, validateSaveRestore hard-gate for Restore) noted in #772.

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
      no-clobber rootfs adoption; resource shape flags > parent plan > defaults.
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
      0.91s incl. claim-8 admission (same-identity clone model; recorded-sha admission; gvproxy-only invariant)

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
  [ ] Firecracker standby pool (the mvmd-facing deliverable) — gated on FC standby
      follow-up; not blocking current libkrun/Vz use

PLAN 183 — Builder-VM egress posture + net boot ✅ DONE (follow-ups tracked in plan)
  Last updated: 2026-06-12
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

PLAN 124 — Lean guest agent                     🟡 ~65%
  [x] A1/A3 drop tokio+rtnetlink (-27 crates)
  [x] B universal agent in all images
  [x] C1 verity-sealed runtime overlay
  [x] D1.0/D1.1 schema SSOT
  [ ] D1.2/D1.3 SDK codegen
  [ ] E signed on-device config

PLAN 184 — Backend descriptor registry          🔴 not started
  [ ] Promote `mvm-backend`'s shipped backend catalog into a first-class
      `BackendDescriptor` / registry API while preserving `VmBackend` as the
      sole backend behavior trait
  [ ] Add descriptor-driven construction for both `AnyBackend` and
      `Arc<dyn VmBackend>` consumers
  [ ] Migrate read-only and clearly generic backend consumers away from enum
      dispatch where no backend-specific behavior is needed
  [ ] Keep `AnyBackend` only for intentionally enum-specific operations
      (`auto_select` policy, backend-specific helpers, explicit variant checks)

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
  [ ] Roll `TestEnv` through remaining high-risk env-mutating tests in `mvm-backend`,
      `mvm-cli`, and `mvm-build`
  [ ] Standardize poisoned-lock handling by distinguishing test/global
      serialization locks from real runtime state locks
  [ ] Rename overly generic internal traits/types where the blast radius is
      small, including storage/backend and layer-local egress proxy names
  [ ] Push stringly backend/provider selectors toward typed values at module
      boundaries
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

PLAN 123 — Network / storage / warm-start        🟢 Phase A done; B done; C1+C4 done; C2/C3 gated
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
  [ ] C2 Firecracker live-memory fast-resume — carved out → Plan 175
  [ ] C3 Vz save/restore (macOS 26+) — owned by Plan 152 WS-C

PLAN 182 — Trait hygiene + backend catalog      🟡 code+docs in; aggregate workspace-test gate remains
  [x] shared `mvm_core::time::{Clock,SystemClock}` replaces the three local copies
  [x] duplicate `KeyProvider` retired in favor of `mvm_core::crypto::keystore`
  [x] backend metadata catalog becomes the single source for `AnyBackend` selectors
      and `mvmctl doctor` backend support maps
  [x] macro scope stays narrow: land `backend_catalog!`, reject broader trait-impl/noop macros
  [x] architecture docs now describe the current trait seams and ownership rules
  [ ] literal `cargo test --workspace` aggregate run (package-local tests are green; workspace run hits SIGKILL on `mvm-backend` here)

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

PLAN 193 — rvproxy network substrate (replace gvproxy/passt)  🔴 proposed, cross-repo
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
  the base-VM fingerprint churn, a separate change). Plan: specs/plans/193-rvproxy-network-substrate.md
```

## Security claims

15/15 shipped, none regressed, + 1 `Preview` (claim 16, egress-substitution
leak-gate — witnesses machine-checked, ADR-002 promotion pending) (`specs/claims/catalog.md`,
gated by `xtask check-claim-catalog`).
