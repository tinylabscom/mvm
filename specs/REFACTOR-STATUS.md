# Refactor status — rollup checklist

**Last updated: 2026-06-11**

> MAINTENANCE: keep this file current. Whenever you land, merge, or descope a
> workstream in any plan below, tick/strike the matching box here in the SAME
> change and bump the "Last updated" date. This is a hand-maintained rollup of
> the per-plan checkboxes in `specs/plans/` and `specs/SPRINT.md` — it is a
> quick index, not the source of truth. If it disagrees with a plan doc, the
> plan doc wins; fix this file.

## Plans

```
PLAN 121 — Crate consolidation (32→15)          ✅ DONE
PLAN 169 — Backend-agnostic agent RPC           ✅ DONE
PLAN 166 — QEMU Linux dev/test backend          ✅ DONE (Phase 2)
PLAN 165 — Sealed-prod interactivity (claim 15) ✅ DONE

PLAN 129 — Secrets / SigV4 substitution         🟢 declared + undeclared (box-validated on QEMU); SDK-free http terminator (#735/#744) + Stage 2 https/name-constrained-CA (#761) landed; FC kernel blocker fixed (#763); live FC https e2e gated only on agent bringup
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
  [ ] live SDK-free FC box e2e — Task 6 — DEFERRED to a bringup/debug session
      (prompt: specs/prompts/129-fc-bringup-debug.md). Kernel blocker (published
      x86_64 bzImage→ELF vmlinux, #746) FIXED — PR #763 (mvm_build::fc_kernel
      auto-extracts at boot); local secret-launch glue DONE (#745). Remaining
      gate: FC guest-agent reachability (live-debug on the dev-kvm box)
  [x] Stage 2 S2.1–S2.6: name-constrained per-VM CA (crypto::egress_ca) + host
      cert/key split + kernel-cmdline cert + placeholder-env delivery (mvm.egress_ca /
      mvm.secret_env) + SNI-gated TLS terminator (terminate bound / splice unbound,
      reqwest re-origination) + :443 nft redirect + ADR-006 Accepted / ADR-067
      proxy-native-primary — PR #761; TDD plan: specs/notes/plan-129-stage2-https-ca-tdd-plan.md
  [ ] Stage 2 S2.7: live SDK-free https FC box e2e — gated on the FC bringup above
      (agent reachability) + a placeholder-env-at-boot path (resolved by Approach A
      in #761; box-validation pending)
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
    [ ] remaining: IR/SDK developer-declared authoring (the only open variant; mvmd
        can author via bundle), terminator-path redaction, live PII spans.
        See plan §"Deferred follow-ups".
  [x] Phase F: egress no-secret-to-guest leak-gate (claim-12/13 backstop) —
      canary tests (handed_placeholders_never_contain_the_secret_value /
      substitution_endpoint_refuses_unbound_destination /
      audit_chain_carries_no_secret_value) in crates/mvm-hostd/tests/
      egress_secret_leak_gate.rs + claim doc claim-egress-no-secret-to-guest.md +
      catalog.md row 16 witnesses (Preview), gated on every PR (Test lane +
      check-claim-catalog)
  [ ] forward proxy https/CONNECT (only http/absolute-form works today) — deferred
  [ ] forward-path signing integration (SigV4)        — DEFERRED (user)

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
  [x] WS-1 warm pool (Plan 118): 1a primitive + 1b-i trait seam/registry/libkrun
      + 1b-ii reaper/doctor/`mvmctl pool`/bench-fix + 1b-iii up auto-claim
      (try_warm_claim/replenish/--warm-pool-size, fail-open) + bundled-kernel
      compat key — libkrun mkGuest warm claim FIRES end-to-end (#757/#758,
      live-validated "Claimed a warm standby"). Bridge boot also live-validated
      (exit 7; up.rs "bridge broken" comment stale). Follow-ups (non-blocking,
      SPRINT.md): multi-kernel keying; pool-status liveness filter;
      home_mvm_keys_dir MVM_DATA_DIR; committed bench delta
  [x] WS-2 checkpoint+fork — fs_quick (#762) + vm_full (#770): mvmctl checkpoint
      create/ls/rm/fork + APFS-CoW capture + integrity-checked fork + lineage +
      checkpoint.created/forked/restored audit + fs_quick+vm_full capability +
      vm_full memory save/restore (saveMachineStateToURL) + vm_full fork arm +
      restore_checkpoint + retire snapshot save/restore. cache GC.
      PR3 (#780): checkpoint diff <a> <b> (metadata+manifest compare) + Vz
      pause/resume (native vCPU quiesce). WS-2 COMPLETE.
  [x] AuditEmitter + host_keypair + plan_persist + pure checkpoint bind helpers
      hoisted to mvm_hostd::audit (mvmd-reachable library API); mvm-cli shimmed
  [ ] WS-5 D verb renames; curl|sh installer; --json remainder
  [ ] signed delta-image distribution (unowned — needs a home)

PLAN 124 — Lean guest agent                     🟡 ~65%
  [x] A1/A3 drop tokio+rtnetlink (-27 crates)
  [x] B universal agent in all images
  [x] C1 verity-sealed runtime overlay
  [x] D1.0/D1.1 schema SSOT
  [ ] D1.2/D1.3 SDK codegen
  [ ] E signed on-device config

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
  [ ] C4 warm-start CLI/RPC wiring — carved out → Plan 175 (rides C2)

PLAN 175 — Firecracker live-memory warm-start    🔴 NOT STARTED (live-KVM-gated; Plan 123 C2 carve-out)
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
  [ ] C1/D1 unify reqwest majors + lock gate

PLAN 153 — CLI directory split                  ✅ DONE (subsumed into Plan 178)
  [x] image.rs → image/ ; catalog.rs → catalog/ (last two flat files)

PLAN 177 — Backend consolidation (8→4)           🟡 Phase 1 DONE; Phase 2 gated  (ADR-076)
  [x] Phase 1 delete docker (+ dead Tier-3 banner subsystem)
  [x] Phase 1 delete cloud_hypervisor (+ ch_runtime, ch-bootcheck)
  [x] Phase 1 fold microvm_nix → qemu
  [x] Phase 1 prune dead CI lane + Justfile setup recipe
  [x] Phase 1 verify: doctor lists {firecracker,libkrun,vz,qemu,apple-container,mock};
      4837/4837 workspace tests (excl mvm-backend SIGKILL bin); clippy/fmt clean
  [ ] Phase 2 (GATED on Plan 152 WS-B + save/pause merge): AVF convergence
      onto supervisor vz + shared console transport + drop apple-container

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
```

## Security claims

15/15 shipped, none regressed, + 1 `Preview` (claim 16, egress-substitution
leak-gate — witnesses machine-checked, ADR-002 promotion pending) (`specs/claims/catalog.md`,
gated by `xtask check-claim-catalog`).
