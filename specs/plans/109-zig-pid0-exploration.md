# Plan 109 — Guest control-layer dep-reduction + encryption design (Zig + lean-Rust v2 evaluation)

> **Renumbering note (2026-05-28):** originally drafted as Plan 105 (commits `eb345fbc` + `24fe3a3d`); slot 105 was claimed concurrently on `main` by `105-plan-100-w1-linux-builder-vm.md`. This plan migrates to slot 109 — slots 105/106/107/108 are all taken on `main`. Same content, same workstreams, same recommendation. Per the spec-numbering-chaos memory, future readers should treat **Plan 109** as canonical and ignore any stale "Plan 105" references in prior commit messages on this branch.

Status: proposed (exploration, not commitment)
Created: 2026-05-27 (as Plan 105); renumbered 2026-05-28 (as Plan 109)
Owner: tbd
Related: SPRINT.md Sprint 57, Sprint 42 Track E, ADR-002, ADR-053, ADR-055, ADR-058, ADR-059, ADR-061 (broker hardening), **ADR-062** (drop host.secrets.v1, add host.audit.v1), Plan 25, Plan 64, Plan 102, **Plan 104** (host services broker — adjacent vsock surface; see §"Process lineage" and W3)

## Why this plan

The guest-side control-layer (`mvm-guest` and its sibling pid0-class binaries) is currently Rust + heavy transitive deps (tokio, serde_json, ed25519-dalek, rtnetlink, seccompiler — hundreds of crates). Track E in Sprint 42 set the gates for Zig adoption; this plan is the first concrete evaluation using those gates. Output is **evidence**, not adoption: two measured prototypes (a Zig port and a lean-Rust-v2 port of the same small binary), three foundational ADR drafts, a design doc for vsock encryption, and a published provider capability matrix.

The two-prototype design makes the milestone risk-symmetric: if Zig wins the measurement, we have evidence to plan a larger Zig adoption. If lean-Rust v2 wins, we have a concrete Rust-internal dep-reduction blueprint. Either way the four shared workstreams (encryption design + three ADRs + capability matrix + threat-model delta) land.

## Systems-design recommendation (taken position)

**Stay Rust. Adopt "lean Rust v2" as the agent's evolution path. Treat the Zig prototype as a measurement check, not a direction.**

Reasoning:
1. The dep-reduction goal is achievable in Rust — `polling` + `linux-raw-sys` + hand-rolled (or `nanoserde`) parsing gets 50–70% of the transitive-crate cut without abandoning the ecosystem. The team already shipped this discipline with `mvm-egress-proxy` (`libc` only, no `tokio`).
2. Agent complexity is architectural, not linguistic. The 33 RPC variants + process supervisor + warm-pool don't shrink because of language choice — they shrink when the monolith splits into core-dispatcher + composable handlers (mirror `mvm-addon-dns` / `mvm-addon-vsock-bridge`).
3. Toolchain tax compounds: Zig adds a CI compiler, a different fuzzer story, a different reproducibility-verification path, a different debugger, contributor onboarding, code-review skill — each manageable alone, significant in aggregate for a small team running 10+ CI lanes.
4. The audit chain is Rust. Claim 8's `AuditEmitter` / `verify_audit_chain` live in `mvm-supervisor` / `mvm-core`. A Zig agent forks the chain (D2 violation + drift risk) or calls back over IPC (boundary surface grows).
5. The protocol is Rust per D2. A Zig agent is a second implementation of every wire type with permanent drift risk; lean Rust v2 keeps `mvm-core` types as the single source of truth.
6. Encryption (W3, Noise_NK) is the highest-leverage security upgrade and `snow` gives it to Rust on day one. Zig would need an hvf Noise impl.
7. Zig's real win is narrow: *tiny* boundary binaries (netinit, future single-purpose addons, ObjC/Swift shims) where there's no async runtime to amortize over. The agent isn't tiny.

What this means for the plan structure:
- **W2′ (lean Rust v2) is the primary track.** Build first. If measurements meet expectations, ships as the actual `mvm-guest-netinit` replacement.
- **W2 (Zig) is the measurement check.** Build second. Its purpose: put a number on what Rust leaves on the table for very small binaries. If the gap is >30% beyond lean Rust v2 on the dep-tree headline, the boundary-language ADR keeps Zig open for *future tiny addons only*. If smaller, the ADR says "Rust everywhere."
- **The agent stays Rust.** Future evolution = refactor (split + addons), not rewrite. A follow-on "agent v2" plan does polling + no-tokio + composable handlers + Noise_NK + supervisor decoupling.
- **W3, W4, W5, W6 are the most strategic deliverables.** They hold value independent of any prototype outcome and they make the boundary contract explicit + add encryption.

Honest uncertainties:
- `polling` + custom executor proven for one-shot binaries; unproven *at the agent's scale* (33-variant dispatcher + long-lived loop). W2′ doesn't settle this — netinit is one-shot. The agent v2 follow-on plan will need its own evaluation.
- Hand-rolled JSON loses serde's `deny_unknown_fields` ergonomic; either encode the invariant manually or stay on `serde` with a smaller derive footprint (`miniserde`?).
- Process supervisor without tokio is doable (`std::process::Command` + `rustix::waitid` + manual PTY) but the warm-pool state machine is non-trivial. Out of scope for W2′ (netinit is one-shot, no children).

This is a recommendation, not a foreclosure. If W2's measurements are decisive in the other direction, the boundary-language ADR adjusts. The point of the milestone is to produce that evidence.

## Design principles (non-negotiable)

- [x] **D1** — Primary motive is dependency reduction in the guest control-layer surface. The W2 rubric leads with dep-tree LOC reaching the guest boundary.
- [x] **D2** — Rust defines the conversation. Zig, if ever adopted, implements it. Wire types stay canonical in `mvm-core` / `mvm-guest`.
- [x] **D3** — Zig stays on the control plane. The data plane (virtio-net, virtio-fs, block devices, OCI rootfs, egress proxy, OCI unpacker, Plan 102's gateway audit substrate, claim 9 sealed-deps, claim 10 OCI provenance) is off-limits.

## Invariants (must not regress)

- [ ] **I1** — Control-plane audit chain stays intact. `AuditEmitter`, `verify_audit_chain`, `mvmctl audit verify` remain authoritative; `LocalAuditKind::NetworkPolicyAllow` keeps being emitted per RPC.
- [ ] **I2** — Data-plane audit substrate stays intact. Plan 102 (gateway audit), claim 9 (sealed deps), claim 10 (OCI provenance), W2 mandatory-deny routes — all out of scope for modification, in scope for regression checking.
- [ ] **I3** — All current backends keep working (libkrun, Firecracker, Apple VZ, Apple Container, Cloud Hypervisor, Docker, Mock). `cargo test --workspace` + per-backend CI lanes green.
- [ ] **I4** — Reversibility. Removing the Zig artifacts at any point leaves a fully-working Rust-only build. No Rust binary is deleted, gated, or moved out of the default path during this milestone.

## Process lineage (context for "pid0")

The guest-side process tree at runtime, after `mvm-verity-init` calls `switch_root`:

```
pid1 = init (NixOS minimal-init, from nix/lib/minimal-init/)
├── mvm-guest-netinit          (one-shot, installs blackhole routes, exits)
├── mvm-guest-agent (uid 901)  ←  the control-layer process (vsock :5252)
│   └── <workload from flake.nix mkGuest { entrypoint = ... }>
├── mvm-addon-dns              (optional, lives full VM lifetime)
└── mvm-addon-vsock-bridge     (optional)
```

The flake-defined workload is a **child of `mvm-guest-agent`**. The agent is both protocol dispatcher and process supervisor (fork/exec/wait/PTY + warm pool + integration probes). The netinit prototype dodges process-supervisor complexity entirely (one-shot, no children), which is exactly why it's the right calibration target.

### Adjacent vsock surface (Plan 104 / ADR-059 / ADR-062 context)

The agent control channel (vsock `:5252`) is *not* the only vsock surface between guest and host. Plan 104 (host services broker, merged 2026-05-26) added a broker channel on `:5300` using the same `AuthenticatedFrame` envelope. **ADR-062 (merged 2026-05-28) rescoped Plan 104** to drop runtime secrets handling as an mvm responsibility — `host.secrets.v1` and the dedicated `mvm-secrets-dispatcher` subprocess on `:5301` are gone; `host.audit.v1` (workload-callable audit emission via the `mvm-broker` subprocess uid 903) takes the broker's first-class slot:

- **`:5300`** — broker channel (host-side, `mvm-broker` subprocess uid 903): hosts `host.time.v1`, `host.cost.v1`, `host.audit.v1`, `broker.v1`. ADR-062's 3-subprocess model — `mvm-broker` for client-facing traffic, `mvm-host-signer` (uid 904) and `mvm-audit-signer` (uid 905) for key-holders behind per-VM UDS, no further vsock listeners.
- **`:5301` — removed.** Was the secrets channel under the pre-ADR-062 design. Don't reference in new specs.

The broker is **host-side** — `mvm-broker` and the signer subprocesses are host-side subprocesses spawned by the supervisor, not guest binaries, so they're outside this plan's pid0 scope. But the wire surface matters for W3 and W4:

- **W3 must cover both vsock ports** (`:5252` agent + `:5300` broker). Same host static Ed25519 pubkey; two independent Noise_NK sessions; the **audit channel (`host.audit.v1` on `:5300`) is the highest-stakes priority** for any encryption rollout because workload-asserted audit entries flow plaintext today and the hypervisor-snooping threat applies to them in the same way it would have to secrets.
- **W4 control-plane-vs-data-plane ADR must name the broker as part of the control plane.** Workload→host service calls (time, cost, audit-emit) carry audit-emitting RPCs and gate on signed `ExecutionPlan.services` bindings — control-plane traffic, not data plane (D3).
- **D2 (Rust defines the conversation) extends to broker types**: `ServiceCall` / `ServiceResponse` envelopes stay Rust-canonical in `mvm-core` alongside `GuestRequest`/`GuestResponse`. Any Zig adoption inherits the same drift-protection constraint.
- **I1 (audit chain) already spans the broker** — Plan 104 funnels all broker calls (including the new `host.audit.v1` workload-emit path) through the supervisor's `AuditEmitter` via the `mvm-audit-signer` subprocess. This plan inherits the integration cleanly; nothing to design.

See `specs/research/agent-evolution-tradeoff-note.md` §"Vsock surface — broader than the agent control channel" for the full table and integration analysis.

## Workstream W1 — Tradeoff note (Track E §"Zig evaluation gates" prerequisite)

Deliverable: `specs/research/agent-evolution-tradeoff-note.md`. No code. Covers both the Zig path and the lean-Rust v2 path so the future decision review has symmetric inputs.

- [ ] Inventory current Rust pid0 dep footprint per binary (cite Cargo.toml line numbers)
- [ ] **Zig path analysis:**
  - [ ] Identify what Zig would and would not displace (`libc` stays via `@cImport`; `nix` 0.29 / `rtnetlink` / `tokio` are the realistic targets)
  - [ ] Toolchain cost: Zig in CI (musl-static cross-compile aarch64 + x86_64), reproducibility story, fuzzer integration (`afl++` works; libFuzzer linkage unproven), `cargo-deny` analog
  - [ ] Auditability comparison with example LoC counts
  - [ ] Risk reduction: what supply-chain attack classes shrink, what new ones appear (Zig stdlib + the Zig compiler itself)
  - [ ] Maintenance: contributor pool, code-review skill, on-call rotation impact
  - [ ] Document the full-agent-rewrite cost (~6,500 LoC of Zig, 6–12 weeks) so the future decision review has it
- [ ] **Lean Rust v2 path analysis:**
  - [ ] Map the dep swaps (`tokio` → `polling` + hand-rolled executor, `serde_json` → `nanoserde` or hand-rolled, `rtnetlink` → `linux-raw-sys` + manual netlink, optional `ed25519-dalek` → `ed25519-compact`)
  - [ ] Estimated transitive-crate reduction (target: 50–70%)
  - [ ] What the agent rewrite costs in Rust (smaller than Zig — same language, same tooling — but still substantial: process supervisor refactor, schema-first protocol, addon split)
  - [ ] Auditability: how the smaller dep tree changes `cargo deny` / advisory exposure
  - [ ] Maintenance: zero new toolchain, contributor pool unchanged
- [ ] **Side-by-side comparison table** with both paths' costs/benefits
- [ ] List open questions for the eventual adoption decision

## Workstreams W2 + W2′ — Paired prototypes of `mvm-guest-netinit`

Target: smallest pid0-class binary (87 lines Rust, drops `tokio` + `rtnetlink` + `netlink-packet-route` if successful). One-shot, no process supervision — isolates the "boundary-code dep-reduction" question from process-supervisor complexity.

Three implementations exist in tree during the evaluation:
1. **Current Rust** (`crates/mvm-guest/src/bin/mvm-guest-netinit.rs`, 87 LoC, today's deps) — the baseline.
2. **Lean Rust v2** (`crates/mvm-guest-netinit-lean/`) — same logic, replace `tokio`/`rtnetlink`/`netlink-packet-route` with `polling` + hand-rolled netlink over `linux-raw-sys`. **This is W2′.**
3. **Zig** (`zig/mvm-guest-netinit/`) — same logic in Zig. **This is W2.**

All three measured against the same rubric. Lean-Rust v2 vs Zig is the fair fight (today's Rust is the unoptimized baseline).

### W2′ — Lean Rust v2 prototype (build first, primary track)

Layout: `crates/mvm-guest-netinit-lean/` as a sibling crate in the workspace. Same Cargo workspace; minimal Cargo.toml.

- [ ] Stand up `crates/mvm-guest-netinit-lean/` with deps limited to `polling` + `linux-raw-sys` + `libc`
- [ ] Implement AF_NETLINK socket + RTM_NEWROUTE messages from raw syscalls (no `rtnetlink` crate, no `netlink-packet-route`)
- [ ] Drop tokio entirely — `polling`-based event handling (one-shot binary, so even simpler than a full event loop)
- [ ] Emit identical `__MVM_NETINIT_REPORT__` marker
- [ ] Exit codes match contract
- [ ] Wire-schema parity test (shares the schema oracle with W2)
- [ ] `cargo-fuzz` harness on the netlink parser (already-known tooling)
- [ ] Reproducible build proof

### W2 — Zig prototype (build second, measurement check)

Layout: `zig/mvm-guest-netinit/` with its own `build.zig`. Top-level `zig/` umbrella keeps Zig artifacts out of cargo's view.

- [ ] Stand up `zig/mvm-guest-netinit/` with `build.zig` (musl-static, aarch64 + x86_64)
- [ ] Port AF_NETLINK + RTM_NEWROUTE installer for `MANDATORY_DENY_RANGES`
- [ ] Emit `__MVM_NETINIT_REPORT__` marker JSON byte-identical to baseline Rust
- [ ] Exit codes match contract (0 success, 1 route failures, 2 systemic rtnetlink failure)
- [ ] Wire-schema parity test (per D2): consume the Rust-canonical report schema; build fails if Rust types drift
- [ ] AFL++ fuzz harness on the netlink parser surface
- [ ] Reproducible build proof (byte-identical rebuilds on both arches — claim 7 invariant)

### Shared verification + measurement (applies to W2 and W2′)

- [ ] Behavioral parity test runner: invoke all three binaries on the same kernel config, diff stdout/stderr/exit/report-marker. Must be byte-identical.
- [ ] CI lane added: build all three binaries; assert byte-identical reproducibility per binary; run each fuzz harness for ≥ 5 minutes per PR; diff behavioral output.
- [ ] Integration: dev-image kernel cmdline selects which binary runs via flake option; default stays current Rust.
- [ ] Measurement table populated in `specs/research/netinit-prototype-measurements.md` with one column per implementation.

Measurement rubric (ordered by primacy per D1):
1. **Dep-tree LOC reaching the guest boundary** — headline number; counted via `cargo tree` + `tokei` for the Rust columns, Zig stdlib modules touched for the Zig column.
2. Transitive crate count + advisory exposure (`cargo audit` applicable, or N/A for Zig).
3. Stripped binary size (musl, aarch64 + x86_64).
4. Compile time cold + warm.
5. Behavioral parity vs baseline.
6. Wire-schema parity (per D2).
7. Fuzz parity: time-to-first-crash on adversarial corpora.
8. Memory ceiling under stress (100k route attempts).
9. Reproducibility (claim 7 invariant).
10. CI cost delta (minutes added per PR).

Items 1, 2, 6 can independently rule out an implementation. The result table feeds the agent-evolution decision: if W2′ already gets 80%+ of W2's dep-reduction win, recommend "lean Rust v2 for the agent, no Zig." If W2 wins decisively, recommend a follow-on plan to evaluate Zig at the agent itself.

## Workstream W3 — Vsock control-plane encryption (paper only)

Deliverable: `specs/research/vsock-control-plane-encryption.md`. No code in this milestone.

**Scope**: both guest↔host vsock surfaces — `:5252` (agent control) and `:5300` (broker — `host.time.v1`, `host.cost.v1`, `host.audit.v1`, `broker.v1`). Same `AuthenticatedFrame` envelope on both; same host static Ed25519 pubkey authenticates both; two independent Noise_NK sessions. **Priority implementation target for any follow-on plan: `:5300` first, specifically the `host.audit.v1` traffic** — workload-asserted audit entries carry the highest-stakes plaintext on the broker today (post-ADR-062 the broker ships on plaintext `AuthenticatedFrame`, consistent with ADR-002's current out-of-scope-for-malicious-hypervisor posture; encrypting `:5300` is the most valuable upgrade). The pre-ADR-062 secrets channel (`:5301`) is gone; do not reference in new specs.

Recommended design (locked):
- **Protocol**: Noise_NK
- **DH**: X25519
- **Cipher**: ChaCha20-Poly1305
- **Hash**: SHA-256
- **Host pubkey distribution**: bake into guest image via `mkGuest { hostPubkey = ./host-signer.ed25519.pub; }` flake parameter, read from `~/.mvm/keys/host-signer.ed25519.pub` at image build time
- **Envelope**: stream-level wrap (post-handshake, every byte through `CipherState::write_message`); `AuthenticatedFrame` signing + sequence# remain intact under the cipher (I1). Each port runs its own session; envelope layering is identical across both.
- **Rust impl pointer**: [`snow`](https://crates.io/crates/snow), small audited
- **Zig impl strategy** (when/if): Noise_NK from scratch (~800 LoC); beats wrapping a C library
- **Coordination point**: any change to `AuthenticatedFrame` in `crates/mvm-core/src/policy/security.rs` is a sync point with the Plan 104 broker work — W3 design must specify the wrap layer precisely so the two efforts can't drift. The secrets-work session driving broker implementation should treat the W3 doc as the encryption contract their future encrypted broker will inherit.

Doc tasks:
- [ ] Write Noise_NK design (full handshake state machine, key schedule, replay handling)
- [ ] Specify `mkGuest { hostPubkey = ...; }` flake parameter and image-build hook
- [ ] Specify envelope layering (stream-level wrap, post-handshake)
- [ ] Document Noise_XK alternative + why rejected (per-boot guest key bootstrap chicken-and-egg)
- [ ] Document TLS_PSK alternative + why rejected (drags rustls into the boundary; contradicts D1)
- [ ] Threat model deltas:
  - [ ] Protects: hypervisor in-memory snooping of vsock buffers, shared-vsock scenarios
  - [ ] Does NOT protect: compromised host (host holds private key)
  - [ ] Does NOT modify: audit chain (signature + sequence# still apply over plaintext-of-cipher)
  - [ ] Out of scope: console PTY data, port-forward TCP relays, virtio-net frames (data plane)
- [ ] Cross-reference ADR-002 §threats, ADR-041, Plan 104 (host-services-broker)
- [ ] Implementation deferred to a follow-on plan that this doc enables

## Workstream W4 — Three new ADRs (drafts, status = proposed)

Numbers are placeholders until commit time — claim against open PRs at commit (memory: spec numbering chaos).

- [ ] **`specs/adrs/NNN-control-plane-vs-data-plane.md`** — promote ADR-053's hint into a contract
  - [ ] Control plane = host ↔ pid0/agent over vsock with `AuthenticatedFrame` (and, post-W3, an encrypted transport)
  - [ ] Data plane = network (passt/gvproxy), virtio-fs, block devices, stdout/stderr, secrets/env, console PTY
  - [ ] Independent enforcement: Plan 102, claim 9, claim 10
  - [ ] Cross-references ADR-053, 055, 058, Plan 64, Plan 102, claims 1–10
- [ ] **`specs/adrs/MMM-pid0-portability-boundary.md`** — what the guest control surface must satisfy regardless of backend
  - [ ] Vsock control transport across Firecracker / libkrun / Apple VZ / Cloud Hypervisor (CID/port convention)
  - [ ] Boot handshake (`ProtocolHello` from `crates/mvm-guest/src/vsock.rs:77+`)
  - [ ] Lifecycle states (boot → ready → workload → drain → shutdown), readiness reporting
  - [ ] What pid0/agent may not do: no host-fs assumptions, no SSH, no shell-out beyond audited verbs, no broad seccomp escape
  - [ ] Cross-platform constraints: musl-static, no `glibc`, kernel-cmdline contract
  - [ ] Explicit non-goal: this ADR does not mandate Zig — Rust + musl-static satisfies it today
- [ ] **`specs/adrs/OOO-boundary-language-policy.md`** — codify Track E's gates as an ADR (reframed from "Zig at the boundary" to "Boundary language policy" so the doc has value even if the Zig answer is "no")
  - [ ] Where any non-Rust language is permitted at the guest boundary: narrow boundary binaries with small ABI surfaces, parser islands, ObjC/Swift shims for VZ
  - [ ] Where non-Rust is not permitted: broad protocol stacks (OCI, PGP, OpenAPI, async runtimes); anything driving the audit chain
  - [ ] Required deliverables per non-Rust adoption: tradeoff note (W1 template), fuzz harness, reproducible-build proof, `cargo-deny`-equivalent supply-chain attestation
  - [ ] Default = Rust. Lean Rust v2 (dep-reduction within Rust) is the always-applicable first path; non-Rust is opt-in evidence-gated.
  - [ ] Rust remains the system spine

## Workstream W5 — Provider capability matrix

Deliverable: `specs/reference/provider-capabilities.md`.

- [ ] Derive from `crates/mvm-core/src/protocol/vm_backend.rs` (`VmCapabilities` struct + `BackendSecurityProfile`)
- [ ] Columns: vsock, virtiofs, snapshotting, egress control, attestation, rosetta, gpu, nested virt, **vsock-encryption support** (new, informs W3 feasibility per backend)
- [ ] Rows: Firecracker, Cloud Hypervisor, libkrun (Linux), libkrun (macOS), Apple VZ, Apple Container, Docker, Mock
- [ ] Add `vsock-encryption-support` field to `VmCapabilities` if a backend needs a column that doesn't exist yet
- [ ] Code-of-truth check: every column maps 1:1 to a struct field, every row maps 1:1 to an `AnyBackend` variant

## Workstream W6 — Threat-model delta + audit invariants on ADR-002

Append §"Threats added in 2026 milestone N" to `specs/adrs/002-microvm-security-posture.md`:

- [ ] Replayed vsock commands — `AuthenticatedFrame` sequence# handles; document where
- [ ] Hypervisor in-memory snooping of control buffers — new; W3 candidate mitigation
- [ ] DNS exfiltration — Plan 102 handles; add explicit threat label
- [ ] stdout/stderr exfiltration — out of scope this milestone; refer to Plan 103
- [ ] Unsafe virtio device exposure — in scope; map to claim 1 + claim 10

Also document I1/I2 as ADR-002 §"Audit invariants under the agent-evolution exploration":
- [ ] Control-plane audit chain (claim 8) must hold across any agent change — cite `AuditEmitter`, `verify_audit_chain`, `mvmctl audit verify`
- [ ] Data-plane audit substrate (Plan 102 / claim 9 / claim 10) — out of scope for modification, in scope for regression-checking

Do not retroactively renumber claims.

## Verification

- [ ] W1 tradeoff note merged to `specs/research/`; reviewed against Track E gates; both Zig and lean-Rust v2 paths analyzed
- [ ] W2 (Zig) prototype runs in a libkrun guest on macOS-arm64 and Linux-x86_64; emits identical `__MVM_NETINIT_REPORT__`; boot via `mvmctl dev up` succeeds with substituted binary
- [ ] W2′ (lean Rust v2) prototype runs in same scenarios with same parity
- [ ] All three implementations (baseline Rust, lean Rust v2, Zig) sit side-by-side in tree; default stays baseline Rust
- [ ] Measurement table populated for all three implementations
- [ ] W3 design doc reviewed; recommended protocol named with rationale; threat-model deltas in W6
- [ ] W4 three ADR drafts committed as proposed; linked from `specs/adrs/README.md` if that index exists
- [ ] W5 capability matrix passes code-of-truth check
- [ ] W6 `cargo test --workspace` green; no claim renumbering

## Expected outcome + branches

**Expected (recommended path):** Outcome B — lean Rust v2 captures most of the win on the netinit binary; Zig delivers a marginal additional reduction that's not worth the toolchain tax for the agent.

Branches:

- **Outcome A — Zig beats lean Rust v2 by >30% on the dep-tree headline metric:** boundary-language ADR keeps Zig open for *future tiny single-purpose addons* (not the agent). Follow-on plan evaluates Zig for `mvm-builder-init`.
- **Outcome B — lean Rust v2 captures most of the win (within ~30% of Zig):** boundary-language ADR says "Rust everywhere by default." Follow-on plan does an agent-v2 refactor (polling + no-tokio + composable handlers + supervisor decoupling + Noise_NK from W3).
- **Outcome C — neither prototype meaningfully shrinks the surface:** stop the prototype track. W3/W4/W5/W6 still land. Encryption is the real win.

In all three branches the four shared workstreams (W3 encryption, W4 ADRs, W5 capability matrix, W6 threat-model delta) commit.

## Non-goals (explicit)

- Rewriting `mvm-guest-agent` in any language (~6,500 LoC for Zig, smaller for lean Rust v2; either way a separate future plan)
- Replacing any backend (libkrun, Firecracker, Apple VZ, Apple Container, Cloud Hypervisor, Docker)
- Implementing vsock encryption (paper only this milestone)
- Replacing `mvm-verity-init` (already minimal — only `libc`)
- Replacing `mvm-builder-init` (stronger second target if W2/W2′ land strong; defer to a follow-on)
- Egress secret detection / stdout exfiltration enforcement (Plan 103 territory)
- Touching Apple VZ Swift shims (ADR-056 / Plan 98 own that surface)
- Renumbering existing claims or ADRs
