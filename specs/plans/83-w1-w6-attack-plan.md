# Plan 83 — Attack plan for Plan 74 W1-W6

**Status:** Proposed
**Date:** 2026-05-14
**Parent plan:** [`74-claim-safe-sandbox-parity.md`](74-claim-safe-sandbox-parity.md)
**ADR:** [`../adrs/048-claim-safe-sandbox-parity.md`](../adrs/048-claim-safe-sandbox-parity.md)

## Why this attack plan

Plan 74 enumerates seven workstreams (W0-W6) but does not pick an
execution order, identify the hard dependencies between them, or
state which artifact has to land before a Shipped/Preview status
flip is allowed. This doc fills that gap so a contributor can pick
up any workstream without re-deriving the strategy.

W0 (claims hygiene + docs guardrails) ships first — it is the
prerequisite for every other workstream because it establishes the
**status table** that every other workstream flips entries in. Once
W0 lands, the new `xtask check-doc-claims` lint blocks marketing
language that runs ahead of implementation. W1-W6 then flip table
rows from Planned → Preview → Shipped as their gates close.

## Dependency graph

```
W0 (claims hygiene)  ─── ships first; gates every claim flip
│
├── W5 (cold-start)         independent, lightest lift
├── W6 (filesystem)          independent, conformance tests
├── W4 (SDK lifecycle)       independent (sits on `mvm-sdk` crate already in tree)
├── W1 (OCI ingest)          independent of W2-W6 but largest greenfield surface
└── W2 (network policy)  ──► W3 (secret placeholders)
                            hard chain: placeholders substitute at the L7 proxy
                            that W2 builds; W3 cannot ship until W2 is Shipped
```

Only one hard chain exists: **W3 depends on W2**. The L7 proxy
that W2 builds is the policy-enforcement point where W3
substitutes placeholders. Without it, W3 reverts to the legacy
env/file injection path which ADR-048 §"Non-goals" explicitly
forbids us from claiming as "secrets cannot leak".

Everything else is parallel-safe.

## Recommended sequencing

### Single-contributor track (optimizes claims-flipping-per-week)

| Order | Workstream         | Why this order                                                          | Rough effort |
| ----- | ------------------ | ----------------------------------------------------------------------- | ------------ |
| 1     | W5 cold-start      | Quickest claim flip — measurement, no new runtime; harness exists       | 1-2 weeks    |
| 2     | W4 SDK lifecycle   | Biggest adoption move; `mvm-sdk` crate already ported, lifecycle missing | 4-6 weeks   |
| 3     | W1 OCI ingest      | Opens the Docker-shaped audience; new code surface                       | 4-6 weeks   |
| 4     | W2 network policy  | Prerequisite for W3; deny-by-default + DNS pin + L7 proxy + SNI/Host    | 4-6 weeks    |
| 5     | W3 secret placeholders | The earlier external sandbox runtime's headline differentiator; rides on W2's proxy (external project referred to obliquely per [[feedback_no_competitor_names_anywhere]]; trait key in auto-memory `reference_external_sandbox_control_plane_oblique_key`) | 3-4 weeks    |
| 6     | W6 filesystem      | Lowest marketing weight; mostly conformance tests + capability flags    | 2-3 weeks    |

Total: ~18-27 contributor-weeks.

### Two-contributor parallel track (faster wall-clock)

- **Track A (adoption):** W5 → W4 → W1.
- **Track B (security):** W6 → W2 → W3. W6 is sequenced ahead of
  W2 on this track because the conformance-test scaffolding is
  needed before we add object-store/encrypted backends that W2 is
  going to want to audit via the same channel.

Total: ~10-14 wall-clock weeks; ~24-32 contributor-weeks total
(the parallel track has overhead — coordination, shared audit
schema decisions).

## Per-workstream attack plan

### W1 — OCI image ingest

**Scope.** `mvmctl image pull <ref>` resolves an OCI reference to
an immutable digest, fetches layers, unpacks to an ext4 rootfs,
records the manifest's entrypoint/env/workdir/exposed-ports, and
registers the result as a first-class template consumable by
`mvmctl up --image`. No host Docker daemon, no shell-out to
`skopeo`.

**Hard dependencies.** None on W2-W6. Pulls into existing
template registry (`mvm-core/src/template.rs`) and template
build path (`mvm-build/src/dev_build.rs`).

**Key new code.**
- `crates/mvm-oci/` — registry resolution, auth (Bearer + Basic),
  manifest fetch, layer fetch, digest verification, max-size and
  layer-count caps.
- `crates/mvm-build/src/oci_to_rootfs.rs` — layer unpack with
  whiteouts, symlinks, hardlinks, ownership/permissions, xattr
  policy.
- `crates/mvm-cli/src/commands/image/pull.rs` — CLI surface.
- Audit kinds in `mvm-core/src/policy/audit.rs`:
  `oci.resolve`, `oci.fetch`, `oci.cache.hit`,
  `oci.materialize`, `oci.verify`, `oci.launch`, `oci.delete`.

**Shipped gate (ADR-048 §"OCI ingest").**
- `mvmctl image pull <ref>` resolves an immutable digest and
  records requested ref + launched digest in the template.
- Production profile rejects mutable tags
  (`policy::profile::production`); dev profile allows them with
  audit.
- Layer unpacking covers whiteouts, symlinks, hardlinks,
  ownership, permissions, entrypoint, env, workdir, exposed
  ports.
- Rootfs artifacts are tenant/cache scoped — no cross-tenant
  read.
- Tests cover digest pinning, mutable-tag rejection, private
  registry auth, whiteout behavior, secret/cache non-leakage.

**Status-table transitions.**
- Planned → **Preview** when `image pull` materializes Alpine
  end-to-end with digest pinning, but mutable-tag rejection and
  full whiteout coverage are not yet in.
- Preview → **Shipped** when every gate bullet above is green
  and a hermetic local-registry integration test runs in CI.

**Suggested PR breakdown.**
1. `mvm-oci` crate skeleton + manifest fetch + digest verify
   (no unpack yet). Unit tests against a fixture manifest.
2. Layer fetch + digest verify + bounded retry. Hermetic
   in-process registry fixture for tests.
3. Layer unpack with whiteouts/symlinks/hardlinks; conformance
   tests against the OCI test corpus.
4. CLI surface (`image pull/ls/rm`); template registration
   plumbing.
5. `mvmctl up --image <ref>` + production-profile mutable-tag
   rejection + audit emission.
6. Doc page in `public/src/content/docs/guides/oci-images.md`
   and status-table flip to Shipped.

**Risk.** Largest greenfield surface. The hard part is policy:
once we accept arbitrary OCI input, the "Nix-built reproducible
rootfs" claim (claim 7 of the security model, deterministic
double-build CI) no longer applies to pulled images. The page
must say this explicitly. Verified-boot (claim 3) requires
generating dm-verity sidecars per pulled image — straightforward
mechanically (we have `verityArtifacts` in `nix/flake.nix`) but
adds non-trivial wall-clock to each pull.

**Cross-repo handoff to mvmd.** Tenant image policy and registry
allow-list rules (mvmd ADR-0020) consume `mvm-oci` as a library;
mvmd never spawns a parallel pull path.

### W2 — Programmable network policy

**Scope.** Supervisor-owned DNS resolver with admission-time
pinning, L7 trusted proxy that all guest egress flows through
under restricted policies, HTTP-Host and HTTPS-CONNECT/SNI
enforcement, default block on metadata endpoints and
local control-plane ranges.

**Hard dependencies.** Builds on existing L3 allow-list and
ADR-004 (egress policy). No dependency on W1, W4-W6.

**Key new code.**
- `crates/mvm-supervisor/src/network/dns.rs` — pinning resolver.
- `crates/mvm-supervisor/src/network/proxy/` — L7 proxy
  (HTTP + HTTPS CONNECT + SNI inspection).
- `crates/mvm-core/src/policy/network.rs` — per-plan
  `NetworkPolicy` type with explicit defaults.
- Audit kinds: `net.allow`, `net.deny`, `net.dns.pin`,
  `net.dns.reject`, `net.proxy.fail`.

**Shipped gate (ADR-048 §"Programmable network policy").**
- `deny` is a first-class default policy in a `production`
  profile.
- DNS answers for allowed names are pinned for workload lifetime.
- HTTP Host and HTTPS SNI verified against policy.
- `169.254.169.254` and local control-plane ranges blocked by
  default.
- Audit records emitted for allow, deny, DNS pin, DNS reject,
  proxy failure.
- Integration tests prove DNS rebinding, raw-IP bypass,
  wrong-SNI, metadata access are denied.

**Status-table transitions.**
- Planned → **Preview** when the L7 proxy can enforce Host/SNI
  for a single fixed policy, but per-plan policy objects are not
  yet wired.
- Preview → **Shipped** when per-plan `NetworkPolicy` objects
  flow through the signed `ExecutionPlan`, all gate bullets are
  green, and the DNS-rebinding + raw-IP bypass + wrong-SNI tests
  pass in CI.

**Suggested PR breakdown.**
1. Pinning DNS resolver + per-plan A/AAAA cache. Unit tests.
2. L7 proxy scaffold (HTTP Host enforcement). Integration test
   against a fixture origin.
3. HTTPS CONNECT + SNI policy. Test for wrong-SNI denial.
4. Default-block metadata + local control-plane ranges. Test
   for `169.254.169.254` denial.
5. Per-plan `NetworkPolicy` type + admission wiring + audit.
6. Doc page in `public/src/content/docs/guides/network-policy.md`
   and status-table flip.

**Risk.** TLS interception is the dragon. We do NOT MITM TLS —
SNI inspection only. State this clearly so users understand the
proxy enforces *destination policy*, not *content policy*.
Document the interaction with verified-boot: the proxy lives in
the supervisor on the host, not in the guest, so it does not
extend the verified-boot chain.

### W3 — Secret placeholders and host-side substitution

**Scope.** Default secret flow gives the guest only an opaque
placeholder string. Real secret values are substituted by the
host-side egress proxy after destination policy passes. Grants
revoke on stop/crash/timeout/parent-death. Legacy env/file
injection stays behind `unsafe_guest_secret_materialization`.

**Hard dependencies.** **W2 must be Shipped first.** The
substitution point is the L7 proxy that W2 builds. Cannot ship
this without a trusted proxy that sees every egress connection.

**Key new code.**
- `crates/mvm-core/src/secrets/placeholder.rs` —
  `SecretPlaceholder` (token, plan id, name, allowed
  destinations, expiry, grant id).
- `crates/mvm-supervisor/src/secrets/grant_registry.rs` —
  grant lifecycle, revocation hooks.
- `crates/mvm-supervisor/src/network/proxy/substitution.rs` —
  request body / header rewrite at proxy.
- Redaction wrappers in `mvm-core/src/policy/audit.rs`,
  `mvm-cli/src/logging.rs`, plan JSON, error messages.

**Shipped gate (ADR-048 §"Secret non-leakage").**
- Default SDK/CLI flow gives the guest only an opaque
  placeholder.
- Real secret values never appear in guest env, files, argv,
  logs, audit detail, plan JSON, cache keys, route labels, error
  messages, or panic output.
- Substitution is bound to destination policy and transport
  identity (SNI/Host match).
- Grant revocation on stop, crash, timeout, parent-process
  death.
- Tests cover hostile-guest exfiltration attempts, destination
  mismatch, redirect chains, wrong SNI, plaintext HTTP, audit
  redaction, crash cleanup.

**Status-table transitions.**
- Planned → **Preview** when placeholder + substitution work
  end-to-end for one provider (e.g. Anthropic), but `redacted`
  formatting is missing in some audit paths.
- Preview → **Shipped** when every redaction wrapper is in
  place, and hostile-guest exfiltration tests run in CI.

**Suggested PR breakdown.**
1. `SecretPlaceholder` type + serde + tests; opaque `Display`
   (already covered by `xtask check-no-display-on-secret-types`).
2. Grant registry + lifecycle hooks (stop/crash/timeout/parent).
3. Substitution logic in the W2 proxy. Hostile-guest tests.
4. Redaction wrappers across plan JSON, logs, audit, errors,
   cache keys, route labels.
5. Default-flow flip in `mvm-sdk` and `mvmctl up`; legacy path
   behind `unsafe_guest_secret_materialization`.
6. Doc page in `public/src/content/docs/security/secret-placeholders.md`
   and status-table flip.

**Risk.** The ADR's gate bullet "Real secret values never appear
in ... panic output" is hard. Rust panic messages can carry
arbitrary captured `Debug` output. We need a panic hook that
redacts known-secret payloads, and a `xtask` lint that catches
new `format!("{e:?}")` of secret-typed errors. ADR-048
§"Non-goals" explicitly forbids claiming this for the legacy
env/file path — make sure the status table row stays Preview
until the default flow is the placeholder path.

### W4 — SDK-owned lifecycle

**Scope.** Python/TypeScript/Rust SDKs expose the same lifecycle
surface — `create`, `exec`, `files.read/write/list/remove`,
`logs`, `snapshot`, `fork`, `stop`, `destroy` — over a stable
local control API. Sandboxes are owned by the SDK process;
parent-death triggers cleanup unless `detach=true`.

**Hard dependencies.** None. Rides on `crates/mvm-sdk` (already
ported per Plan 60). The lifecycle ports onto the existing
`up`/`stop`/`exec`/`logs` plumbing without rewriting it.

**Key new code.**
- `crates/mvm-sdk/src/lifecycle.rs` — core lifecycle contract +
  Rust binding.
- `python/` — pyo3 binding (already specified in Plan 60
  Phase 5).
- `typescript/` — napi-rs binding.
- `crates/mvm-supervisor/src/lease.rs` — parent-process lease
  using `prctl(PR_SET_PDEATHSIG)` on Linux,
  `pthread_kill_other_threads_np`/parent-pid watcher on macOS.
- `crates/mvm-cli/src/commands/sandbox/` — `mvmctl sandbox ls`
  for detached sandboxes.

**Shipped gate (ADR-048 §"SDK lifecycle").**
- Python, TS, and Rust SDKs expose the same surface.
- SDK-created sandboxes are owned by the SDK process unless
  `detach=true`.
- Parent death triggers sandbox cleanup or documented lease
  expiry.
- Lifecycle surface works without importing or executing
  untrusted user code during static compilation
  (the existing `mvmctl compile` AST-walk path stays).
- Tests cover create, exec, files.*, logs, snapshot, stop,
  parent cleanup, error redaction.

**Status-table transitions.**
- Planned → **Preview** when Rust + Python surfaces are
  functional but the TS binding is not.
- Preview → **Shipped** when all three SDKs run the same fixture
  suite, and parent-death cleanup test is green on Linux + macOS.

**Suggested PR breakdown.**
1. Rust `lifecycle` module + parent-process lease + cleanup
   test on Linux.
2. macOS parent-pid watcher; same cleanup test on macOS CI.
3. `mvmctl sandbox ls` for detached sandboxes; audit on
   create/destroy.
4. Python binding (pyo3) + shared fixture suite.
5. TypeScript binding (napi-rs); same fixture suite passes.
6. Doc page in `public/src/content/docs/guides/sdk-lifecycle.md`
   and status-table flip.

**Risk.** Cross-platform parent-death handling. Linux gets
`PR_SET_PDEATHSIG` for free; macOS needs a watcher thread or a
kqueue `EVFILT_PROC NOTE_EXIT` subscription. Get this right or
the "cleanup bound to parent" claim is false on macOS.

### W5 — Cold-start measurement and budgets

**Scope.** Extend `runtime_boot_bench` and
`cargo xtask perf boot` into one canonical harness that reports
fresh start-return, guest-agent-ready, snapshot restore,
warm-pool claim, and SDK create-to-exec separately. Publish
numbers with full host/backend/kernel/rootfs context.

**Hard dependencies.** None. The harness exists; this is
consolidation + reporting + CI budget gates.

**Key new code (mostly refactors).**
- `crates/mvm/src/perf/harness.rs` — single canonical harness.
- `xtask/src/perf.rs` — extend with a `report` subcommand that
  emits a markdown table under `specs/perf/`.
- `specs/perf/` — checked-in benchmark reports per host/backend.
- `.github/workflows/perf.yml` — CI budget gates for
  representative artifacts; regression diff against prior report.

**Shipped gate (ADR-048 §"Cold-start").**
- Harness records host, backend, kernel/rootfs digest, CPU
  model, memory, vCPU count, storage mode, readiness signal.
- Numbers published as p50/p95/p99/max with readiness boundary
  named.
- Fresh boot, guest-agent-ready boot, snapshot restore,
  warm-pool claim reported separately.
- CI enforces regression budgets for representative artifacts.

**Status-table transitions.**
- Planned → **Preview** when one canonical report runs on one
  host and one backend (e.g. macOS Apple Silicon + libkrun).
- Preview → **Shipped** when the harness runs on at least two
  backends, CI budget gates are green for ≥1 week, and
  `specs/perf/` carries a published report.

**ADR-048 §"Non-goals" constraint.** **Do NOT claim sub-100ms
cold boot until p95 fresh guest-agent-ready supports it.** It is
acceptable to claim faster warm-pool or snapshot numbers
*labeled as such*. The gated phrase regex in W0's
`check-doc-claims` will block any unqualified `<100ms` claim
until the cold-start status row is flipped to Shipped *and* the
docs that quote the number sit on the status-table page.

**Suggested PR breakdown.**
1. Consolidate `runtime_boot_bench` + `xtask perf boot` into
   one harness; emit JSON.
2. Add markdown `report` subcommand; commit first report under
   `specs/perf/`.
3. CI workflow `perf.yml` + budget gates.
4. Doc page in `public/src/content/docs/reference/performance.md`
   with the published numbers + methodology link.

**Risk.** Numbers that disappoint. The earlier external sandbox runtime markets
<100ms; we may be at 200-500ms on Firecracker cold boot with
audit append and plan signing in the path. That is OK — publish
the truth + warm-pool/snapshot numbers separately. Do not try to
hide it behind misleading phrasing; the `check-doc-claims` lint
will catch it.

### W6 — Extensible filesystem backends

**Scope.** Split the storage contract into mountable + API-only
capability flags. Add conformance tests reused by every backend
(local, encrypted, object store, memory). Define consistency /
rename semantics for object stores. Cover path traversal,
symlink escape, concurrent write, large-file edge cases.

**Hard dependencies.** None. Builds on existing
`crates/mvm-storage` `VolumeBackend` trait.

**Key new code.**
- `crates/mvm-storage/src/capability.rs` — `Mountable` vs
  `ApiOnly` capability flags.
- `crates/mvm-storage/tests/conformance.rs` — single conformance
  suite reused per backend.
- `crates/mvm-storage/src/backends/object_store.rs` — semantics
  for consistency, rename, partial-write, health.
- Audit kinds: `volume.attach`, `volume.detach`, `volume.read`,
  `volume.write`, `volume.delete`, `volume.rename`,
  `volume.snapshot`, `volume.backend.health.fail`.

**Shipped gate (ADR-048 §"Filesystem backends").**
- `VolumeBackend` / filesystem contract has conformance tests
  reused by every backend.
- Docs distinguish mountable from API-only backends.
- Encrypted backends encrypt content + names where promised.
- Object-store backends define consistency, rename,
  partial-write, health semantics.
- Tests cover path traversal, symlink escape, concurrent writes,
  large files, deletion, rename, audit.

**Status-table transitions.**
- Planned → **Preview** when the conformance suite passes for
  local + memory backends but encrypted/object-store are
  incomplete.
- Preview → **Shipped** when all four backends pass conformance
  + the path-traversal/symlink-escape negative tests run in CI.

**Suggested PR breakdown.**
1. Capability flag split + minimal `Mountable` / `ApiOnly`
   plumbing. No behavior change.
2. Conformance test scaffold; local + memory backends pass.
3. Encrypted backend (content + name encryption); conformance +
   ciphertext-shape tests.
4. Object-store backend (S3-API); conformance + consistency +
   rename + partial-write tests.
5. Audit emission across attach/detach/read/write/etc.
6. Doc page in `public/src/content/docs/reference/storage-backends.md`
   and status-table flip.

**Risk.** Encrypted-backend "names where promised" — this is
optional per the ADR ("where promised"). Decide up front whether
the encrypted backend encrypts names; document the decision.
Object-store consistency under concurrent writes is fundamentally
weaker than ext4 — the contract MUST state this explicitly.

## Cross-cutting concerns

### CI gates per claim

Each Shipped status flip requires a corresponding CI lane to
exist *before* the flip:

| Claim                 | CI gate that must be green                                  |
| --------------------- | ----------------------------------------------------------- |
| oci-ingest            | Hermetic-registry integration job + digest-pin negative test |
| network-policy        | DNS rebinding + raw-IP bypass + wrong-SNI denial tests       |
| secret-non-leakage    | Hostile-guest exfiltration + redaction sweep tests           |
| sdk-lifecycle         | Same fixture suite green on Linux + macOS, 3 SDKs            |
| cold-start            | Budget gate green for ≥1 week + published `specs/perf/` report |
| filesystem-backends   | Conformance suite green per backend + traversal/escape tests |

A status flip PR must include the workflow change *and* the
status-table edit in the same commit. Otherwise the
`check-doc-claims` lint can't be trusted as the gate (table
edit without CI = false Shipped; CI without table edit = wasted
gate).

### Status-table flip discipline

Flipping a row from Planned → Preview or Preview → Shipped is
the moment that unblocks marketing language. The flip is a
two-line edit (the `<!-- claim:foo status:Preview -->` marker
and the visible table cell). Combine it with:

1. The CI workflow change that enforces the gate.
2. A new doc page (or section) under
   `public/src/content/docs/`.
3. An update to the per-claim "what would move it to Preview /
   Shipped" mini-section on
   `public/src/content/docs/security/sandbox-parity-status.md`
   to reflect the new baseline.

### Definition of done per workstream

A workstream is "done" when:

1. All ADR-048 gate bullets are checked.
2. The status-table row is flipped to Shipped and the CI
   workflow that enforces the gate is in `.github/workflows/`.
3. A user-facing doc page exists (not a placeholder).
4. `cargo test --workspace` + `cargo clippy --workspace
   --all-targets -- -D warnings` clean on host.
5. Linux-only tests (vsock, jailer/seccomp, dm-verity, network
   namespaces) pass in the builder VM per AGENTS.md.
6. `specs/SPRINT.md` updated to reflect completion.
7. The `cargo xtask check-doc-claims` lint stays clean after
   the flip (i.e., the new docs that quote previously-gated
   phrases now legitimately have the Shipped marker).

## Risks

The eight cross-cutting risks (R1-R8) plus the "Risks resolved since
plan was written" note live in the parent plan
[`74-claim-safe-sandbox-parity.md` §"Risks"](74-claim-safe-sandbox-parity.md#risks).
That section is the canonical reference — owners, current evidence,
mitigation assignments. This sidecar does not duplicate; pick up the
relevant Rn entry when starting a workstream and check it against
current code state before kicking off.

Quick map from workstream to load-bearing risks:

| Workstream | Risks that affect kickoff   |
| ---------- | --------------------------- |
| W1 OCI     | **R3** (verity A or B before code lands), **R10** (layer-unpack CVE class), **R13** (runtime overlay disk gates W1.3-W1.4), R8 |
| W2 network | R1, **R4** (audit backpressure), R6, **R9** (TLS substitution mechanism), **R11** (non-HTTP egress), **R12** (DoH/DoT bypass), R8 |
| W3 secrets | R1, **R2** (panic hook is new), R5 (snapshot interaction), R6, **R9** (substitution mechanism gates W3 entirely), R11 (non-HTTP secret channels), R13 (SDK runtime is in the overlay), R8 |
| W4 SDK     | R6 (macOS kqueue parity), R13 (SDK lifecycle binaries live in the overlay), R8 |
| W5 perf    | R7 (publish every readiness boundary), R8 |
| W6 storage | R4 (new audit kinds), R8 |

**R3, R9, and R13 are now decided** —
[ADR-050](../adrs/050-oci-image-verity-posture.md) picks pull-time verity
generation for W1, [ADR-049](049-secret-substitution-mechanism.md)
picks the vsock side-channel for W3 (with proxy-with-CA available
later as an explicit opt-in feature flag), and
[ADR-051](051-mvm-runtime-overlay-disk.md) introduces a separate
verity-sealed mvm-runtime overlay disk that hosts the guest
agent, seccomp shim, runner, and per-language SDK runtime
libraries for *every* microVM (Nix-built and OCI-pulled alike),
unifying the agent placement story. ADR-051 also forces a
one-time refactor of `mkGuest` to stop baking those binaries
into per-image closures. The remaining top-level risks (R1, R2,
R4-R8, R10-R12) stay open and reference the parent plan.

## Verification

This doc is descriptive. To check its claims:

- Status taxonomy + seven claims: `specs/adrs/048-claim-safe-sandbox-parity.md`.
- W0 lint behaviour: `xtask/src/check_doc_claims.rs` (after
  W0 lands) + inline unit tests.
- mvmd handoff: mvmd ADR-0020 in the sibling repo (cross-repo
  reference; not in this tree).
- Builder-VM transition state:
  `specs/plans/72-libkrun-builder-vm.md` (or successor) and the
  memory note `project_builder_vm_being_replaced.md`.
