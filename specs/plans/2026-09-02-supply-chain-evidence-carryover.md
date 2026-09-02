# Supply-Chain Evidence Carryover Plan

Date: 2026-09-02
Status: PROPOSED
Repos: `mvm` (this repo), `mvmd`, `mvm-studio`, `mvm-assurance`

## Context

A competitor's product in the artifact-provenance space is deployed at a
prospective customer. Their pitch rests on three verbs — tag every artifact
with signed provenance at build time, track artifacts into production with
runtime beacons, and trust the result because the evidence is verifiable, not
inferred. Their marketing poses a fixed set of questions a user can ask
("which of our code is in production?", "where did this artifact come from?",
"who built it?", "what dependencies are actually in this build?", "are we
exposed to CVE X?").

Our platform already has the cryptographic substrate to answer every one of
those questions — but the answers are scattered across CLI verbs, sidecars,
and unwired library seams, and several of the questions have no query surface
at all. This plan closes those gaps. It is written without naming the
competitor anywhere in code, commits, PRs, or docs.

## What we confirmed exists (evidence base)

### `mvm` (first-hand)

- Build provenance content-addressed into the signed plan:
  `crates/mvm-build/src/provenance.rs` (`record_provenance`), plan id re-derived
  before signing at `crates/mvm-core/src/plan/signing.rs:50-73`.
- Local-first deploy records with exact-byte digests:
  `crates/mvm-sdk/src/deploy.rs:36-109` (`DeployRecord` v2), stored under
  `~/.mvm/deployments/<ir-hash>`.
- Chain-signed, genesis-sealed, per-tenant append-only audit log with Merkle
  roots, inclusion proofs, PROV-O export, and `.mvmev` evidence archives:
  `crates/mvm-hostd/src/supervisor/audit_file.rs`, `crates/mvm-hostd/src/audit/`.
- Witness sink for off-host root publication:
  `crates/mvm-hostd/src/audit/witness.rs` (HTTP/file, fail-open, documented
  limits in the module header).
- dm-verity verified boot (tampered rootfs refuses to boot, MVM-SEC-03).
- Host-signed attestation export/verify with nonce and boot measurement;
  hardware providers are stubs (`AttestationMode` in
  `crates/mvm-contract/src/plan/types.rs:1014-1032`,
  `crates/mvm-core/src/crypto/attestation/provider.rs`).
- CycloneDX SBOM + CVE scan sidecars on hash-locked dependency volumes:
  `crates/mvm-sdk/src/compile/deps_audit.rs`.
- Signed, content-addressed `.mvmpkg` packs and publisher trust store:
  `crates/mvm-cli/src/commands/bundle/`, `trust/`.
- `mvmctl explain <run-id>` answers "what happened in this run" from the
  verified chain.

### `mvmd` (first-hand; note this is the V1 from-scratch rewrite)

- 9 crates: `mvmd`, `mvmd-core`, `mvmd-types`, `mvmd-api`, `mvmd-mvm`,
  `mvmd-rama`, `mvmd-iroh`, `mvmd-veilid`, `mvmd-conformance`.
- REST surface (`crates/mvmd-api/src/lib.rs:136-152`): `/v1/fleet`,
  `/v1/nodes`, `/v1/instances`, `/v1/nodes/{id}/reconcile`,
  `/v1/billing/account`, `/v1/mailboxes/{id}/{messages,lease,ack}`.
  **No** deployment/provenance/audit/SBOM/attestation query endpoints.
- Digest-bound placement chain: `crates/mvmd-types/src/placement.rs` binds
  `workload_digest`, `execution_plan_digest`, `receipt_digest`, and the signed
  plan envelope into permits/leases. This is the natural anchor for
  deployment truth.
- Hash-chained usage receipts (BLAKE3, chain-digest validation,
  replay protection): `crates/mvmd-core/src/billing.rs:30,141-152`.
- Node heartbeats with 30 s freshness gating placement
  (`crates/mvmd-core/src/scheduler.rs:4,60-61`).
- SQLite store (WAL). **No** fleet audit journal, no provenance/SBOM store,
  no standards-format attestation anywhere.

### `mvm-studio` (first-hand)

- Tauri 2 desktop app; single Machines page rendering only
  `{id, name, status}` (`ui/src/lib/tauri.ts:29-34`).
- The verified audit-reading seam `LocalAuditReader` already ships in
  `mvm-client` (`crates/mvm-client/src/audit/mod.rs`, first-hand from the mvm
  repo) and is entirely unwired in studio.
- Gateway sidecar runs with an ephemeral memory store + temp data dir per
  launch (`src-tauri/src/sidecar.rs`) — nothing durable survives restarts.

### `mvm-assurance` (first-hand)

- `mvm-scout`: deterministic scanning; reports in Markdown, JSON, SARIF,
  NDJSON (`crates/mvm-assurance-report/src/lib.rs`).
- `scoutd` extension pack ships an SPDX SBOM and an embedded signature block
  (`extensions/scoutd/extension-pack.json:92-93`).
- No publisher trust root (all packs signed with ephemeral keys), no
  in-toto/DSSE/SLSA interchange, and no certifying result without hardware
  attestation.

## What the competitor gets right (carryover principles)

1. **The identity travels with the artifact.** Correlation dies when an
   artifact leaves your database. We must make provenance portable and
   self-verifying inside the artifact itself.
2. **"Which of our code is in production?" is the killer query.** Simple,
   asked constantly, answered nowhere in our surface today.
3. **Adoption must be five lines of YAML and fail-open.** The build must
   never break because of us. Frictionlessness wins deals.
4. **SBOM is a byproduct of the build, not a step.** Record what actually
   ended up in the artifact; diff it against what was declared.
5. **Beats beat registries.** Workloads that self-report at startup give
   real-time deployment truth with zero polling infrastructure.
6. **Third-party verifiability.** Evidence published to an external
   transparency service is auditable without trusting us.
7. **Desktop capture of AI coding sessions is the new front of the chain.**
   Signed record of what the agent did, at the machine, before the commit.

## Workstreams

### WS1 — Deployment truth: beacon, registry, and the "prod or not" query

The competitor's core demo is answering "what version of what code is running
in which environment, right now?" We have all the raw truth (deploy records,
digest-bound placement, heartbeats) and no query that joins it.

- [x] WS1.1 (mvm): guest startup beacon. Shipped as broker service
      `host.beacon.v1`: on boot `mvm-agentd` reports `{agent_version,
      boot_unix_ms}` over the existing vsock broker channel; the host
      handler stamps the supervisor-authoritative identity from
      `ServiceCallCtx` and appends a chain-signed
      `lifecycle.beacon_reported` entry through the audit-signer
      (`crates/mvm-hostd/src/broker/handlers/host_beacon_v1.rs`). Identity
      is host-bound by construction — the guest payload cannot express
      `workload_id`/`tenant_id` (`deny_unknown_fields`), unlike a
      guest-asserted `workload_audit` entry. Default-on: registered
      whenever the audit-signer UDS is present; a 1 token/s rate limit
      bounds chain bloat under a hostile guest; guest-side fail-open with
      bounded retries (3 tries, 2 s apart). Plan-policy suppression seam
      (a `SubprocessConfig` flag sourced from plan policy) is the
      designed follow-up — deferred to the mvmd environment-model work.
      Tests: socket-pair client envelope tests, mock-signer handler tests
      (authoritative stamping, guest-spoof refusal, rate limit, signer
      error mapping), retry-helper tests.
- [ ] WS1.2 (mvmd): persist launch records. Placement already binds
      `workload_digest`/`execution_plan_digest` (`mvmd-types/src/placement.rs`);
      add a durable `launches` table keyed by `(fleet, environment, workload_id)`
      recording plan digest, environment, permit id, and beacon arrival.
- [ ] WS1.3 (mvmd): query endpoints `GET /v1/deployments` and
      `GET /v1/deployments/{workload_id}` returning environment × version
      truth, plus `environment` as a first-class attribute on start requests.
      BDD scenarios in `mvmd-conformance`.
- [x] WS1.4 (mvm): `mvmctl deployments ls [--workload Y] [--json]` over the
      local `<mvm_home>/deployments/` store for the no-control-plane path
      (`mvmctl deployments ls`, `mvm_sdk::deploy::list_deployments`).
      Unreadable records surface as named skips rather than failing or
      hiding the listing. `--env` filtering waits for the environment
      model (WS1.3) — deploy records today pin only the kernel digest,
      not an environment name. Row shape is designed to match the future
      mvmd response so studio renders one type.
- [ ] WS1.5 (mvm-studio): Deployments page consuming 1.4 / the mvmd endpoint.
- Tests (all repos): positive, wrong-fleet/role negative, stale-beacon path.

### WS2 — Verity-sealed in-artifact provenance mark

Their core mechanism is an embedded signed mark. Our stronger version: write
the signed provenance record into the sealed rootfs **before** the dm-verity
hash is computed, so the mark is not only embedded in the artifact but
refuses to boot if tampered — tamper-evidence enforced by the kernel, not
just a signature check.

- [ ] WS2.1 (mvm-build): emit `ProvenanceMark` (canonical JSON, Ed25519-signed:
      plan id, input digests, builder identity, timestamp, SBOM reference)
      into the rootfs at `/mvm/provenance.json` + detached signature during
      seal, before verity sidecar generation. Gate behind a plan/build flag,
      default on for new builds.
- [ ] WS2.2 (mvm): `mvmctl artifact inspect <image|rootfs>` reads and verifies
      the mark offline (verity-aware: report whether the artifact's roothash
      matches a recomputation). Docker/OCI images additionally get the mark
      as OCI manifest annotations so registries carry it.
- [ ] WS2.3 (mvm-assurance): `mvm-scout artifact` scan mode verifies a foreign
      artifact's mark if present and reports it as a finding — so our
      scanning story also recognizes third-party marked artifacts.
- Tests: roundtrip seal→inspect→verify; tampered mark → boot refusal and
  inspect failure; mark survives registry push/pull (OCI annotations).

### WS3 — Standards interchange: DSSE-signed in-toto provenance statements

Our provenance is bespoke canonical JSON. Compliance teams ask for SLSA-style
statements. Emit them without changing our internal model — serialization
decision only.

- [ ] WS3.1 (mvm-build): emit an in-toto Statement (SLSA v1.0 provenance
      predicate) as a DSSE envelope at seal time, signed with the builder
      Ed25519 key; optional keyless Sigstore signature using the existing
      `sigstore-verify` dependency family. Ship alongside the artifact and
      record its digest in the audit chain.
- [ ] WS3.2 (mvm-assurance): DSSE-wrap scout reports and the `scoutd` pack
      provenance block; verify on admission in `verify_pack_at`
      (`mvm-core/src/packs.rs`). SPDX already exists for scoutd — keep.
- [ ] WS3.3 (mvmd): accept and store the statement digest at
      `/v1/deploy-artifacts`-equivalent upload; expose it in the deployment
      query response (WS1.3).
- Tests: statement roundtrip, wrong-key rejection, digest binding to the
  audit chain.

### WS4 — External transparency publication

Our Merkle roots are self-signed and local. Extend the existing witness sink
to publish to a public transparency log so auditors don't have to trust us.

- [ ] WS4.1 (mvm): extend `mvm-hostd/src/audit/witness.rs` `HttpWitnessSink`
      with a Rekor/SCITT-compatible publisher (the SCITT capsule design in
      `specs/2026-08-25-scitt-integration-and-hash-chained-action-state.md`
      is the starting point). Publish `SignedAuditRoot`; keep the current
      sink as fallback. Fail-open with an `audit.witness_failed` event.
- [ ] WS4.2 (mvm): `mvmctl trust audit verify --against <log>` re-checks
      inclusion of witnessed roots online.
- [ ] WS4.3 (mvm): verify the pack `transparency_log` reference
      (`TransparencyLogReference`, `mvm-core/src/packs.rs:337-356`) against
      the real log instead of accepting it as metadata.
- Tests: published root inclusion proof verifies; withheld root detects
  fork; offline fallback path.

### WS5 — Hardware attestation providers

The single biggest gap — every real attestation-dependent result today is
`INCONCLUSIVE`. The challenge/join machinery is complete and fail-closed;
only the providers are stubs.

- [ ] WS5.1 (mvm): implement the TPM2 provider end-to-end on Linux
      (`crypto/attestation/tpm2.rs`, `tss-esapi` already behind the
      `attestation-tpm2` feature): AK quote against enrolled EK/manufacturer
      roots, returning `RuntimeAttestationVerification`.
- [ ] WS5.2 (mvm): implement a SEV-SNP verifier (VCEK/ASK/ARK collateral
      validation) behind its existing feature gate; same shape as 5.1.
- [ ] WS5.3 (mvm + mvm-assurance): collateral enrollment tooling + docs;
      re-run the live canary so `assurance.attestation_verified` is real and
      the campaign verdict can certify.
- Tests: quote verify positive/negative (tampered quote, wrong collateral,
  expired), fail-closed when device absent.

### WS6 — SBOM as build byproduct + exposure queries

- [ ] WS6.1 (mvm-build): capture the actual dependency set observed during
      build (what the installer fetched — `fetch.log` already records every
      URL) and diff against the declared manifest; emit CycloneDX **and**
      SPDX for built images, not just dep volumes.
- [ ] WS6.2 (mvm): `mvmctl deps audit --exposed <CVE>` joins the local CVE
      sidecars with deployment truth from WS1.4 to answer "are we exposed,
      and where?".
- [ ] WS6.3 (mvm-studio): exposure view (WS1.5 + WS6.2 join).
- Tests: mutation between manifest and build is detected and reported.

### WS7 — Studio query surface

- [ ] WS7.1 (mvm-studio): wire `LocalAuditReader` (`mvm-client`) into an
      Audit Trail page — verified, cursor-paginated, per-machine trail. No
      backend changes required; the seam exists.
- [ ] WS7.2 (mvm-studio): render the provenance fields already present on
      `MachineState` (`revision`, `flake_ref`, `profile`) in a machine
      detail panel.
- [ ] WS7.3 (mvm-studio): durable gateway mode — persistent data dir and
      token reuse instead of per-launch ephemeral state, so audit and
      deployment history survive restarts.
- Tests: UI typecheck/build CI already present; add component tests for the
  new pages.

### WS8 — CI integration and fail-open adoption

- [ ] WS8.1 (mvm): publish a GitHub Action + GitLab CI template
      (five YAML lines) that wraps a build with `mvmctl build`, emits the
      WS3.1 statement, and uploads it. Fail-open: on any mvm failure, rerun
      the original build command untouched.
- [ ] WS8.2 (mvm): a verify-mode action that fails the pipeline when an
      artifact's mark/statement doesn't verify (strict mode, opt-in).
- Tests: hermetic pipeline fixture; failure injection proves fail-open.

### WS9 — Desktop AI-session capture (research → phase 3)

The competitor's newest capability is signed capture of AI coding sessions on
the developer machine (prompts, tool calls, edits, commits). We have the
runtime-side analog (`mvm-assurance` campaigns evaluate agent behavior inside
admitted microVMs) but nothing at the desktop front of the chain.

- [ ] WS9.1 (mvm-assurance): research spike — can `mvm-scout` host a
      hook-based observer for coding agents that emits digest-signed session
      records which later join the build provenance (same join mechanism as
      the Scout scan → campaign join)? Privacy posture: digest-first, like
      the existing prompt handling.
- No production commitment until the spike lands.

## Phasing

- **Phase 1 (demo parity):** WS1, WS2, WS3, WS7.1–7.2. These answer every
  homepage question in our vocabulary with our differentiators (verity-sealed
  marks, chain-signed audit) intact. All are serialization/UI/API work — no
  hardware, no new infra.
- **Phase 2 (trust depth):** WS4, WS6, WS8, WS7.3.
- **Phase 3 (hard claims):** WS5, WS9.

## Non-goals

- We do not build a general-purpose mark inserter for arbitrary third-party
  binaries (their `insert` UX). We seal what we build and verify what we
  admit; `mvm-scout` *recognizes* foreign marks (WS2.3) but we stay a
  runtime-evidence platform, not an artifact-mutating tool.
- No floating-point or scoring changes in mvmd placement (AGENTS.md rule).
- No server/daemon grows inside `mvm` itself (ADR boundary); fleet queries
  live in mvmd, local queries in `mvmctl`, presentation in studio.

## Open questions

1. Environment model in mvmd V1: is `environment` (dev/staging/prod) a
   fleet attribute, a workload label, or a launch-time field on the start
   request? Decision needed before WS1.3.
2. Rekor vs self-hosted transparency service for enterprise/self-host
   customers — WS4 publisher should be pluggable like the existing
   `WitnessSink` trait. Confirm with the customer deployment model.
3. Do we offer strict admission (refuse unmarked images) in v1, or
   report-only? Leaning report-only first, strict as plan policy.
