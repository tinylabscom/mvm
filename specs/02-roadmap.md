# Roadmap and shipped-state companion

`specs/01-project.md` is the north-star product overview: it describes the
system we are building and the posture we want the public story to earn. This
file is the implementation companion. It records what is already claim-gated,
what is partially shipped, and which plans close the remaining gap.

## Current baseline

The security substrate is materially ahead of the product surface. The claim
catalog currently records shipped witnesses for the core isolation and
traceability properties: host-filesystem confinement, non-root execution,
dm-verity verified boot, production agent surface reduction, fuzzed host/guest
parsers, hash-verified developer image, cargo audit/deny, signed audited
execution plans, content-addressed bundles, default-deny egress, sealed
application-dependency volumes, plan-gated host services, broker secret
handling, OCI provenance, and sealed-production no-interactivity.

The main remaining gap is not the basic sandbox boundary. It is the product and
developer surface around that boundary: SDK coherence, typed helpers, local
preview URLs, lifecycle verbs, task/files protocol, install/uninstall DX,
macOS secret-substitution parity, prompt-injection taint policy, and a witnessed
non-persistence claim.

## Shipped or close to shipped

- **Core security claims:** claims 1-15 are shipped in
  `specs/claims/catalog.md`; claim 16, egress substitution keeping raw secrets
  off the guest, is tracked as `Preview`.
- **Backend matrix:** the runtime matrix is now Firecracker, libkrun, Vz, QEMU
  as dev/test, plus mock. Apple Container and cloud-hypervisor were removed by
  Plan 177; Vz is at parity with the macOS libkrun baseline.
- **Signed execution and audit:** every workload launch is admitted through a
  signed `ExecutionPlan` and chain-signed audit path.
- **Verified boot and sealed production:** dm-verity rootfs integrity and the
  sealed-production no-console/no-shell path are shipped.
- **SDK imperative baseline:** Python and TypeScript `Sandbox` now cover
  create/exec/copy/forward/id/info, sync and async teardown, and dev-tier
  gating. This is the usable imperative substrate, not yet the full product
  veneer.
- **Encryption substrate:** AEAD, KEK rotation policy, per-rebuild DEK binding,
  signed snapshots, and VMGenID reseed substrate are implemented. The encrypted
  storage-provider selection and VMGenID delivery follow-ups remain open.
- **Vz warm/start primitives:** Vz snapshot, pause/resume, vm_full
  save/restore, fork, and warm pool work are live-proven, with Firecracker
  live-memory warm-start still tracked separately.

## Partially shipped gaps

- **Secret substitution parity:** Plan 129 ships the core secret-substitution
  model and leak gate, but Sprint 55 records that substitution is Linux-only
  today: Firecracker and QEMU have it, while libkrun and Vz do not. Plan 197
  makes this a workload-backend compile-time obligation, and Plan 193 / rvproxy
  owns the gateway-level macOS terminator.
- **SDK as the whole authoring surface:** Plan 125 has completed the imperative
  `Sandbox` baseline and TypeScript exec parity. Still open: typed helpers,
  one-IR coherence across decorator/runtime/`mvm.toml`/flake, terse secret
  binding, doctor capability table, named security profiles, and the
  workload-facing host-services SDK.
- **Core demo regression guard:** Sprint 60 has the spine and freeze guard, but
  the macOS/libkrun `core_demo_e2e` still needs to be driven green end-to-end.
- **WASM preview to production promotion:** ADR-080 preconditions have several
  landed pieces, including trace hardening, secret-scan admission, capability
  projection, and declarative file materialization. The `.wasm` artifact
  admission and in-guest runner are not started.

## Planned closures

- **Product surface and app-builder DX:** Sprint 61 / Plan 181 is the product
  closure for preview ingress, lifecycle verbs, streamable task/files protocol,
  and install/uninstall UX. It deliberately keeps multi-tenant HTTP transport
  and tenant auth in `mvmd`.
- **Witnessed non-persistence:** Plan 167 promotes the cold-state guarantee from
  architecture prose to a numbered, catalog-witnessed claim. It should prove
  that a workload's runtime state does not survive teardown and that `mvmctl run`
  does not reuse a prior guest.
- **Prompt-injection guardrails:** Plan 135 completes the taint/provenance
  model and deterministic capability authorization. It intentionally avoids a
  "we detect prompt injection" claim; the claimable property is that untrusted
  provenance cannot authorize privileged host actions without a signed binding.
- **MacOS substitution parity:** Plan 197 Phase 2 should lift substitution into
  the shared workload launch funnel and add the no-default per-backend transport
  seam. The transparent macOS `:80`/`:443` path depends on the rvproxy gateway
  migration in Plan 193.
- **At-rest confidentiality completion:** Plan 122 shipped the crypto substrate;
  the remaining storage-provider wiring and VMGenID token delivery need to land
  before the broadest "everything at rest is encrypted and restored snapshots
  always reseed in practice" wording is fully accurate.
- **Observability and metering:** Plan 127 fills in egress/build-minute
  metering, per-phase boot benchmarks, structured tracing, and non-failing
  budget reporting.

## Public-copy rule

Before copying language from `specs/01-project.md` into README, website, CLI
help, or marketing material, check this file plus `specs/claims/catalog.md`.
Use shipped language for claim-gated properties, preview language for partially
implemented features, and roadmap language for unchecked plans. In particular:

- Do not claim macOS secret substitution until Plan 197 Phase 2 and its rvproxy
  dependency are closed.
- Do not claim witnessed non-persistence until Plan 167 adds catalog witnesses.
- Do not claim prompt-injection protection as detection accuracy; claim only the
  deterministic signed-binding gate once Plan 135 lands.
- Do not list Apple Container or cloud-hypervisor as active runtime backends;
  they were removed in favor of the consolidated matrix.
- Do not claim WASM production isolation until ADR-081's artifact admission and
  in-guest runner exist.
