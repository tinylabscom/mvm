# Certifying assurance campaign closeout

Backing: shipped-source
Validation: admitted_lifecycle_dispatches_cleans_up_and_returns_host_evidence

Status: **IN PROGRESS. The strict operator-session handoff is complete. The
explicit provider-state launch handoff and fixed admitted lifecycle runner are
implemented. The sibling-owned signed `scoutd` pack is now independently
produced and accepted by MVM's generic verifier. The operator-configured
admitted booter is implemented and injected into the provider executable.
The sibling-owned guest typed-probe loop now uses MVM's canonical generic
assurance API and the fixed runner completes the admitted lifecycle in focused
conformance tests. The native Linux all-feature builder gate is green. Trusted
attestation and the live KVM/Scout campaign are still required.**

This is the closeout plan for the open work in
`2026-08-17-admission-bound-ai-assurance-sessions.md`. Its finish line is one
real Scout-linked campaign executed through an admitted MVM and evaluated from
joined signed evidence. Unit fixtures, the non-certifying fixture provider,
and a plain `machine run --receipt` do not satisfy this plan.

## Ownership boundary

- `mvm-assurance` owns the `scoutd` source, rules, build, version, signature,
  SBOM, provenance, revocation identity, and publication of its generic MVM
  extension pack.
- MVM owns generic pack installation and verification, signed-plan admission,
  the concrete provider/controller process, guest dispatch, typed broker,
  resource enforcement, observers, cleanup, receipts, and attestation joins.
- The operator owns campaign declarations that contain facts absent from the
  Scout provider request. Neither repository may invent or weaken those facts.
- Ordinary MVM launch remains independent: no assurance pack discovery,
  controller startup, or additional authority occurs without an explicit
  assurance campaign.

## Live checklist

- [x] **1. Complete the counterparty handoff.** Version the sibling provider
      request or add a separate strict operator-declaration input carrying
      trial/idempotency identity, detailed finding identity, requested tools
      and observation scopes, step/output limits, synthetic canaries, and
      destination labels. Add exact-key, mismatch, oversize, and unsupported-
      version conformance tests in both repositories.

- [x] **2. Produce the sibling-owned extension pack.** Build `scoutd` as a
      guest-mountable artifact and emit a signed `mvm.extension-pack/v1` with
      its identity, version, protocol range, placement, entrypoint, maximum
      authority, all resource budgets, provenance, SBOM, revocation identity,
      and permission delta. Prove tampering, expiry, revocation, wrong signer,
      unsupported protocol, and oversized artifacts are refused by MVM.

- [x] **3. Ship the concrete MVM provider executable.** The generic
      `mvm-hostd::assurance_provider::serve_provider` helper now owns the
      bounded `MVEX` process boundary and accepts only an injected typed
      `AdmittedCampaignRunner`; the checked-in `mvm-extension-provider`
      executable injects the fixed lifecycle runner and operator-configured
      booter, loading only explicit
      operator configuration, and exposes neither a complete `MvmClient` nor
      an arbitrary command path. Ensure inherited credentials, host paths,
      and environment values cannot enter prompt or durable state.
  - [x] Add an explicit absolute `--provider-state-root` sibling launch input,
        pass it as the provider's `--state-root`, keep `env_clear`, and reject
        missing, relative, and symlink journal roots. Prompt history for the
        lifecycle runner is rooted beneath that same explicit state directory.
  - [x] Add `LifecycleAdmittedCampaignRunner`, which rechecks the joined
        identity and fixes the bind/dispatch/observer/cleanup/finalization
        sequence without exposing a generic client or command surface.
  - [x] Supply the operator-configured `AdmittedTrialBooter` that resolves and
        re-verifies the sibling-owned signed pack, builds the exact admission
        inputs, and injects the lifecycle runner into the checked-in provider
        executable. Its strict private `boot-config.json` pins the MVM home,
        pack/trust identities, workload/kernel digests, backend, policies,
        authority, budgets, and destination map; unknown fields and path,
        permission, identity, or signer mismatch fail closed.
  - [x] Extend the sibling launcher with explicit absolute
        `--provider-mvm-home`; after `env_clear` it restores only that
        `MVM_HOME` and the provider refuses a boot config whose pinned host
        state root does not match it.

- [x] **4. Wire the finalized admitted runner.** For every declared campaign,
      install and re-verify the exact pack, synthesize and sign the plan, mint
      the short-lived grant, boot the disposable target, open the bound session,
      deliver the digest-only prompt, execute only declared typed probes,
      collect observer evidence, confirm cleanup, finalize the trial, and
      return the host-assembled sibling evidence record. Refuse every identity
      mismatch rather than continuing with weaker evidence.

- [x] **5. Finish recovery and lifecycle conformance.** Test cancellation,
      deadline expiry, stale/revoked grants, nonce replay, duplicate
      idempotency keys, controller crash before and after terminal commit,
      guest crash, host restart, partial observer evidence, cleanup failure,
      and concurrent-session exhaustion through the concrete provider path.

- [ ] **6. Supply trusted attestation evidence.** Join a verified quote from
      the admitted runtime to the exact plan, workload, artifact, policy,
      backend, session, and receipt identities. Missing, stale, foreign, or
      unsupported attestation must produce `INCONCLUSIVE`; no software boolean
      may substitute for a verified quote.
  - [x] Land the host-only verifier and evidence join. The canonical quote
        challenge binds the exact admission/session identities, grant nonce
        and expiry, backend, and opening receipts. Provider, challenge,
        enrolled-root, freshness, and lifetime mismatches fail closed; a valid
        join emits signed `assurance.attestation_verified` audit and receipt
        references consumed by the host finalizer.
  - [x] Bind the operator-selected attestation mode into the signed execution
        plan and refuse an attestation-required Scout request when the
        operator configuration selects `noop`. Ordinary launches and
        non-attesting assurance campaigns retain the `noop` default.
  - [ ] Implement and configure a native TPM2, SEV-SNP, or TDX quote verifier
        with enrolled trust collateral on a supported runtime. The current
        feature-gated providers still return `NotYetImplemented`, so the
        completed join alone is not certifying evidence.

- [x] **7. Restore the native Linux builder gate.** Resolve the HVF builder's
      six-disk/maximum-five layout or provide the supported builder-VM path,
      diagnose the libkrun no-progress failure, refresh embedded host/guest
      binaries, and pass Linux workspace all-target Clippy plus Linux-gated
      assurance tests in the project builder VM.

- [x] **8. Run the deterministic live canary.** Execute a synthetic-canary
      campaign through a real KVM-backed MVM using the signed sibling pack and
      concrete provider. Capture the admitted plan ID, session ID, grant
      digest/nonce/expiry, workload/source/artifact/policy digests, backend,
      observer references, cleanup reference, attestation reference, and final
      execution receipt. Label it non-certifying unless every trust-root and
      observer requirement validates.
  - [x] Publish MVM's counterparty test vector for the effective policy
        digest: `sha256:nul-separated-policy-refs-v1` hashes
        `operator-network-v1`, `operator-egress-v1`, `operator-fs-v1`, and
        `operator-tools-v1` in network, egress, filesystem, tool order with
        one NUL separator between fields. MVM computes this through the shared
        `mvm-contract` helper and refuses any other requested identity.
  - [x] Add a workload compatibility preflight: assurance admission now
        requires `mvm-meta.json` with guest protocol version 2 or newer, so a
        legacy protocol-v0 rootfs is refused before Firecracker startup rather
        than reaching the guest init and panicking on extension activation.
  - [x] Execute a real x86_64 KVM/Firecracker canary on the supplied native
        Linux host with the freshly built protocol-v2 workload, the signed
        sibling pack, and the concrete provider. The run reached signed plan
        admission, Firecracker, the guest agent, observer collection, exact
        cleanup, and host finalization. It recorded plan
        `sha256:18a220846c25a6cec1f0b4f36dd4bfbab764f4e50671394e6da32acfcbd7ef16`,
        session `s-ebc20dc44ec9937f1acc4b7c85038c1b`, campaign
        `mvm-campaign-b057c885ef0176c9`, trial `trial-1`, grant digest
        `sha256:b0991c541656cac6ebd02c27389a8b3c299b7cbadd6d4477653a0219545acf34`,
        nonce `gn-48c803a9f0c79e8c71eee34b349c8c9a`, expiry `1787266198230`,
        source digest `sha256:3333333333333333333333333333333333333333333333333333333333333333`,
        workload/artifact digest
        `sha256:8ebd17c11112e175e6bbdd3296a7d105dce6dcd74a422c16d008bd16f2870fdb`,
        policy digest
        `sha256:5dd0de53b6d211f764728599e291e93a9491dc34f87596e906365fb74c95e0ff`,
        backend `firecracker`, four signed audit references, and four signed
        receipt references. The provider journal replayed the exact response
        with one VM directory before and after retry. The result is explicitly
        `INCONCLUSIVE`: no trusted hardware attestation was available and the
        typed guest probe did not report an attempted effect.

- [ ] **9. Demonstrate the full Scout flow.** Run Scout scan, assurance plan,
      assurance run with the operator-pinned trusted MVM provider, and report
      correlation. Verify retries do not execute twice and that removing any
      observer, cleanup, receipt, policy, identity, or required attestation
      evidence changes the result to `INCONCLUSIVE`.
  - [x] Run the reference Scout scan, assurance plan, explicitly
        non-certifying fixture provider, and report correlation. The fixture
        run exits with the expected non-certifying status and the correlated
        report is globally `INCONCLUSIVE`.
  - [x] Run the same Scout-linked shape through the concrete MVM provider with
        a complete operator-session bundle, signed extension pack, protocol-v2
        workload, explicit provider state root, explicit MVM home, and an
        environment-cleared launcher. The sibling now emits the published
        digest. The request reached signed-plan admission and then failed
        closed before guest-agent startup because `mvm-oci-init` denied the
        user-volume path; the identical retry replayed without a second
        execution. The result is `INCONCLUSIVE`.
  - [x] The sibling's identity-join and policy-mismatch tests, plus its
        six-case evidence regression, show that missing/corrupt observer,
        cleanup, receipt, policy, identity, or attestation facts are
        `INCONCLUSIVE`.

- [ ] **10. Pass release gates and close the plans.** Run MVM format, check,
      workspace tests, all-target Clippy, required-feature/gated checks,
      sibling workspace tests and Clippy, schema compatibility, and the live
      builder/KVM lane. Record exact commands and identities, then update this
      plan, the parent assurance plan, `specs/SPRINT.md`, and
      `specs/REFACTOR-STATUS.md` together.
  - [x] Pass host MVM format, workspace all-target check, complete workspace
        tests including doctests, all-target Clippy, x86_64 Linux cross-target
        and BDD required-feature checks, schema emission, plan-name validation,
        and sprint-append validation.
  - [x] Pass sibling format, workspace all-target check, complete workspace
        tests, all-target/all-feature Clippy, producer tests, and the canonical
        four-test guest harness against this MVM checkout.
  - [x] Pass the native Linux all-feature builder lane.
  - [x] Pass a live KVM campaign lane. The supplied native x86_64 host reached
        the real guest agent and completed observer, cleanup, finalization, and
        exact terminal replay; the result is recorded as non-certifying until
        trusted hardware attestation and a successful typed effect probe exist.

## Completion criteria

- [x] The signed `scoutd` pack is independently produced by `mvm-assurance`
      and consumed through MVM's generic extension model without a Scout
      special case.
- [ ] The concrete provider completes a real admitted campaign without
      exposing arbitrary host authority, secrets, commands, paths, or an
      unrestricted client to the workload.
- [ ] The final evidence joins source, plan, workload, artifact, policy,
      session grant, backend, observer, cleanup, receipt, and required
      attestation identities.
- [ ] The host evaluator—not the AI, extension, or provider—derives the final
      outcome, and every missing or mismatched required fact is
      `INCONCLUSIVE`.
- [ ] Ordinary `mvmctl machine run` behavior and critical path are unchanged.

## Current blockers

- The sibling now builds `scoutd` from its own source against an explicitly
  selected MVM checkout. It imports `mvm_agentd::assurance::AssuranceCampaign`
  and `mvm_contract::assurance` directly, so the extension owns its loop while
  MVM remains the single owner of envelope parsing, authority enforcement,
  broker framing, the capability descriptor, and observation validation. The
  loop selects only admitted destination labels, stops at the admitted step
  budget, and returns a verdict-free candidate. No Scout rule or binary is
  compiled into or special-cased by MVM.
- MVM now has a generic `serve_provider` process helper, a dedicated
  transport-safe `mvm-extension-provider` executable, and a concrete fixed
  lifecycle runner behind the narrow `AdmittedTrialBooter` seam. The controller
  strictly parses the explicit operator-session bundle, joins every campaign
  before invoking the runner, and refuses missing, extra, or mismatched
  sessions. The checked-in executable now loads the strict operator boot
  config, re-verifies and promotes the exact signed pack, synthesizes and
  admits the exact plan, and supplies the lifecycle runner. Focused conformance
  now exercises typed probe dispatch, host observation, confirmed cleanup, and
  host finalization. It remains non-certifying without a live KVM execution and
  trusted attestation.
- The provider launch contract now carries an explicit absolute durable state
  root and a separately explicit absolute MVM state root while continuing to
  clear the inherited environment. The launcher restores only the selected
  `MVM_HOME`; the provider requires the strict boot config to pin that exact
  root. MVM rejects relative and symlink replay roots and has no `HOME`,
  current-directory, or process-temporary fallback.
- Trusted runtime attestation and a real KVM canary have not been demonstrated.
  The host and project builder expose none of `/dev/tpmrm0`, `/dev/tpm0`,
  `/dev/sev-guest`, or `/dev/tdx_guest`; the three feature-gated providers are
  still `NotYetImplemented` stubs with no provider cryptography dependency.
  Exact-current builder probe `mvm-builder-vm-1787214676670-12105` also found
  no `/dev/kvm`, TSM report path, or TDX firmware path and an empty
  `/sys/class/tpm`; the seven all-feature provider tests pass only by proving
  fail-closed stubs. Item 6 remains open. It requires access to one real
  supported trust environment and its verifier collateral: a TPM2 device with
  provisioned AK plus trusted EK/manufacturer roots, an SEV-SNP guest with AMD
  VCEK/ASK/ARK collateral, or a TDX guest with Intel DCAP/PCS collateral.
- The complete reference Scout command sequence was exercised as far as the
  available counterparty permits. Scan run
  `scout-1787181844-1787181844602-371467bf57b4` produced source digest
  `sha256:371467bf57b495dff263de382d03981b238786810b76866b21be8fa332fad496`
  at revision `ab44bdc5175ce3337fabcc7f392ddadc9679b306` and requested policy
  `sha256:a2201af69c8ad236dd688087ca494875a6841058b9839e70b806d50d54e4cc21`.
  Planning reported `planned_broker_unavailable`; the fixture run and
  correlation exited with the expected non-certifying status and evidence
  digest
  `sha256:9e3fd7373036c577c02087c4df66906a8767dc5506605cd9178f8a933b3aac3a`.
  The report is globally `INCONCLUSIVE`. Its 15 per-finding `PREVENTED` labels
  come only from fixture evidence (`certifying: false`) and are not MVM
  prevention evidence; the sibling should avoid presenting those labels as
  final outcomes when the report itself is non-certifying.
- Item 5 is complete. The fixed runner now applies the minimum request,
  authority, and grant deadline; commits identity-bound cancellation before
  stopping the admitted guest call; confirms cleanup after deadline or guest
  failure; and refuses stale or closed sessions before dispatch. The concrete
  controller serializes its admitted-run budget, durably replays a completed
  response after process reconstruction, and refuses interrupted, failed, or
  conflicting claims without another run. Missing observer or cleanup facts
  remain explicit non-certifying broker gaps.
- The native libkrun builder now passes a source-current six-disk runtime
  probe. The corrected Stage 0 persistent-store path completed without ext4,
  data-loss, or capacity errors and promoted rootfs
  `sha256:4eea52acc023d58a9f7b25e58297c9ca923ec10b90c7dd83608a49967d1a4b53`.
  The rebuilt image contains the static `/sbin/mvm-setpriv`; builder init uses
  the workload-parity bounded arguments and launches the automatic agent as
  UID 990 with exactly `CAP_KILL|CAP_SYS_TIME` effective and ambient and
  `NoNewPrivs=1`. The strict live result recorded mask
  `0000000002000020`, all six disks, and exit code zero. Mutable XDG, Rustup,
  Cargo, target, and temporary state use explicit `/out` paths without
  changing `HOME`. The persistent store also survives sparse regrowth and
  dirty-journal recovery, and kernel cache validation now hashes content rather
  than trusting length and mtime. The source-current native run passed the
  focused sparse-store, Stage 0 prepopulation/recovery, Stage 0 binary, VMM,
  and hostd assurance tests; workspace all-target/all-feature Clippy and check;
  and the BDD required-feature check. The durable marker set is
  `conformance-bdd`, `hostd-assurance`, `mvm-build-recovery-20260820`,
  `mvm-vmm`, `stage0`, `stage0-store-recovery-20260820`, `workspace-check`,
  and `workspace-clippy`, closing item 7. The final proof used the fresh marker
  root
  `/nix/var/mvm/assurance-gates/2026-08-20-admission-ai-assurance-final-current`
  rather than resuming the earlier run; all 559 Linux `mvm-vmm` tests and 72
  focused hostd assurance tests passed, the exact-current shell job completed
  with exit code zero, and its VM state is
  `mvm-builder-vm-1787217398177-7306`.

## Completed evidence

- The sibling-owned `scoutd` loop now accepts only the bounded admitted
  envelope, exposes only MVM-declared destination labels, assigns deterministic
  per-step idempotency keys, invokes only `campaign_probe.v1`, and emits no
  verdict field. Its isolated build harness directly links the canonical MVM
  guest client and contract and pins all mutable build caches without inheriting
  `HOME`; four guest-loop tests and four build-harness tests pass.
- The canonical static extension was rebuilt, materialized, independently
  signed, and accepted by MVM's generic verifier as pack
  `sha256:230e7cc19eb5b045edbc05e2d63887fed8b9571cc3adafd5ee06f0a25f5c6d01`,
  artifact
  `sha256:7321a3853a2e04ee1d53bef5e6931b9d2e672450900c9e7580e04f8f2e3432fc`,
  signer `e4398c7acd5e776cacc3d354dfdcc994`, Firecracker backend, policy
  `sha256:ff64aa2df5fc4cdf3db5cbd1ee80b3778d2d9bf427f9f29a4dd0ffd650c87de1`,
  and exact `host.assurance.v1::probe` capability. This used an ephemeral test
  publisher key and is conformance evidence, not a release trust root.
- The probe descriptor's canonical ABI digest is frozen as
  `sha256:7bb85df93f7c89e3426053f3a54ea86e0c0167b9410c5ec4d5838c2533c3dd64`.
  MVM now rejects a returned observation whose schema, probe identity, or
  blocked edge does not join the exact invocation before the extension can use
  it.
- Item 4 focused conformance is green: 3 probe-contract tests, 7 workload API
  tests, 6 broker-client tests, 27 host typed-broker/observer tests, 26 host
  session/finalizer tests, 4 lifecycle-runner tests, and 3 real provider-process
  tests. Touched-crate all-target Clippy passes with warnings denied. The one
  controller-proxy test requires permission to bind its temporary Unix socket;
  it passed outside the filesystem sandbox.
- Item 5 focused conformance is green: 9 lifecycle-runner tests, 9 concrete
  provider-controller tests, 7 durable prompt/cancellation adapter tests, 4
  guest cancellation-state tests, and 27 typed broker/session-authority tests.
  These cover cancellation before and during dispatch, stale expiry, session closure as
  grant revocation, nonce replay, duplicate idempotency, timeout cancellation,
  guest failure, pre/post-terminal controller recovery, host reconstruction,
  partial observer evidence, cleanup failure, and concurrent-run exhaustion.
  The provider journal test also proves bounded durable state omits prompt,
  credential, and runner-diagnostic markers. Focused hostd/agentd all-target,
  all-feature Clippy passes with warnings denied.
- The sibling workspace build boundary is explicit: `mvm-scout` disables
  implicit binary discovery and `scoutd` is compiled only by its isolated MVM-
  API harness. The sibling passes 73 workspace tests, all-target check,
  all-target/all-feature Clippy, formatting, 4 pack-producer tests, and the
  4-test guest harness.
- Host-available release checks are green: the clean complete
  `cargo test --workspace` run passes including doctests; the current
  `mvm-hostd` library contributes 1,906 passing tests, and the assurance
  contract suite contributes 64. Workspace all-target check and Clippy,
  formatting, x86_64 Linux all-target cross-check, BDD required-feature
  compilation, six-key schema emission, plan-name validation, and
  sprint-append validation also pass. The native Linux all-feature builder lane
  is independently green; neither result implies a live KVM campaign. The
  final workspace gate also isolates the nested xtask Cargo target and holds
  the shared test-environment guard across manifest and mock-agent signer
  resolution, eliminating parallel test artifact/home races. The positive
  configured-booter fixture now uses a production-admissible Firecracker pack;
  separate tests retain the fail-closed `qemu`/`mock` refusal.
- The libkrun builder hardware probe confirms the guest has no `/dev/kvm` and
  no TPM2, SEV-SNP, or TDX device. The already-running owner-approved Lima test
  VM does expose `/dev/kvm`, but this checkout has no admission-visible Lima
  `VmBackend` and production must refuse that dev/test tier; it is not live
  campaign evidence. A certifying run needs a supported KVM provider plus a
  genuine enrolled hardware attestation root and verification collateral.
- Production assurance admission now rejects the configured `qemu` and `mock`
  dev/test backends before artifact or pack work. The focused
  `assurance_production_refuses_dev_test_backends` test passes and
  `cargo clippy -p mvm-hostd --all-targets --all-features -- -D warnings`
  exits zero. `firecracker`, `libkrun`, and `hvf` remain eligible for the
  subsequent strict identity and runtime checks; this negative gate is not a
  live KVM canary, so item 8 stays open.

- `mvm-assurance` now owns the generic `scoutd` extension recipe, provenance
  input metadata, SPDX SBOM, permission delta, revocation identity, and an
  independent Ed25519/OpenSSL pack producer that never copies or reads the
  publisher private key. Its static x86_64-musl guest artifact is materialized
  by MVM's product-agnostic deterministic ext4 utility and contains no MVM or
  Scout-specific host command surface.
- MVM's standalone generic verifier accepted the actual x86_64 staged pack as
  `org.tinylabs.scoutd`: pack
  `sha256:7b952b62f2b4d906e68072e902858494fbd1f8ff964e77f731e0cda153c14e98`,
  artifact
  `sha256:83a52924d3fba5c18ddf4b2cbb50196e8524b014084b07c3e81a2e0412f16fae`,
  signer `a3ef495d2b7993c50bd90a1ef7f3fe0e`, protocol 1, Firecracker,
  policy compatibility
  `sha256:ff64aa2df5fc4cdf3db5cbd1ee80b3778d2d9bf427f9f29a4dd0ffd650c87de1`,
  and exact capabilities `vsock` plus `host.assurance.v1::probe`. The same
  staged pack was refused after artifact tampering, after expiry, under signer
  revocation, and under a trust store containing only a different signer.
  Focused generic tests additionally refuse unsupported protocol and artifact
  budget overflow.
- Pack-slice verification is green: three deterministic extension-image
  tests, 33 generic pack tests, two extension-admission tests, one standalone
  verifier test, three guest-entrypoint tests, and four independent producer
  tests. Focused MVM check/Clippy and sibling `mvm-scout` Clippy pass with
  warnings denied; both repositories pass format checks.

- The counterparty handoff uses
  `mvm.assurance.operator-session-bundle/v1`. `mvm-security` accepts it only
  through `--operator-session-bundle`, validates every nested strict AI-session
  request against the exact Scout request, clears the provider's inherited
  environment, sends `OpenSession`, verifies the request/count acknowledgement,
  and sends `Start` only afterward.
- MVM parses the same bounded bundle, requires one unique exact session per
  declared campaign, joins all shared source/narrative identities, binds its
  digest into the durable idempotency claim, and refuses `Start` before journal
  or runner work when the bundle is missing or mismatched. MVM continues to
  inject plan, grant, workload, artifact, policy, backend, audit, and receipt
  facts only after admission.
- The reusable `mvm-hostd::assurance_provider::serve_provider` helper now
  owns the generic MVEX loop and accepts only an injected typed runner. The
  checked-in process injects `LifecycleAdmittedCampaignRunner` with
  `OperatorConfiguredTrialBooter`; no provider-specific command path or
  unrestricted client is exposed.
- The approved Lima KVM test VM is `aarch64`, but the staged sibling pack
  contract currently declares `target_arch: x86_64`; MVM must refuse that
  mismatch. The live canary therefore needs an arm64 sibling pack/workload or
  an x86_64 KVM environment, not an architecture-specific Scout exception.
- The explicit `dev_test` assurance tier now admits QEMU only as permanently
  non-certifying evidence, while production admission refuses QEMU and mock.
  The native builder can run the required lane, but its shared 68.7 GiB Nix
  store filled while realizing the aarch64 default-tenant image (`No space on
  device`). No garbage collection or pre-existing state removal was done; a
  live canary needs additional builder capacity or an already-built aarch64
  dev image, in addition to a supported hardware attestation root. A follow-up
  isolated retry used a fresh 96 GiB sparse store and the cached native boot
  image, but stopped before VM startup because Stage 0 needed to fetch
  `nix-2.34.7-aarch64-linux.tar.xz` and this environment cannot resolve
  `releases.nixos.org`.
- `LifecycleAdmittedCampaignRunner` now drives the already-open admitted
  session through exact provider binding, digest-only durable dispatch, host
  observation, confirmed backend teardown, and host finalization. Its positive
  mock-backend lifecycle test returns host-assembled evidence; a boot identity
  mismatch stops and cleans the target before dispatch. Missing admitted boot,
  cleanup, dispatch result, or required trusted attestation stays explicitly
  non-certifying.
- A process-level conformance test launches the actual
  `mvm-extension-provider` child, sends the sibling-compatible
  `Hello`/`OpenSession`/`Start`/`Shutdown` sequence, and verifies a missing
  admitted boot returns a bounded `INCONCLUSIVE` response rather than falling
  back to the retired placeholder runner.
- Focused MVM conformance passed: 8 counterparty tests, 7 provider-controller
  tests, 4 lifecycle-runner tests, 7 operator-booter tests, 3 provider-binary
  tests, and 3 provider-process tests. Focused sibling conformance passed 24
  `mvm-security` library tests. `cargo check -p mvm-hostd --all-targets` and
  `cargo clippy -p mvm-hostd --all-targets -- -D warnings` pass. The sibling
  workspace all-target check and touched-crate all-target Clippy pass from an
  isolated `/tmp` target with warnings denied. The aggregate hostd library run
  passes 1,883 tests with one ignored.
- The concrete-booter tests cover exact signed-pack re-verification and
  promotion, closed backend vocabulary, budget narrowing, a narrow default
  ceiling, unknown config fields, loose config permissions, and symlink
  refusal. Process tests cover explicit global MVM-home binding and prove a
  configured runner fails closed before boot when its exact artifacts are
  unavailable.
- The supplied Hetzner live lane is x86_64 with readable `/dev/kvm` and
  Firecracker 1.14.1. The current provider built there in 4m54s and the
  sibling-owned x86_64-musl `scoutd` built there in 1m21s. The signed pack
  identities are pack `sha256:7b952b62f2b4d906e68072e902858494fbd1f8ff964e77f731e0cda153c14e98`,
  artifact `sha256:83a52924d3fba5c18ddf4b2cbb50196e8524b014084b07c3e81a2e0412f16fae`,
  and signer `a3ef495d2b7993c50bd90a1ef7f3fe0e`. A direct MVEX run reached
  descriptor exchange, operator-session acceptance, signed-plan admission,
  and a real Firecracker launch. With `/usr/local/bin` restored in the
  provider's cleared `PATH`, the cached protocol-v0 OCI rootfs failed closed
  in `mvm-oci-init` (`user-volume activation failed: path policy denied`) and
  panicked before the guest agent came up; the result was `INCONCLUSIVE` with
  `mvm.assurance.admitted_boot` missing and no evidence emitted.
- The sibling now consumes the published
  `sha256:nul-separated-policy-refs-v1` interface and emits
  `sha256:5dd0de53b6d211f764728599e291e93a9491dc34f87596e906365fb74c95e0ff`;
  its cleared-environment launcher explicitly restores `/usr/local/bin` in
  the provider PATH. The real linked run reached signed-plan admission, then
  failed closed before the guest agent because `mvm-oci-init` reported
  `user-volume activation failed: path policy denied`. Its exact retry
  replayed without a second admission/execution event. This is the current
  lifecycle/runtime blocker, distinct from the resolved digest mismatch.
- A fresh native x86_64 run on that host built the current protocol-v2 tenant
  image and runtime overlay, embedded the static guest control binaries in a
  disposable rootfs-only copy, and reached the real guest agent. The signed
  pack was `sha256:f72aeb04240d16ea6c0c8a4855f3d8443006e7eb3702429af005c3718946e59d`,
  its artifact was
  `sha256:315970a2910e5f5ea30516dab723d55d127fa3c16497eadcebf36aa403cb3af1`,
  and its ephemeral publisher key id was `086c60554cd1103e0295a09c92700b66`.
  This is live KVM lifecycle evidence and exact replay evidence, but not a
  certifying result: the host has no `/dev/tpmrm0`, `/dev/tpm0`,
  `/dev/sev-guest`, or `/dev/tdx_guest`, and the response has
  `attestation_verified:false` and `attempted_effect:false`.
- A broad `cargo test --workspace` attempt exhausted the filesystem while
  running `mvm-core` after the earlier assurance-sensitive groups passed. The
  apparent 429 failures were write failures (`os error 28`), not assertion
  regressions. `cargo clean` removed only the worktree's generated target
  directory (629,038 files, 123.3 GiB); the full clean rerun remains item 10.
