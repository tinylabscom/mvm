# Admission-bound AI assurance sessions

Backing: shipped-source
Validation: a_provider_cannot_smuggle_an_mvm_binding_through_the_request_parser

Status: **W1–W4, W5.1–W5.4, W6/W7, W7b, W8, and W9.1–W9.4, including the sibling-owned typed-probe loop, concrete operator-configured admitted provider lifecycle, focused lifecycle fault/recovery closeout, runtime-attestation evidence join, and native Linux builder gate, are implemented. W5.5 and a live certifying Scout campaign remain open.**

Closeout of the remaining certifying-campaign work is tracked in
`2026-08-18-certifying-assurance-campaign-closeout.md`.

An AI workload can drive a Scout-linked assurance campaign from inside an
admitted microVM. This plan is the MVM half of that: the typed envelope the
workload receives, the authority it runs under, the one probe verb it may
call, and the host-derived outcome.

The counterparty is `mvm-assurance` (`mvm-scout` + `mvm-security`). It owns
source analysis, campaign planning, the final evidence report, and the
guest-side `scoutd` binary and pack. MVM owns only the generic extension-pack
verification, installation, admission, guest dispatch, typed broker, and
enforcement path. `scoutd` is the first consumer of that path, not a name,
binary, rule set, or launch dependency compiled into MVM. Future optional
forensic observers and workload auditors must use the same contracts without
requiring MVM changes.

## Trust split

Everything crossing into an AI session is an identifier, a digest, or a
reference. No secret value, host path, socket name, or log body appears in any
type in `mvm_contract::assurance`.

Three properties are structural rather than checked at runtime:

- The provider's half of the envelope (`AssuranceSessionRequest`) cannot carry
  admission facts. `deny_unknown_fields` refuses an `mvm_binding` key outright,
  and the assembled `AiSessionInput` has no `Deserialize` at all — it is only
  constructible from an `MvmBinding` derived from a signed `ExecutionPlan`.
- The AI's reply (`TrialResultCandidate`) has no outcome field, so
  "the model wrote PREVENTED" is not a representable state.
- Effective authority is one intersected value (`EffectiveAuthority`), not a
  set of checks spread across the dispatch path.

## Landed

- [x] **W1 — Contract.** `mvm_contract::assurance`: bounded ids/digests/refs,
      the `mvm.assurance.ai-session-input/v1` envelope, the AI candidate, the
      host-assembled `mvm.assurance.trial-result/v1` document, and size,
      length, collection, budget and control-character limits. Nesting depth is
      fixed by the schema — there is no recursive type and no free-form
      `Value` — so there is no depth counter to get wrong.

- [x] **W2 — Admission binding and authority.** `MvmBinding::builder().plan(&plan)`
      quotes the admitted plan; the builder refuses a binding that cites no
      audit entry or no receipt. `EffectiveAuthority::intersect` narrows
      extension maximum ∩ request ∩ policy ceiling ∩ signed grant ∩ explicit
      approval, and a `campaign_probe.v1` without operator approval does not
      survive it.

- [x] **W3 — Probe surface.** `host.assurance.v1` in `mvm-hostd`, registered
      only when `ExecutionPlan.services` names it, exposing one verb. The AI
      selects a declared destination *label*; the host resolves it against the
      campaign's operator-declared table and consults the live
      `mvm_core::egress_broker::decide_egress`. Idempotency-key replay returns
      the first result without burning a step; nonce replay, session/trial
      mismatch, step exhaustion and deadline expiry each refuse distinctly.

- [x] **W3.1 — Counterparty wire conformance.** `assurance::wire` projects the
      exact key sets `apps/mvm-security/src/ai_session.rs` validates, and the
      envelope reports *effective* authority — the counterparty rejects the
      `deadline_unix_ms: 0` a request may carry to mean "none set".

- [x] **W4 — Guest-side API.** `mvm_agentd::assurance::AssuranceCampaign`
      reads the delivered envelope and calls declared probes by *label*. The
      surface offers no method taking a command, path, host, port, or socket —
      not by convention, but because no such parameter exists on it. Local
      guards fire before any round-trip, and nonces are session-scoped and
      single-use. Reading the envelope needed a direction-specific type:
      `AiSessionInput` is serialize-only so the host can never parse admission
      facts out of provider bytes, so the guest reads `DeliveredSession`, and a
      test asserts the two describe the same document.

- [x] **W6/W7 — Audit and receipt emission.** `mvm_hostd::audit::assurance`
      writes `assurance.session_opened`, `assurance.probe` and
      `assurance.trial_completed`; the first and last carry an execution
      receipt. Emission is **fail-closed**: the ordinary emit path treats
      receipts as a derived cache and swallows their errors, which is wrong for
      evidence a claim rests on, so an evidence-bearing emit errors instead. A
      probe whose record cannot be written is refused (`AuditUnavailable`) and
      leaves no trace of an attempt. References are content digests of the
      exact signed entry bytes, and `resolve_audit_ref` finds the line back on
      disk — asserted by test, so a citation is resolvable rather than
      decorative. Records carry the declared *label*, never the host or port
      behind it.

- [x] **W7b — Session lifecycle on the boot path.** `assurance_session::open`
      mints a derived grant, intersects authority, records
      `assurance.session_opened`, builds the binding from those references, and
      opens the session — refusing outright if the plan does not bind
      `host.assurance.v1`, if the campaign declares no edge, or if the record
      could not be written. `AdmitAndStartParams.assurance` carries an
      operator-declared campaign through the real boot path, and a test asserts
      `admit_and_start` produces a live session whose binding quotes the
      admitted plan. Assurance stays off the ordinary launch path: `None` is the
      default and every existing call site takes it.

      The plane is a process-global installed when the broker registry binds the
      service, but `open_on` takes it explicitly — a `OnceLock` admits one
      value, so a decision path only reachable through the global would be
      testable exactly once per process.

## Open

- [ ] **W5 — Observer and cleanup evidence.** `EvidenceSet` is consumed by the
      evaluator. Host-observer and confirmed-cleanup producers now populate
      their fields and signed references; trusted hardware attestation remains
      absent. Any plan requiring it therefore evaluates to `INCONCLUSIVE`,
      which is the correct fail-closed behaviour and not a certifying result.

  - [x] W5.1 Bind observer evidence to session, plan, campaign, trial and the
        exact probe audit/receipt references. The host broker snapshots only
        its mediated observations, commits their exact probe audit references
        under `assurance.observer_completed`, and returns a signed observer
        receipt. The extension cannot supply these facts or references, and a
        foreign identity emits nothing.
  - [x] W5.2 Bind teardown confirmation to the same identities and refuse a
        merely requested teardown as cleanup evidence. Assurance sessions now
        refuse plans without `destroy_on_exit`; cleanup checks the exact
        admitted backend and VM, calls stop, requires authoritative `Stopped`
        read-back, rejoins the session identity, and only then emits signed
        `assurance.cleanup_completed` audit and receipt references.
  - [x] W5.3 Carry attestation verification only from the admitted runtime's
        verifier; a configured attestation mode is not evidence. The host now
        constructs a canonical challenge over the admitted session, plan,
        campaign, trial, source, workload, artifact, policy, grant digest,
        nonce, backend, expiry, and opening receipt references. Only a
        host-selected runtime verifier can return bounded native-quote
        metadata. The host rejoins the exact challenge, required provider,
        enrolled trust-root reference, verification time, and expiry before
        emitting `assurance.attestation_verified` audit and receipt records.
        The finalizer accepts only that identity-bound evidence; configured-
        only, foreign, stale, wrong-provider, unenrolled-root, or overlong
        verification remains false and therefore `INCONCLUSIVE` when required.
        The concrete provider carries the operator-selected attestation mode
        into the signed execution plan and refuses a required Scout request
        when the operator posture is `noop`; ordinary callers retain the
        closed `noop` default.
  - [x] W5.4 Persist enough host-side state to recover an interrupted trial as
        `INCONCLUSIVE` without re-executing its idempotency key.
        The strict, fsynced dispatch marker binds the admitted plan, session,
        source, artifact, policy, grant, extension, payload digest and campaign
        identities without prompt bytes. A retry validates every field and
        emits a signed `INCONCLUSIVE / execution_interrupted` completion with
        audit and receipt references; a committed recovery is itself
        idempotent, while malformed, unknown-field and identity-mismatched
        markers fail closed without execution or evidence emission. Recovered
        work also cannot promote controller-supplied cleanup into verified
        cleanup evidence; the finalizer ignores it and remains inconclusive.
  - [ ] W5.5 Exercise the synthetic canary through a KVM microVM and label it
        non-certifying unless W5.1–W5.3 all have trusted witnesses.
        A supplied native x86_64 KVM host now reaches the real guest agent,
        observer, cleanup, and host finalization; the exact retry replays the
        terminal response without a second VM. W5.5 remains open because the
        host has no trusted hardware attestation root and the probe produced no
        attempted-effect evidence.

- [x] **W8 — Generic extension pack, admission, and guest bridge.** The
      counterparty's `assurance run --provider <path>` spawns a framed-stdio
      provider speaking `mvm.security.campaign-request/v1`. MVM must expose a
      generic controller path that resolves a separately supplied, signed
      extension pack, admits its declared identity/placement/capability maximum
      and budgets, dispatches its manifest-selected entrypoint, and drives the
      existing typed broker. MVM must not build, ship, name, or special-case
      `scoutd`.

  - [x] W8.1 Define a strict, versioned generic extension-pack manifest over
        the existing signed/revocable pack substrate.
  - [x] W8.2 Verify and install an extension content-addressably without adding
        discovery to ordinary launch.
  - [x] W8.3 Admit extension identity, protocol range, placement, authority,
        budgets, provenance/SBOM, revocation identity, and permission delta.
        This version executes `guest_workload` placement only and refuses
        `isolated_controller` during signed-plan admission; it never silently
        redirects a controller extension into the workload guest.
  - [x] W8.4 Re-verify the exact pack at launch, mount its declared artifact
        read-only, and dispatch only its boot-validated manifest entrypoint.
        The guest request has no program, argv, environment, host path, socket,
        destination, policy, observer, credential, or cleanup selector.
  - [x] W8.5 Bind all broker calls to the extension's admitted capability
        descriptors and signed `run-extension` and `cancel-extension` plan
        verbs; enforce payload, output, artifact, wall-clock, step,
        concurrency, CPU, and memory ceilings before or during execution.
        CPU/address-space rlimits are a Linux guest path and therefore have a
        Linux-gated test.

- [ ] **W9 — Counterparty controller provider and evidence completion.** The
      generic MVM primitives exist, but the sibling request does not yet carry
      enough identity/authority to build one strict session request, and no
      trusted provider binary drives them end to end.

  - [x] W9.1 Parse the counterparty request with exact keys, bounds and closed
        identifiers, then project each campaign into an untrusted
        `AssuranceSessionRequest` without inventing missing trial, finding, or
        authority facts. MVM now parses the current sibling schema strictly and
        joins it to a separately operator-authored strict session request,
        comparing every overlapping identity and narrative field. Fields the
        sibling does not carry stay explicit operator inputs; missing narrative
        facts and any mismatch are refusals. The schema emitter publishes this
        counterparty boundary alongside the assurance and extension schemas.
  - [x] W9.2 Open the declared campaign only after signed-plan admission and
        deliver the bound `AiSessionInput` through a production agent-session
        prompt adapter. The production adapter now constructs
        `AgentSessionCommand::Prompt` only from the bound envelope, fsyncs
        digest-only history before dispatch, and restores a running request
        after crash. MVM now also owns the generic `MVEX` v1 codec and blocking
        controller stream adapter, byte-compatible with the sibling, with
        digest, payload-ceiling, monotonic-sequence, typed-error, cancel and
        shutdown conformance tests. The admitting controller now exposes its
        session/evidence handler over a bounded host-only UDS. A generic
        host-signed service-proxy binding carries the exact typed descriptors
        to the resident broker, which derives session identity from the VM
        registration and routes capability invocations without receiving an
        audit signing key. A dedicated `mvm-extension-provider` process now
        owns the bounded MVEX transport and injects the fixed lifecycle runner
        with an operator-configured admitted booter. The reusable
        `serve_provider` helper accepts
        an injected typed runner without selecting a provider or command path.
        Its controller accepts an explicit operator
        session bundle through `OpenSession`, joins every campaign before the
        runner, and rejects missing, extra, or mismatched session identities;
        `LifecycleAdmittedCampaignRunner` now joins the already-open boot
        session, uses an explicit provider-owned prompt-journal root, dispatches
        through the durable adapter, confirms cleanup, and returns only the
        host finalizer's evidence. The strict private boot config pins the
        explicit MVM state root, pack and trust identities, workload/kernel
        digests, backend, policies, authority, budgets, and destination map;
        the booter re-verifies and promotes the exact pack, synthesizes and
        admits the plan, boots, and opens the declared campaign. A missing or
        mismatched input fails closed before dispatch.
    - [x] W9.2a Add a generic, host-signed typed-service proxy binding whose
          empty form is byte-compatible with ordinary VM registration.
    - [x] W9.2b Keep the admitting controller's session/evidence handler behind
          a bounded host-only UDS and route the resident broker through it
          without moving an audit signing key into the broker.
    - [x] W9.2c Prove the live process seam refuses unsigned bindings, direct
          (non-capability) calls, mismatched service/session identities,
          oversized frames, missing controller state, and controller failure.
  - [x] W9.3 Support cancellation, timeout, duplicate request recovery and
        provider protocol errors without a second campaign execution. Timeout
        and durable at-most-once dispatch, prompt-history recovery, and signed
        interrupted-result emission are implemented. The generic campaign
        controller now commits the strict request digest before calling its
        admitted runner and commits the bounded typed provider response before
        returning it on `MVEX`. A completed retry receives the same response;
        an interrupted, failed, or identity-conflicting retry never calls the
        runner. Durable state contains no prompt bytes or runner diagnostic.
    - [x] Live cancellation is durable before transport, exact-identity bound,
          and carried over a separate production-safe guest RPC. The guest can
          resolve only the already-active admitted extension call, requests
          process-group termination through the existing bounded kill ladder,
          waits for an active call to stop before acknowledging it, and records
          a cancellation that wins the pre-dispatch race so the matching call
          cannot create a child. Signed cancellation audit and receipt
          references are atomically persisted before journal confirmation,
          survive controller crash without a second transport call, and join
          host-assembled evidence only when session, campaign, trial, and
          source identities all match. The wire exposes no PID, signal,
          command, path, or cleanup selector.
    - [x] The generic framed server now returns bounded sanitized `Error`
          frames for typed-handler refusals and rejects digest tampering,
          oversize announcements and replayed sequences. The campaign
          controller persists final error/result identity and response before
          transport, refuses all non-completed replay states, and derives the
          response's `certifying` bit from complete joined host evidence rather
          than accepting it from its runner.
  - [x] W9.4 Return only host-assembled `mvm.security.trial-evidence/v1`
        records; the provider response's `certifying` bit is never authoritative.
        The host finalizer now consumes only its typed observer run and typed
        confirmed-cleanup token, derives the verdict, signs completion, and
        emits the exact evidence/result documents. The strict
        `mvm.security.provider-response/v1` type and JSON schema now exist, and
        the sibling accepts `certifying: true` only when the response claims it
        and the operator pins the exact provider descriptor identity. The
        durable generic controller now emits this response on `MVEX` and
        derives its certification bit from evidence completeness. The fixed
        lifecycle runner now turns each supplied finalized boot into that
        controller output and refuses boot identity mismatch before dispatch.
        The real signed-pack `AdmittedTrialBooter` and executable injection
        are implemented. The sibling-owned guest loop now imports MVM's
        canonical assurance API, selects only declared labels within the
        admitted step budget, invokes only `campaign_probe.v1`, and emits a
        verdict-free candidate. Contract, guest, broker, host observer,
        finalizer, lifecycle-runner, and provider-process conformance tests
        cover the complete code path. The live KVM evidence join remains W5.5
        and cannot be claimed from these focused tests.

## Path and architecture drift found during implementation

- The prompt named `crates/mvm-core/src/plan/execution_plan.rs`; the owning
  type moved to `crates/mvm-contract/src/plan/execution_plan.rs` and is
  re-exported by `mvm_core::plan`.
- `crates/mvm-cli/src/commands/vm/up/` remains the authoritative CLI admission
  path, while the reusable in-process admission seam is now
  `mvm_hostd::plan_admission::admit_and_start`.
- `AgentSessionCommand::Prompt` and `AgentSessionJournal` remain the generic
  transport-neutral contract. The assurance-specific production adapter now
  lives in `mvm_hostd::assurance_agent_adapter`. The generic framed controller
  and terminal replay wrapper now exist; `mvm-extension-provider` owns the
  bounded process boundary. Its concrete admitted runner invokes the adapter
  after `OperatorConfiguredTrialBooter` re-verifies the exact signed pack and
  supplies the admitted boot. The checked-in binary fails before serving when
  its strict operator boot configuration is absent or mismatched.
- The generic extension contract versions both `guest_workload` and
  `isolated_controller` placements, but the present execution bridge safely
  implements only the former. A future isolated controller can reuse the same
  pack and broker contracts; this version fails its admission explicitly.
- The counterparty checkout used for conformance is
  `plans/mvm-assurance-v0.3.0`; there is no sibling directory literally named
  `mvm-assurance` in this workspace.
- The counterparty's earlier `mvm.extension.manifest/v1` schema still describes
  a controller command and is not an installable pack. The sibling now also
  owns a separate signed, guest-mountable `mvm.extension-pack/v1` build/export
  path for the static `scoutd` guest entrypoint. Its `mvm.extension.v1` frame
  format remains usable above generic admitted dispatch; neither protocol nor
  the extension is compiled into MVM.
- The counterparty requires `source.subject_locator`, although the prompt's
  logical JSON omitted it. MVM includes the bounded locator for exact sibling
  conformance, but it is correlation text and never an executable host path.
- The prompt asks for audit/receipt references inside `mvm_binding`; the
  counterparty's exact-key validator keeps those references on the trial
  result instead. MVM retains them in the richer host-side binding and emits
  the exact counterparty wire projection.

## Cross-repository blocker

The sibling `CampaignRequest` intentionally carries Scout-derived shared
identity only. The missing operator-owned trial, detailed finding, authority,
canary, and destination facts now travel in the separate strict
`mvm.assurance.operator-session-bundle/v1`: the sibling validates the exact
join and sends it through `OpenSession`, then MVM repeats the all-or-nothing
join before durable claim or runner execution. MVM does not derive or default
those facts. The sibling now produces a signed, guest-mountable `scoutd`
extension pack and MVM's generic verifier accepts it. MVM now ships the
concrete operator-configured runner and booter that consume the pack. Its
client-side forced non-certifying downgrade has
been removed in favor of an explicit `--trusted-provider-id` descriptor pin;
this enables certification only after the remaining MVM evidence gates
validate and does not trust a provider bit by itself.

The cross-process session-state blocker is closed. Signed VM registration now
contains an optional generic typed-service proxy binding; ordinary empty
registrations retain their pinned canonical bytes. The resident broker accepts
only descriptors present in both signed service and capability admission,
requires capability invocation, derives the session identity from the VM
registration, and proxies to the controller-owned handler through a bounded
host-only UDS. The controller retains the audit signing key and authoritative
session/evidence state. Missing controller state, mismatched identities,
oversized frames, unsigned descriptors, direct calls, and post-start session
open failure all fail closed; the latter also stops the just-started VM.

The provider launch seam now carries `--provider-state-root` and
`--provider-mvm-home` explicitly from the counterparty. It maps the former to
the provider's `--state-root`, clears the inherited environment, then restores
only the selected `MVM_HOME`. Both sides reject relative roots; MVM also
rejects a symlink replay root, restricts it to mode `0700`, and requires the
strict boot config's `host_mvm_home` to match the active value exactly. The
lifecycle runner's prompt history and provider keys remain under the explicit
provider root; there is no `HOME`, current-directory, credential, or temporary
fallback.

`mvm-security assurance plan` additionally reports the brokers it needs and
cannot reach:

```
immutable_snapshot, builder_microvm, subject_microvm, guest_observer,
host_observer, execution_receipts, artifact_sealing
```

MVM now supplies generic signed extension admission, typed broker enforcement,
a host-owned mediated observer, and signed audit/receipt references, but that
path is not yet connected to the sibling's broker inventory and MVM does not
yet supply trusted guest-observer, attestation, or artifact-sealing evidence
for this campaign. The
counterparty's own milestone M3 ("broker-backed execution") is unstarted, and
its plan 006 states plainly that an ordinary `machine run` receipt must remain
`INCONCLUSIVE`. The sibling's `mvm-securityd` starter returns
`inconclusive_broker_unavailable`; `mvm-security-fixtured` synthesizes evidence
with `certifying: false`. Neither is the trusted MVM-backed provider required
for W9 or a certifying campaign.

The supplied x86_64 KVM/Firecracker lane now proves the MVM side reaches a
real microVM: descriptor exchange, operator-session acceptance, signed-plan
admission, extension-pack promotion, guest-agent startup, observer collection,
exact cleanup, and host finalization all completed. The live run admitted plan
`sha256:18a220846c25a6cec1f0b4f36dd4bfbab764f4e50671394e6da32acfcbd7ef16`,
session `s-ebc20dc44ec9937f1acc4b7c85038c1b`, grant digest
`sha256:b0991c541656cac6ebd02c27389a8b3c299b7cbadd6d4477653a0219545acf34`,
nonce `gn-48c803a9f0c79e8c71eee34b349c8c9a`, backend `firecracker`, and
workload digest `sha256:8ebd17c11112e175e6bbdd3296a7d105dce6dcd74a422c16d008bd16f2870fdb`.
The exact retry replayed the bounded terminal response without creating a
second VM. It remains `INCONCLUSIVE` because no trusted TPM2/SEV-SNP/TDX root
was present and the typed probe reported no attempted effect.
The sibling planner now consumes the published
`sha256:nul-separated-policy-refs-v1` interface through its small shared
policy-identity module and emits MVM's exact four-reference digest over
`operator-network-v1`, `operator-egress-v1`, `operator-fs-v1`, and
`operator-tools-v1` in admission order:
`sha256:5dd0de53b6d211f764728599e291e93a9491dc34f87596e906365fb74c95e0ff`.
The sibling launcher also restores `/usr/local/bin` through its explicit
provider PATH after clearing the inherited environment. A real Scout-linked
request with the canonical digest, signed pack, protocol-v2 plan, strict
operator bundle, explicit provider state root, and explicit MVM home reached
signed-plan admission on the supplied host, then failed closed before the
guest agent: `mvm-oci-init` reported `user-volume activation failed: path
policy denied`, followed by an init panic. The identical retry returned the
durable terminal result without a second admission or execution event. No
Scout-specific MVM exception is appropriate.

## Verification record

- `cargo fmt --all -- --check` — pass.
- `cargo check --workspace --all-targets` — pass.
- `cargo test --workspace` — pass on a clean complete post-closeout run,
  including doctests. The changed aggregate libraries include 692
  `mvm-agentd` tests and 1,906 passing `mvm-hostd` tests. Cancellation-focused coverage
  additionally passed the 57 assurance contract tests, five durable adapter
  tests, four guest cancellation-state tests, the real process-group kill
  test, the strict cancel wire test, the signed-verb admission test, and the
  pre-transport full-identity join test. Five terminal-controller tests cover
  exact completed replay, a sibling-framed response, interrupted/conflicting
  refusal, diagnostic-free durable failure, and fail-closed certification.
- `cargo clippy --workspace --all-targets -- -D warnings` — pass.
- `just check-gated` — pass: x86_64 Linux all-target cross-check plus
  `mvm-conformance --all-targets --features bdd`.
- `cargo run -p xtask --quiet -- check-plan-names` and
  `check-sprint-append` — pass.
- The current assurance contract rerun passes 64 tests, and schema emission
  parses with the six request/result/operator-bundle/extension/provider keys.
- The reference Scout flow produced run
  `scout-1787181844-1787181844602-371467bf57b4`, source digest
  `sha256:371467bf57b495dff263de382d03981b238786810b76866b21be8fa332fad496`,
  revision `ab44bdc5175ce3337fabcc7f392ddadc9679b306`, and requested policy
  `sha256:a2201af69c8ad236dd688087ca494875a6841058b9839e70b806d50d54e4cc21`.
  Scan and planning completed; the only runnable sibling provider was the
  expressly non-certifying fixture, so run/correlation returned the expected
  nonzero status and global `INCONCLUSIVE` with evidence digest
  `sha256:9e3fd7373036c577c02087c4df66906a8767dc5506605cd9178f8a933b3aac3a`.
  No admitted plan, session grant, observer, cleanup, or execution receipt was
  produced by that fixture.
- The native libkrun builder now passes its live six-disk runtime probe. Stage
  0 prepares and reuses the labeled `mvm-nix-store` ext4 image, invalidates
  failed external seeds, and finalizes only an actually mounted persistent
  store; the corrected Stage 0 completed without ext4, data-loss, or capacity
  errors and promoted rootfs
  `sha256:4eea52acc023d58a9f7b25e58297c9ca923ec10b90c7dd83608a49967d1a4b53`.
  The rebuilt image supplies the static `/sbin/mvm-setpriv` used by workload
  images. Builder init launches the automatic agent as UID 990 with exactly
  `CAP_KILL|CAP_SYS_TIME` effective and ambient and `NoNewPrivs=1`; the strict
  live result recorded capability mask `0000000002000020` and exit code zero.
  Mutable XDG, Rustup, Cargo, target, and temporary state use explicit `/out`
  paths without changing `HOME`. Sparse-store regrowth, dirty-journal recovery,
  and SHA-256 kernel-cache validation are covered. The source-current native
  lane passed focused sparse-store, Stage 0 prepopulation/recovery, Stage 0
  binary, VMM, and hostd assurance tests; workspace all-target/all-feature
  Clippy and check; and BDD required-feature compilation. Its durable marker
  set records all eight completed gates, so the native builder blocker is
  closed.
- Hardware discovery is also fail-closed: neither the macOS host nor the
  libkrun builder exposes TPM2, SEV-SNP, or TDX devices, and the builder has no
  `/dev/kvm`. The three MVM attestation providers remain dependency-free
  `NotYetImplemented` stubs. An owner-approved Lima test VM has `/dev/kvm`, but
  no admission-visible Lima backend exists in this checkout and that dev tier
  cannot supply production or attestation evidence. The exact-current builder
  probe (`mvm-builder-vm-1787214676670-12105`) confirmed absent
  `/dev/{tpmrm0,tpm0,sev-guest,tdx_guest,kvm}`, absent TSM/TDX report paths, and
  an empty `/sys/class/tpm`; all seven all-feature provider tests pass by
  proving the three providers return `NotYetImplemented`. W5.3's verifier-to-
  finalizer join is complete and covered by seven focused tests, but no native
  provider can yet produce the required verification metadata on this
  hardware; every real attestation-required result therefore stays
  `INCONCLUSIVE`.
- The owner-approved Lima KVM test VM is `aarch64`, while the currently
  published sibling `scoutd` pack declares `target_arch: x86_64`; MVM's generic
  pack verifier correctly refuses that identity mismatch. A live canary needs
  an arm64 pack/workload pair or an x86_64 KVM test environment, supplied by
  the sibling/operator rather than a Scout-specific MVM fallback.
- Production assurance admission now rejects the configured `qemu` and `mock`
  dev/test backends before artifact or pack work. The focused refusal test and
  `mvm-hostd` all-target/all-feature Clippy with warnings denied pass. No
  admission-visible Lima backend exists, and this negative admission proof is
  not a KVM execution, so W5.5 remains open.
- `cargo run -q -p mvm-contract --features schema --bin
  emit_assurance_schema | jq -c 'keys'` — pass; emitted the request, result,
  generic extension-pack, campaign-request, and provider-response JSON-schema
  keys.
- Sibling `cargo test --workspace` with an isolated target — 73 pass, including
  its request/result conformance fixtures, frame protocol, starter provider,
  and explicitly non-certifying fixture tests. Its host `mvm-scout` package
  disables implicit binary discovery; the guest `scoutd` is built only through
  the explicit MVM-API harness. Its current 4 guest-harness tests and 4
  pack-producer tests pass. Sibling all-target check, all-target/all-feature
  Clippy, and formatting pass.
- Focused generic controller coverage — pass: three frame-codec tests, three
  blocking-stream tests, and five counterparty request/response tests. The
  emitted schema now includes `mvm.security.provider-response/v1`.
- Sibling trusted-provider change — `cargo test -p mvm-security --lib` passes
  17 tests and `cargo clippy -p mvm-security --all-targets -- -D warnings`
  passes. A new negative matrix proves neither a provider claim without an
  operator pin nor a mismatched pin can certify.
- Strict operator-session handoff — the focused MVM counterparty suite passes
  8 tests, the durable provider controller passes 9, the fixed lifecycle
  runner passes 9, the durable prompt/cancellation adapter passes 7, the
  operator-configured booter passes 7, the provider binary
  passes 3, and the real process boundary passes 3. The sibling `mvm-security`
  library passes 24 tests, including the
  explicit CLI input, exact Scout join, unknown-field/mismatch refusal, and
  acknowledgement-count binding. The process tests prove state lands only
  under the explicit root with private permissions, require the configured
  global MVM root to match the explicitly restored `MVM_HOME`, and leave
  unrelated ambient traps untouched. `cargo check -p mvm-hostd --all-targets`
  and the sibling `cargo check --workspace --all-targets` pass; touched-crate
  all-target Clippy passes in both repositories with warnings denied. Schema
  emission includes
  `mvm.assurance.operator-session-bundle/v1`.
- Focused lifecycle recovery — 4 guest cancellation-state tests and 27 host
  assurance broker tests join the concrete provider suites above. Cancellation
  before dispatch never enters the executor, in-flight deadline cancellation
  is committed once, expired or closed sessions never dispatch, and durable
  provider state contains no prompt, credential, or unbounded diagnostic.
- Sibling-owned extension pack — the static x86_64-musl `mvm-scoutd`, strict
  build recipe, SPDX SBOM, and independent Ed25519/OpenSSL pack producer emit a
  guest-mountable `mvm.extension-pack/v1`. MVM's generic verifier accepted
  pack `c193d328a039b2ff9fdc9a20c7b2a32dc70759f1d6b40c6d6fd143218349e3c9`
  with artifact
  `d14e60a2ea06823debf82d9278db0c6f03de413423ddbc4efa804fa7244c3d67`
  and signer `4f4e286c2e1978f76cb168c56825b828`; staged tamper, expiry,
  revocation, wrong-signer, unsupported-protocol, and artifact-budget refusals
  are covered. The concrete booter also re-verifies and promotes the exact
  signed pack from its strict private config. The guest loop now calls the
  canonical MVM assurance API for each admitted destination label within its
  step budget and returns no verdict. A rebuilt conformance pack was accepted
  as pack `230e7cc19eb5b045edbc05e2d63887fed8b9571cc3adafd5ee06f0a25f5c6d01`,
  artifact `7321a3853a2e04ee1d53bef5e6931b9d2e672450900c9e7580e04f8f2e3432fc`,
  signer `e4398c7acd5e776cacc3d354dfdcc994`; its ephemeral publisher key is not a
  release trust root, so this closes the typed guest wiring without claiming a
  certifying campaign.
- The signed controller-service bridge passes 11 signed-control tests, four
  controller-proxy boundary tests, 18 broker-daemon tests, the capability-only
  direct-call refusal, the admitted boot rollback test, and a real
  `campaign_probe.v1` round trip through the controller UDS that records host
  evidence. Focused all-target Clippy across contract, core, VMM, runtime and
  hostd passes with warnings denied.
- The durable campaign-controller wrapper passes five focused tests: exact
  response replay without a second runner call, real sibling-compatible frame
  round trip, interrupted and identity-conflicting refusal, durable failed
  refusal without diagnostic persistence, and fail-closed host-derived
  certification. Focused `mvm-hostd --all-targets` Clippy passes with warnings
  denied.
- The embedded host and guest payloads were forcibly rebuilt with cache reuse
  disabled before the final native lane. The source-matched Stage 0 image then
  rebuilt successfully with the workspace-local `third_party/am-fs-ext4`
  dependency present in the filtered Nix source.
- No certifying sibling Scout run was executed. A trusted provider executable,
  installable signed guest extension, and bounded typed-probe loop now exist,
  but hardware attestation providers remain unimplemented and no real KVM
  canary supplied the joined evidence required for certification. Item 7 is
  closed by the fresh marker root
  `/nix/var/mvm/assurance-gates/2026-08-20-admission-ai-assurance-final-current`;
  all eight gates passed against the exact current source, including 559 Linux
  `mvm-vmm` tests, 72 focused hostd assurance tests, and workspace
  all-target/all-feature Clippy with warnings denied. The source-matched final
  VM state is `mvm-builder-vm-1787217398177-7306`.
  The concrete provider also carries the operator-selected attestation mode
  into the signed plan and refuses an attestation-required request against
  `noop`; ordinary non-attesting launches retain the safe default. QEMU/mock
      remain production-refused and QEMU is available only through an explicit
      non-certifying dev/test tier. A live canary attempt exhausted the builder's
      shared 68.7 GiB Nix store while realizing the aarch64 dev tenant image; no
      pre-existing state was removed, so the KVM lane remains open. A fresh
      96 GiB isolated-store retry then stopped before VM startup because Stage 0
      required `nix-2.34.7-aarch64-linux.tar.xz` from `releases.nixos.org`, which
      is not resolvable in this environment.

## Narrative coverage

The one implemented probe is `egress.admission.v1`, which serves
network-egress narratives. The campaign the reference scan actually emits is
`mvm.boundary.tool-authority.v1`, which it does not serve. Adding a probe is a
new `ProbeInvocation` variant plus its dispatch arm; the enum is closed so a
variant without an arm does not compile.
