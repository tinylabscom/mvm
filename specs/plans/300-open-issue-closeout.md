# Plan 300 — Open issue closeout

**Status:** TRIAGE COMPLETE — execution pending
**Snapshot date:** 2026-08-10

## Objective

Reduce the current open issues in `tinylabscom/mvm` to a set backed by current
product intent and evidence. Every issue closes only after its implementation,
tests, live witnesses where required, documentation, and GitHub state agree.

This plan is a closeout map, not permission to weaken a security claim or to
close an issue because a nearby implementation exists. Mixed issues must be
split or narrowed before closure.

## Closure rules

An issue is ready to close when all of the following are true:

1. The issue's acceptance criteria match the implemented scope. Obsolete or
   rejected requirements are rewritten in the issue before closing.
2. The implementation is merged to `main` and the relevant unit, integration,
   BDD, security, and platform tests pass.
3. A live witness exists for any backend, kernel, privilege, networking,
   process, or performance claim that static tests cannot establish.
4. The owning plan, `specs/SPRINT.md`, and `specs/REFACTOR-STATUS.md` record
   the same status and evidence.
5. The issue receives a final comment linking the merged PR, test result,
   live-run evidence, and any intentionally excluded scope, then is closed.

The final closeout pass must also check that no issue is being closed merely
because its title was superseded by a refactor. The replacement issue or plan
must carry the remaining acceptance criteria.

## Current disposition

### Closed

#### #2192 — resident warm-launch service contract

The owning warm-launch plan marks this work complete. The repository contains
the typed `WarmServiceRequest`/`WarmServiceResponse` contract, the in-process
`WarmLaunchService`, explicit optional/required/cold modes, lease ownership,
refusal reporting, and lifecycle tests.

Closure recorded on 2026-08-08:

- Final issue comment links `specs/plans/298-warm-claim-service-and-hvf-pool.md`,
  `crates/mvm-contract/src/protocol/vm_backend.rs`, and
  `crates/mvm-runtime/src/warm_service.rs`.
- Contract and runtime warm-service tests passed with the required test-support
  feature; live KVM tests remain intentionally separate for backend issues.
- #2192 is closed as completed. Plan 298's `[x]` status remains unchanged.

### Split or narrow before closing

#### #2101 — default workload kernel and OCI privilege posture

The default-microVM kernel fallback was fixed by PR #2102. The remaining
security question is separate: the OCI guest-agent path now sets
`NoNewPrivs`, but the capability bounding-set posture still needs an explicit
decision and a live witness. The current path intentionally retains narrowly
needed agent capabilities, so “empty bounding set” cannot be assumed without
checking restore behavior.

Close path:

- Edit the issue to separate the resolved kernel-selection defect from the
  remaining OCI hardening finding.
- Decide whether the OCI workload process must have an empty bounding set or a
  documented minimal set. Preserve the agent's authenticated restore needs.
- Add positive and negative Linux tests for the selected posture and run the
  adversarial workload probe on both HVF and Firecracker.
- Close the kernel-selection portion and close the remaining issue only after
  the decision, code, and live evidence are merged.

#### #2211 — host-side eBPF vsock telemetry

The loader, observability sidecar, supervisor attach/detach hooks, metrics,
audit event, CI build, and live Linux attach path are present. The current
ring-buffer event still reports an IPv4 destination with `bytes = 0` and no
latency measurement, so the issue's original tuple `(plan_id, vm_id,
destination, bytes, latency)` is not fully implemented.

Close path:

- Either narrow the issue to the completed bounded connection-observation
  spike and document that byte/latency accounting is follow-up work, or
- implement byte and latency accounting, add IPv6 behavior or an explicit
  limitation, and prove the real substitution-endpoint path end to end.
- Update the issue acceptance checklist and close it only after the selected
  scope is reflected in the code, tests, and `specs/REFACTOR-STATUS.md`.

### Security, kernel, boot, and audit issues

#### #2135 — Security lane is red

This is an active generated tracker, not stale bookkeeping. The latest
Security run has failed mutation-witness jobs in `mvm-cli`, `mvm-core`,
`mvm-agentd`, `mvm-hostd`, and `mvm-runtime`.

Close path:

- Triage every surviving mutant and add or repair the corresponding witness.
- Re-run the mutation jobs and the full Security workflow.
- Do not rewrite the mutation baseline unless the mutated behavior was
  intentionally removed and the issue documents why.
- Let `.github/workflows/security-lane-watch.yml` close the issue after a clean
  scheduled or release run.

#### #2289 — kernel pin freshness

The generated freshness tracker reported both synchronized kernel inputs one
point release behind the latest Linux 6.12 LTS release. The prior #2128
closeout covered the preceding 6.12.102 update; #2289 is the current tracker
for the next point-release remediation.

Close path:

- Update the custom workload kernel and libkrunfw inputs together, including
  source hashes and any generated or recorded metadata. This change updates
  both consumers to Linux 6.12.103 with the verified SRI hash
  `sha256-8UOqreiHe6VhbniLRIJXbbKEgbz1V+9Tf0/MOTj8MXY=`.
- Build and verify both kernel artifacts and run the kernel-pin freshness
  check.
- Run the relevant workspace, kernel, verified-boot, and reproducibility tests.
- Roll the new kernel through each existing VM with `mvmctl vm rekernel`;
  fleet rollout remains the mvmd responsibility.
- Add the release/build and rollout evidence to the issue, then close it.

#### #2165 — read-only block root with `rw` bootargs

The HVF default block-root command line still asks Linux to mount `/dev/vda`
read-write while the workload runner attaches the rootfs read-only.

Close path:

- Make the root mount mode a single typed contract shared by disk attachment,
  bootargs, and the guest mount policy. Do not rely on contradictory duplicate
  `root=` declarations.
- Add unit tests for read-only, writable-development, and verity-root shapes.
- Add a live macOS/HVF plain-ext4 boot witness that reaches userspace, and a
  Firecracker regression witness for parity.
- Update the boot documentation and close the issue after both backends pass.

#### #2107 — mirror signed audit appends into tracing

The signed chain remains separate from operational tracing, and no complete
mirror exists in `AuditEmitter`.

Close path:

- Emit one best-effort, sanitized diagnostic event only after a successful
  chain append. The mirror must never affect signing, ordering, or success.
- Include only non-sensitive event labels and stable identifiers; exclude
  secrets, credentials, environment values, raw policy, and sensitive paths.
- Test field parity, sensitive-field exclusion, hostile subscribers, and byte
  identity of the signed chain with mirroring enabled and disabled.
- Document that the verified chain remains the source of truth, then close.

### L3 networking

#### #2180 — L3 spec unreachable from CLI/IR boot paths

The CLI now derives `NetworkMode::L3Vsock` from workload IR, but the full
`L3NetworkSpec` is still not carried through every synthesis and boot path.
Several `SynthesisInput` sites still use `l3_network: None`, and the local
hostd boot path still defaults `network_mode`.

Close path:

- Add the user-facing L3 fields to the workload IR with secure defaults.
- Thread the typed spec through `SynthesisInput`, plan signing, admission,
  and the local boot request without reconstructing or discarding it.
- Remove hardcoded defaults from boot paths except for deliberately networkless
  test fixtures.
- Add a conformance witness that declares MTU, DNS, ingress, and IPv6 fields,
  then proves the same values reach a booting VM.
- Add a negative test proving an unsupported host refuses before boot.

#### #2181 — no IPv6 packet across a live guest boot

Host allocation, kernel support, guest configuration, and userspace datapath
coverage exist. The missing evidence is a real Firecracker/HVF guest boot
carrying an admitted IPv6 flow.

Close path:

- Run a real guest with an admitted IPv6 lease and verify the guest address,
  peer route, and default route from the guest/kernel view.
- Carry an admitted IPv6 TCP flow and response through the real backend.
- Prove an unadmitted destination is refused and a spoofed source is dropped.
- Run the witness on both Firecracker and HVF, or explicitly split the issue
  into backend-specific validation issues with honest capability labels.
- Store the exact source revision, host, backend, and witness output in the
  research note and issue before closing.

### Warm-launch workstream

The dependency order is:

```text
#2192 contract
    ├── #2193 artifact prewarm
    ├── #2194 HVF golden-VM restore
    │     └── #2195 claim-time read-only shares
    ├── #2196 Firecracker warm backend
    ├── #2197 process hardening
    ├── #2198 user-visible timing/refusal semantics
    └── #2199 benchmark and CI gates
```

#### #2193 — asynchronous content-addressed prewarm

The artifact store, durable jobs, restart recovery, source validation, and
authenticated readiness verifier are implemented. Backend-specific golden-VM
factories remain.

Close path: connect the Apple Silicon and Linux factories to the shared
verifier; prove cache hit, miss, invalidation, corruption, concurrent
prewarm, and restart recovery; then close only after a warm claim cannot enter
with a missing or mismatched artifact.

#### #2194 — Apple Silicon HVF golden-VM pool

Parent reservation, pause/resume, snapshot-frame codecs, channel rebinding,
resident handoff, and a Darwin warm-claim matrix have landed. The remaining
question is whether the final design is the signed paused-parent handoff or a
true copy-on-write child restore with all required device/vCPU state.

Close path: record that design decision in the issue, prove fresh identity,
authority, channel setup, failure quarantine, restart recovery, and live
readiness on release-built Apple Silicon. Close only when the advertised
capability bits correspond exactly to the proven path.

#### #2195 — fixed virtio-fs share slots

Close path: add fixed share-slot topology, opened-directory claim bindings,
read-only enforcement, race/symlink/disappeared-directory refusal tests, and
proof that host paths and directory contents never enter pool keys or saved
state. Unsupported backends must refuse warm mode rather than report a cold
launch as warm.

#### #2196 — Linux Firecracker warm backend

The paused-child preload path and an authenticated source-matched witness
exist, but the full Linux matrix and production standby admission remain.

Close path: validate factory capture, child restore, identity/authority
handoff, cleanup, quarantine, restart recovery, snapshot device/network
restrictions, and timing on the exact merged source in the builder and real
KVM environments.

#### #2197 — resident process hardening

Close path: document Linux and macOS process boundaries separately; enforce
least privilege, inherited-resource allowlists, no-new-privileges, resource
limits, and share confinement; then add unauthorized file/socket access,
signal, privilege-retention, refusal, and cleanup tests for both platforms.

#### #2198 — timing, refusal, and CLI fallback behavior

Internal timing and typed warm outcomes exist, but the user-facing contract
still needs explicit warm-required and cold behavior.

Close path: add explicit `--cold` and warm-required behavior, stable text and
machine-readable refusal fields, exact-300ms tests, and a regression proving
that no launch labeled warm can fall back to cold. Keep command execution and
teardown outside the warm readiness window.

#### #2199 — benchmark and CI gates

The Darwin 1,000-claim matrix is evidence, not the complete gate.

Close path: run 1,000 claims for every supported backend, image, CPU/memory
shape, cache state, and supported share shape; retain all outliers; publish
p50, p95, p99, maximum, refusal rate, and cold comparison; then enforce
strict `<300ms`, p50 ≤30ms, and p99 ≤50ms in CI.

### Agent-runtime and Studio workstream

Implement these in order so the later surfaces consume shared contracts:

```text
#2167 durable session/event contract
    └── #2168 policy and human approval
          └── #2170 typed capability bindings
                └── #2169 bounded Studio inspector
                      └── #2166 parent epic closeout
```

#### #2167 — durable agent session and event contract

Define stable public session IDs, lifecycle states, versioned durable and
ephemeral events, sequence/cursor rules, idempotent prompt delivery,
retention, redaction, bounded history, and typed reconnect/error behavior.
Use the existing transcript and audit mechanisms rather than creating a
parallel persistence model.

Close gate: serialization round trips, reconnect/cursor/idempotency tests,
adapter restart tests, and proof that secrets never enter durable history.

#### #2168 — runtime permissions and human approval

Define policy vocabulary and precedence for allow, deny, and ask while keeping
signed admission and guest enforcement authoritative. Approval can only add a
decision for an already-admitted capability.

Close gate: default denial, precedence, expiry, cancellation, replay,
unauthorized response, tampering, missing state, bounded metadata, and audit
tests.

#### #2170 — typed capability bindings

Add versioned descriptors, input/output schemas, admission-time and invocation-
time allowlists, bounds, timeouts, cancellation, binding identity, and typed
failures over the existing agent protocol.

Close gate: positive and negative protocol round trips, authorization and
confused-deputy tests, size/time limits, cancellation, and secret non-exposure.

#### #2169 — bounded Studio inspector

Expose session history, bounded output, process state, filesystem operations,
approval requests, and capability discovery through the shared client and
gateway contracts. Keep read-only-by-default behavior and fail closed when a
backend cannot enforce an operation.

Close gate: reconnect, stale cursor, authorization, denied mutation, bounded
rendering, audit emission, teardown, and local/gateway parity tests. Studio
UI work remains in the Studio repository.

#### #2166 — parent epic

Close after #2167, #2168, #2170, and #2169 have merged, their compatibility
notes are written, and one end-to-end agent session uses the shared contracts
without weakening MVM admission, audit, or production shell restrictions.

#### #2083 — versioned mvmctl Studio launcher

Keep this as a cross-repository dependency until the Studio server handshake
is agreed. Then implement fixed artifact lookup, ownership/permission checks,
private readiness handoff, version negotiation, production refusal, clean
shutdown, and no-secret-in-argv/log/state tests. Close only after the matching
Studio server contract and an end-to-end local launch are both available.

## Execution sequence

1. With #2192 closed, split/narrow #2101 and #2211.
2. Repair the generated security tracker (#2135) and current kernel freshness
   issue (#2289), because they affect the evidence quality of every later
   closeout.
3. Fix the rootfs boot contract (#2165), L3 wiring (#2180), and live IPv6
   witness (#2181).
4. Finish the warm-launch dependency graph from #2193 through #2199.
5. Implement the agent-runtime contract sequence (#2167 → #2168 → #2170 →
   #2169), then close #2166 and coordinate #2083 with Studio.
6. Implement the audit-to-tracing mirror (#2107), or explicitly descope it
   from the product roadmap with a recorded decision rather than leaving it
   indefinitely open.
7. Run a final open-issue query, compare every issue against this plan, update
   all three progress documents, and close only issues with complete evidence.

## Final closeout checklist

- [ ] Every issue body has current acceptance criteria and no obsolete claim.
- [ ] Every merged PR and live witness is linked from the issue.
- [ ] `cargo test --workspace` is green on the host; Linux-only tests ran in
      the builder VM.
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` is green in the
      required Linux builder environment.
- [ ] Required Nix, Firecracker, KVM, kernel, and platform gates are green.
- [ ] `specs/SPRINT.md`, the owning plan, and `specs/REFACTOR-STATUS.md` agree.
- [ ] A fresh GitHub open-issue query contains only intentionally active work.
