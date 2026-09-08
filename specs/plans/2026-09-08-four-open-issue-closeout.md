# Four-open-issue closeout

Backing: shipped-source
Validation: check-sprint-append

**Opened:** 2026-09-08
**Baseline:** `main` at `1c8d5154c3` after issues #3211 and #3213 closed

## Outcome

Close the four issues that remained open after the signing-smoke recovery and
Linux 6.12.109 pin landed: #3207, #3190, #3039, and #3011. Each issue gets its
own reviewable delivery branch, regression coverage, operational evidence, and
issue-closing pull request. This plan does not turn unrelated findings into the
same change; a new defect gets a new issue and an explicit dependency here.

## Verified baseline

| Issue | Current fact | Completion witness |
| --- | --- | --- |
| [#3207](https://github.com/tinylabscom/mvm/issues/3207) | The installed CLI fetches `DEFAULT_BOOT_IMAGE_TAG`, while the CLI release gate validates the highest published boot-image tag. | The release gate validates and attaches the exact tag the built CLI fetches, with a structural regression that fails if the two diverge. |
| [#3190](https://github.com/tinylabscom/mvm/issues/3190) | A failed builder run has been observed leaving the steady-state store lock unavailable for the full wait budget; the surviving owner is not yet proven. | A deterministic failure reproducer identifies the owner, the corrected failure path releases/reaps it, and the next builder acquires the same store promptly. |
| [#3039](https://github.com/tinylabscom/mvm/issues/3039) | Explicit warm claims now fail loudly, but the restored child still does not complete the authenticated post-restore identity handshake on HVF or Firecracker. | The existing live warm-claim BDD scenario passes on both backends without weakening authentication or the explicit-residency failure policy. |
| [#3011](https://github.com/tinylabscom/mvm/issues/3011) | The repository has zero self-hosted runners; hosted macOS cannot provide Apple Silicon plus non-nested HVF. | A hardened Apple Silicon runner executes the live macOS documented-surface job; the recorded-evidence fallback skips automatically. |

## Delivery shape and ordering

Use one worktree and one pull request per issue. #3207 goes first because it is
a release-correctness gap. #3190 can proceed independently. Hardware
provisioning for #3011 can start in parallel with those code changes, but its
workflow cutover lands only after the runner passes a local burn-in. #3039 can
start privately after its disclosure gate and does not publish until release
clearance is recorded.

1. #3207 — couple the shipped boot-image tag to the release gate.
2. #3190 — prove and correct failed-builder lock ownership.
3. #3039 — repair the authenticated warm-child activation path after clearance.
4. #3011 — cut the documented-surface lane over to the hardened runner.
5. Run the cross-issue closeout sweep and confirm all four issues are closed.

The runner can be provisioned before step 3. The current `@warm_claim` scenario
remains an explicit reported skip until #3039 proves both backends; runner
availability must not be represented as warm-claim coverage.

## Global guardrails

- [ ] Before public work on #3039, update the opaque private invention/workstream
      record with contributors, dates, alternatives, and relevant private
      commits, then record owner and patent-counsel release clearance. Do not
      link the public repository inward to that record.
- [ ] Preserve and inventory any existing unpublished local #3039 work before
      rebasing or editing it. Never discard, overwrite, or push it as part of
      plan setup.
- [ ] Write the failing unit, structural, integration, or BDD regression before
      each implementation. A reproduction that only exists in a shell history
      is not the regression.
- [ ] Keep Nix, Firecracker, Linux-specific, and non-wasm `mvmctl` runtime work
      inside the builder VM. Native HVF live witnesses run on the authorized
      macOS host or the dedicated Apple Silicon runner.
- [ ] Keep every wait bounded and matched to ownership: events for owned live
      resources, timers for deadlines, reconciliation only for external or
      crash-recovery state. Do not introduce a new polling loop as a shortcut.
- [ ] Preserve fail-closed security behavior. Never weaken artifact identity,
      authenticated restore, store single-writer exclusion, or release gates to
      make a test green.
- [ ] Update this plan, `specs/SPRINT.md`, and `specs/REFACTOR-STATUS.md` in each
      delivery PR. Close an issue only after its merged code and named live or
      operational witness exist.

## Workstream 1 — #3207: one boot-image tag contract

### Reproduce and decide

- [x] Add a failing structural test that reads the compiled
      `DEFAULT_BOOT_IMAGE_TAG` and the release workflow's selected tag and
      demonstrates the current mismatch.
- [x] Make the consumer contract authoritative: the release gate must validate
      and attach the exact boot-image tag the built CLI will request. Remove the
      independent "highest published tag" decision from the CLI release path.
- [x] Keep the boot-image publishing train independent; no CLI release may
      silently advance the default to an image release that does not exist.

### Implement and verify

- [x] Expose or consume the default tag through one machine-readable path that
      both the release test and workflow can verify without duplicating a second
      version literal.
- [x] Validate the complete current asset matrix for that exact tag before any
      CLI release is created, including both architectures and both SDK libc
      variants.
- [x] Extend `tests/release_assets.rs` with positive coverage and negative
      fixtures for a divergent tag, a missing release, and an incomplete asset
      set.
- [x] Run the focused release-asset suite, workflow lint, repository policy
      gates, workspace tests/check, and zero-warning Clippy.
- [x] Exercise a release dry-run or equivalent non-publishing workflow witness
      and record that the tag validated by the gate equals the fresh-install
      download tag.
- [ ] Merge the issue-linked PR and close #3207.

The implementation advances the compiled default to the complete published
`boot-image/v0.1.5` line and makes `xtask release-boot-image tag` the workflow's
machine-readable source. The validator refuses a divergent tag and any empty or
missing member of the 24-asset architecture/libc matrix. The structural
regression first failed against the former highest-release lookup, then the
focused suites, workspace check, workflow lint, and non-publishing live query
passed. The live query resolved the compiled and published tags to the same
`boot-image/v0.1.5` release with all 24 required assets present and nonempty.

## Workstream 2 — #3190: failed-builder lock lifetime

### Prove ownership before changing it

- [ ] Build a deterministic regression with an isolated `MVM_HOME` and short
      lock budget that forces the builder failure after the store lock is
      acquired, then immediately attempts a second acquisition.
- [ ] Record the process tree and lock owner at each transition without logging
      job contents, credentials, or unrelated host paths. Distinguish the
      one-shot caller, hypervisor supervisor, endpoint sidecars, and persistent
      builder session.
- [ ] Audit every spawn on the failing route for descriptor inheritance and
      every error return for child reaping. Treat an inherited descriptor as a
      hypothesis until the reproducer identifies the surviving owner.
- [ ] Separately reproduce or rule out the builder-side `unexpected EOF reading
      a line` under bounded cold-fetch pressure so lock cleanup is not confused
      with the initiating failure.

### Correct the matched ownership boundary

- [ ] Make the process whose lifetime legitimately covers the writable store
      the only lock owner. On every failed one-shot build, terminate and reap
      owned descendants before returning, or prevent accidental descriptor
      inheritance if that is what the evidence proves.
- [ ] Preserve the deliberate persistent-builder contract: a healthy adopted
      session may hold the lock for its VM lifetime, and a competing one-shot
      route must still refuse rather than corrupt the image.
- [ ] Add positive, error-path, and repeated-run tests proving the lock remains
      held while an authorized writer is live and becomes reacquirable promptly
      after failure or teardown.
- [ ] In the builder VM, inject the reproduced failure and show that a second
      build using the same store starts well inside the configured lock budget.
      Verify no orphan supervisor or endpoint remains.
- [ ] Run affected crate tests, full workspace tests/check, Linux gated checks,
      and zero-warning Clippy.
- [ ] Merge the issue-linked PR and close #3190.

## Workstream 3 — #3039: authenticated warm-child activation

This workstream starts only after the global disclosure gate is satisfied. The
previous fix remains valuable: an explicit warm request refuses on a failed
claim instead of silently cold-booting. Preserve that policy while repairing
the handshake itself.

### Diagnose both backends

- [ ] Rebase and reconcile preserved unpublished work only after clearance;
      retain any useful tests without assuming its proposed root cause is
      correct.
- [ ] Reproduce the current `@warm_claim` BDD failure on native macOS/HVF and
      Linux/Firecracker in the builder VM, using distinct isolated homes and
      retaining bounded non-secret diagnostics.
- [ ] Trace the child through fork/restore, transport readiness, authenticated
      Ping, `PostRestore`, acknowledgement, entropy reseed, clock resync, and
      commit. Identify the first state that differs between the restored child
      and a known-good guest on each backend.
- [ ] Add focused failing tests at the proven boundary plus the existing live
      BDD scenario. Include timeout, wrong-session/wrong-key, tampered token,
      and dead-child cases where the affected seam can reject them.

### Repair and prove the contract

- [ ] Fix the smallest shared ownership or activation boundary supported by the
      diagnosis. Reuse the existing authenticated guest-agent protocol and
      backend traits; do not add a second identity-delivery path.
- [ ] Arm any owned readiness observer before resume/activation, keep a bounded
      deadline and supported-host fallback, and perform a final child identity
      and state verification before committing the claim.
- [ ] Preserve policy behavior: explicit warm residency fails on claim failure;
      automatic best-effort residency may fall back only with the existing
      visible diagnostic and never reports a warm claim it did not complete.
- [ ] Prove the live scenario on HVF and Firecracker, including successful
      workload output, consumed standby state, cleaned transient request state,
      and a completed authenticated identity handshake.
- [ ] Enable the warm-claim BDD capability only for backend lanes carrying that
      live evidence. Do not publish warm-start performance claims until the
      measured path proves it used a successful claim.
- [ ] Run security negative tests, affected crate suites, full workspace
      tests/check, gated targets, BDD, and zero-warning Clippy.
- [ ] Merge the cleared issue-linked PR and close #3039. Update the earlier warm
      readiness plan's stale merge-only checkbox to state that the first fix
      merged but did not complete the reopened issue.

## Workstream 4 — #3011: self-hosted Apple Silicon e2e

### Provision and harden

- [ ] Provision a dedicated Apple Silicon Mac with non-nested HVF, current
      macOS, encrypted storage, a least-privilege runner account, and no
      unrelated developer credentials or data.
- [ ] Register it at repository scope with a unique documented label set and a
      narrowly scoped, non-persisted registration token. Record owner,
      patch/update cadence, capacity, alerting, teardown, and credential-rotation
      procedures outside the source tree where operational secrets belong.
- [ ] Because this is a public repository, prove the unique label is reachable
      only from trusted merged-main schedules and protected release callers.
      Fork pull-request code must never execute on this runner.
- [ ] Ensure each job begins from a clean workspace and leaves no workload VM,
      builder session, TAP/device state, signing material, or job credential
      behind. Bound concurrency to the host's proven capacity.

### Burn in and cut over

- [ ] On the target Mac before registration, run the documented prerequisites,
      `just e2e-launch`, and `just e2e-docs` from a clean checkout. Resolve any
      software/setup blocker as its own issue rather than declaring the hardware
      lane ready around it.
- [ ] Change both the macOS host-check and live macOS job to the unique
      self-hosted labels. Update structural tests so the two jobs cannot drift
      onto different hosts or regain a hosted Intel label.
- [ ] Retain the live architecture/backend preflight. A mislabeled or degraded
      runner must refuse before spending the full suite budget.
- [ ] Run the trusted reusable workflow and capture a green witness where the
      host check reports supported, `e2e-docs-macos` boots real HVF guests, and
      `e2e-docs-macos-evidence` is skipped automatically.
- [ ] Prove the release caller blocks on the live macOS job when it fails and
      cannot quietly substitute a stale committed evidence record while the
      capable runner path is selected.
- [ ] Run workflow lint, `tests/github_actions_extended_e2e.rs`, repository
      policy gates, and the complete live macOS documented-surface suite.
- [ ] Merge the issue-linked workflow PR, confirm one post-merge trusted run,
      and close #3011.

## Final closeout

- [ ] Confirm #3207, #3190, #3039, and #3011 are all closed by their merged PRs
      or, for runner provisioning, by the merged workflow change plus the named
      post-merge operational witness.
- [ ] Confirm no required scenario is green through an accidental skip: the
      macOS lane ran on HVF, warm claim ran on both supported backends, the lock
      failure test exercised contention, and the release test compared the
      exact shipped tag.
- [ ] Run `cargo test --workspace`, `cargo check --workspace`, zero-warning
      workspace Clippy, gated targets, and all repository policy checks on the
      final integration commit. Run Linux/Nix/live backend commands only in
      their authorized environments.
- [ ] Mark this plan, the sprint, and the refactor rollup complete with links to
      the four merged PRs and their live/operational evidence, then synchronize
      the clean main checkout with `origin/main`.
