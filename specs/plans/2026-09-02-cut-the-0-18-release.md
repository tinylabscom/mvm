# Cut the 0.18 release

**Opened:** 2026-09-02
**Target:** a published `v0.18.0` GitHub release with signed artifacts, a
matching Homebrew formula, published SDKs, and a docs site deployed from the
tag.

## Where we actually are

`Cargo.toml` has said `version = "0.18.0"` since `2f36df43b1` ("release:
v0.18.0", 2026-08-16). A `v0.18.0` tag exists **on origin**, pointing at
`9846ca4b` (2026-08-17). There is **no `v0.18.0` GitHub release**, no
`v0.18.0` asset, and no run of `release.yml` for that tag — `release.yml` has
exactly one run in its entire history, a `workflow_dispatch` dry-run from
2026-06-30. The last real release is `v0.17.0` (2026-07-08).

So 0.18 is a tag with nothing behind it, sitting 349 commits behind `main`,
while `main` carries 1,146 commits of work since `v0.17.0`.

`release.yml`'s publishing job is `needs: [bdd, e2e-docs, build,
initramfs-image]`. The `e2e-docs` dependency was added on 2026-08-29 by
`b718876112` — twelve days *after* the tag — so the tag predates the gate it
would now have to clear.

### The gate has never passed

`e2e-docs` (`.github/workflows/e2e-docs.yml`) has **never once been green on
either backend**. Every one of the last fifteen Extended CI runs shows both
jobs as `failure` or `cancelled`:

- **Linux / Firecracker** — the cucumber suite hits its 3600 s deadline and is
  killed. On the 2026-09-02 run it died inside `README persistent machine
  lifecycle works end to end`, having spent ~54 min on checkout/toolchain/build
  before the suite even started. Individual live scenarios cost 7–8 min each
  (`machine run --image alpine -- /bin/sh -c 'exit 7'` took 7 m 44 s). The
  script prints `the suite produced no scenario summary — this run proves
  nothing` and exits 70.
- **macOS / HVF** — cannot run at all. `e2e-docs-macos-host-check` fails by
  design on `macos-15-intel` (`mvm-hvf-supervisor` is Apple-Silicon-only and
  links as a stub; the `slp/krun/libkrun` formula is ARM-only), and
  `macos-latest` arm64 reports `HV_UNSUPPORTED` because Hypervisor.framework is
  nested there. Issue #3011.

Extended CI passes `macos_blocks_on_unusable_host: false` so its nightly red
means a regression; `release.yml` passes `true`, so **a tag push today fails at
the macOS host check within seconds.**

### What is already fine

- Hermetic BDD (`bdd.yml`) is green — `BDD conformance=SUCCESS` on PR #3106.
- `ci.yml` is green on `main` through the merge queue.
- `security.yml` nightly is green.
- README→witness coverage is already machine-checked:
  `features/suites/s8_readme_contract/readme_examples.toml` holds 38 examples —
  26 `witness` (live), 4 `hermetic_witness`, 8 `exempt` with written reasons —
  and `readme_coverage.toml` classifies every fenced block. The mechanism for
  "e2e covers every README command" exists and is enforced; what is missing is
  a lane that can actually *run* it.
- Doc gates pass locally: `check-doc-claims`, `check-cli-help-matches-docs`,
  `check-claim-catalog`, `check-witness-citations`, `check-asserted-absence`,
  `check-honesty`. (`check-no-overclaim` reports 20 findings, all of them
  inside `.claude/worktrees/*` — the known nested-worktree scan pollution, not
  a tree defect.)

## Blockers, in the order they have to fall

### P0-1 — macOS evidence without a runner (issue #3011) — DONE

`release.yml` would not publish without live macOS evidence, and no hosted
runner can produce it. Rather than weaken the gate or wait on hardware, the
release now accepts a *recorded local run*, machine-checked.

- [x] `xtask record-release-evidence <lane> <log>` parses the suite's own
      `[Summary]` block, refuses a run with failing scenarios or no summary at
      all, and writes `specs/evidence/e2e/<lane>.json` naming the commit, the
      host, and a digest over every material path.
- [x] `xtask check-release-evidence` recomputes that digest and fails unless the
      record describes the tree being tagged. The commit SHA is recorded only so
      a mismatch can name the files that moved; a rebase moves history under a
      SHA, so the digest is what is trusted.
- [x] `e2e-docs.yml` gains `e2e-docs-macos-evidence`, which runs exactly when
      the host probe says no guest could boot. Pointing `runs-on` at a
      self-hosted Apple Silicon runner therefore retires it with nothing to
      remember to flip back.
- [x] `tests/github_actions_extended_e2e.rs` pins all of the above, so the job
      cannot be deleted and the release go quiet again.
- [ ] Provision the self-hosted Apple Silicon runner anyway and close #3011.
      The evidence path is scaffolding for a missing runner, not a destination:
      it proves the tested tree and the tagged tree are identical, and cannot
      detect a hand-edited record.

**Sequencing constraint this creates.** Any change under `crates/`, `src/`,
`features/`, `examples/`, `nix/`, `scripts/`, `Justfile`, `README.md` or the
manifests invalidates the evidence. `specs/`, `CHANGELOG.md`, `public/`,
`.github/` and the root `tests/` directory deliberately do not — so release
notes, and the evidence file itself, can land after the run. **The suite run
must therefore be the last material step before the tag**, with only the
evidence commit between it and `release-tag`.

### P0-2 — Make the Linux documented-surface lane finish — PARTLY DONE

The budget was the same arithmetic error twice: at 60 minutes the job had no
time for setup, at 120 it had 54 minutes of setup and the suite spent its 60
and was killed mid-scenario. A killed suite prints no summary, so both read as
"this run proves nothing".

- [x] Raise the Linux job to `timeout-minutes: 180` and pin
      `MVM_E2E_TIMEOUT_SECS: 7200` beside it.
- [x] Add `the_linux_job_budget_exceeds_the_suite_deadline`, asserting the job
      budget exceeds the suite deadline by at least an hour, so the two cannot
      drift apart a third time.
- [ ] Confirm one green `Documented surface e2e (Linux, Firecracker)` run.
      Until that lands this is a sized guess, not a measurement.
- [ ] If it still will not fit, attribute the 7-8 min per live transient
      scenario before adding more budget: OCI pull, ext4 materialization,
      Firecracker boot, agent handshake, teardown. The warm-home optimization
      in `crates/mvm-conformance/tests/steps/cli.rs` is already in place, so
      this is real per-boot cost rather than a caching bug — but it has never
      been broken down.

### P0-3 — Resolve the stale `v0.18.0` tag

Nothing was ever published under it: no GitHub release, no assets, no crates
(crates.io publishing is deliberately disabled in `publish-crates.yml`), no npm
package, and PyPI is still on 0.15.1. No consumer can hold a `v0.18.0`
artifact, so deleting and re-cutting is safe and is the right call — it keeps
the tag matching `Cargo.toml`.

- [ ] `git push origin :refs/tags/v0.18.0` and delete the local tag.
- [ ] Re-cut `v0.18.0` at the release commit once P0-1/P0-2 are green.

### P1-1 — CHANGELOG is 224 commits stale

`CHANGELOG.md`'s `[0.18.0] — 2026-08-16` section was written at the version
bump and has been touched once since (`9bb65cea1a`, 2026-08-22). Everything
merged after that is unrecorded.

- [ ] Regenerate the section with `git-cliff`, which is what `just
      _release-prep` already uses. Because the stale tag caps
      `--unreleased` at 2026-08-17, delete it *first* (P0-3), drop the
      existing `## [0.18.0]` block, and regenerate the whole `v0.17.0..HEAD`
      range in one pass — otherwise you get two `## [0.18.0]` sections.
- [ ] Re-date the heading to the actual release date.
- [ ] Call out the user-visible breaks explicitly: the Virtualization.framework
      backend removal (Plan 226 R1P1, `--hypervisor` value gone), the
      overlay-only runtime, and the virtio-fs device deletion if PRs #3106/#3109
      land first.

### P1-2 — Docs on the website

`pages.yml` deploys on `push: tags: v*` and on `release: published`, so the
site redeploys from the tag automatically. It last ran (successfully, by
dispatch) on 2026-08-27 and has **never been exercised by a tag push** —
that trigger path is unproven.

- [ ] Dispatch `pages.yml` manually from `main` before the tag and confirm a
      clean deploy, so the tag-push path is not the first time it runs.
- [ ] Re-run the doc gates on the release commit in a clean checkout (not a
      worktree parent) so `check-no-overclaim` reports honestly.
- [ ] Audit the pages listed under `public/src/content/docs/` that describe
      changed surface for this release — the removed macOS backend, the
      overlay-only runtime, `machine`/`build`/`ops`/`env`/`trust` grouping — and
      fix drift. Per `.agent-memory/notes/`, docs claims drift past every
      existing doc gate at roughly one wrong claim per page, so this is a read,
      not a gate run.
- [ ] Confirm `guides/verify-release.md` (the only page naming 0.18) matches the
      asset set `verify-release` actually publishes.

### P1-3 — SDK publication is behind

PyPI is on 0.15.1; the npm package resolves to nothing. `publish-sdk.yml`
triggers on `release: published`, so it will fire — but it has not fired
successfully in two releases' worth of drift.

- [ ] Dry-run `publish-sdk.yml` (`dry_run: true`) against `main` and fix what
      breaks before the tag, rather than discovering it post-publish.
- [ ] Confirm `crates/mvm-sdk/sdks/release.toml` versions track the workspace
      version.
- [ ] Decide whether npm publication is in scope for 0.18 or explicitly
      deferred, and say which in the release notes.

## Housekeeping that should not block the tag

- [ ] **PR #3113 is malformed** — it commits plan files under
      `.worktrees/mvm-plan-docs/specs/...` instead of `specs/plans/`, its body
      has three empty bullets, and it carries a tool-attribution trailer. Close
      it and re-land the three plans at the correct paths, or fix in place.
- [ ] **PR #3109** (`chore(vmm): delete the virtio-fs device and its FUSE
      server`, −2259 lines) has `Test eBPF telemetry load/attach=FAILURE` and
      `Test=FAILURE`. Either land it before the tag or hold it until after —
      a −2.2k-line deletion merging mid-release is avoidable risk.
- [ ] **PR #3106** (`chore(hvf): delete the now-dead virtio-fs share plumbing`)
      is fully green but `BLOCKED`; find out why and land it.
- [ ] **PR #3089** (agent memory plane) reports `+0/-0, 0 files` — an empty PR.
      Close or repoint.
- [ ] **Issue #3111** — `ensure_home_dir` has no callers, so claim W1.5's 0700
      invariant is enforced by nothing. This is a security-posture claim with no
      live enforcement; fix it before shipping a release whose docs assert it.
- [ ] **Issue #3007** (Extended CI red) closes when P0-2 lands, *plus* the
      `Aarch64 no-KVM bundle smoke (QEMU TCG)` job, which died with exit 143 on
      a runner shutdown after the unaccelerated build overran its budget. Not a
      release blocker — it is not in `release.yml`'s `needs` — but it is half of
      why #3007 stays open.
- [ ] **Issue #3068** (SDK sidecar is a convenience, not a requirement) — not a
      0.18 blocker. Confirm and defer.

## Release runbook, once the blockers are clear

Run in order; each step's evidence is named so nothing is claimed unproven.

1. [ ] `main` is green: `ci.yml` on the merge queue, `security.yml` nightly,
       `Extended CI` (or its remaining failures explicitly accepted and
       recorded).
   [ ] Every material change is already landed — see the sequencing
       constraint under P0-1. Anything that lands after the suite run
       invalidates its evidence and the run has to be repeated.
2. [ ] Local gate on a clean checkout of the release commit: `just ci` (lint +
       test + doctests + bdd), then `just check-gated`.
3. [ ] `just e2e-launch` and `just e2e-docs` pass locally on an Apple Silicon
       host, and `just record-e2e-evidence macos-hvf <log>` writes the record.
       Commit only that file; it is deliberately non-material, so committing
       it does not invalidate itself.
4. [ ] CHANGELOG regenerated and merged (P1-1).
5. [ ] `pages.yml` dispatched green from `main` (P1-2).
6. [ ] `publish-sdk.yml` dry-run green (P1-3).
7. [ ] `release.yml` `workflow_dispatch` with `dry_run: true` — builds,
       packages, host-bin bundling and the Linux cross-build on the real
       runners, publishing nothing.
8. [ ] Delete the stale origin tag (P0-3).
9. [ ] `just check-e2e-evidence` passes against the exact commit to be
       tagged, then `just release-tag 0.18.0`.
10. [ ] Watch `release.yml` through `bdd` → `e2e-docs` → `build` →
        `initramfs-image` → `release` → `verify-release`. `verify-release` is
        the one that proves the published asset set is complete and signed;
        a release is not done until it is green.
11. [ ] Confirm the downstream `release: published` consumers fired:
        `update-homebrew-tap.yml`, `publish-sdk.yml`, `pages.yml`.
12. [ ] Install from the published artifact on a clean machine and run the
        README quick-start end to end. A downloaded binary carries the embedded
        host binaries; a contributor build does not, and only this step proves
        the shipped one does.

## Notes

- Do not relax `macos_blocks_on_unusable_host` for `release.yml`. The whole
  reason that flag is split per-caller is so a nightly can tolerate a standing
  hardware gap while a release cannot.
- `check-no-overclaim` scans nested worktrees. Run the release gates from a
  clean checkout or its output is noise.
