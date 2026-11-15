---
title: "Open-issue burn-down 2026-11-14: lane-red triage, cold-home lock ordering, witness pitfalls"
author: Ari
date: 2026-11-14
branch: main
cost: { minutes: 180, tokens: 400000 }
id: l-5471-burn-down
scope: repo
status: active
src: agent
touches:
  - scripts/check-no-ssh.sh
  - features/suites/s29_doc_examples/docs_coverage.toml
  - crates/mvm-vmm/src/host/workload_wait.rs
---

## Decided

- A red "lane is red" issue is closable when the newest *scheduled* run is green and a named commit explains the fix — #5334 was fixed by 721160ce9b (#5445) + bfcbbba9ba (#5435), not by any dispatch.
- #5462 (Security lane): the 2026-11-14 scheduled run failed only "No SSH of any kind" because #5475's share deny list names `id_rsa`/`id_rsa.*` as deny patterns. The gate's ALLOWED_FILES (with a why-comment) is the documented remediation; fix in PR #5486.
- #5369 (CI main red): three jobs. BDD failures were (1) operations-cookbook.mdx still assigning a bare-string env after #5463 made EnvValue explicit — write `literal("dev")`; (2) `policy validate ./policy/api-group.toml` outside the docs coverage ledger — a scenario staging the guide's own group file moves it (and the pack-sources variants) uncovered→covered; regenerate with `MVM_UPDATE_DOCS_COVERAGE=1 cargo test -p mvm-conformance --test conformance --features bdd -- -i '<repo>/features/suites/s29_doc_examples/*.feature'` (the `-i` filter needs the glob form; a bare file path selects 0 scenarios). `ui::success` is verbosity-gated and prints to stdout, so assert with `--verbose` on stdout. The aarch64 failure was `read_to_end` on a pty master propagating EIO — EIO is normal slave-close hangup; treat as EOF like `pump_output` does. Fixes in PR #5499.
- #5294 code is fully landed on main via #5281 + #5309 (HostDialRoute taken by the mailbox process; libkrun/QEMU/apple-container declare guest_mailbox). Only live witnesses remained.
- #5306 premise is partly stale: `wait_for_workload_exit` (300 s cap) has no foreground-CLI caller outside wasm — foreground runs read the exec stream. Remaining: live verification (Firecracker run >300 s, crash-without-report → UNKNOWN, pid-reuse done in #5332).

## Tried and ruled out

- #5300: two prior lanes found no safe package/version to remove from mvmctl's release closure; the issue itself says document blockers and ask for scope disposition rather than forcing a removal. Treat as blocked, not actionable.

## Watch out

- `bin/dev` silently overrides `MVM_HOME` with the pair-keyed home (`~/.local/state/mvm/pairs/<digest>/home`), so "cold home" repros through bin/dev are not cold. Use the raw pair-built binary (`target/pair-<digest>/debug/mvmctl`) with an exported MVM_HOME for real isolation.
- The dev-surface guest-runtime build takes ~25 min per cold home and fails with "source changed while guest runtime was building" if the checkout moves mid-build (including a `git pull`). Interrupted builds leave an incomplete runtime-overlay cache that fails closed with "run mvmctl bootstrap"; `rm -rf <pair home>/cache/runtime-overlay/<version>` + `bin/dev bootstrap` recovers.
- Cold-home concurrent launches ARE serialized: the second launch waits on the guest-runtime lock ("waiting for guest runtime — held by pid ...") and kernel prep happens inside that window, so the #5471 race may already be fixed on main — verify with a full cold-home dual launch before designing a fix.
- Pre-commit hook runs cargo fmt + scoped clippy per commit; under load a commit can look timed out while still having landed — check `git log` before retrying.
- A PR that never receives CI events (zero check runs across pushes/close-reopen) may be in a CONFLICTING merge state — rebase onto current main first; GitHub can silently skip pull_request workflow delivery for unmergeable heads.
- An interactive rebase that DROPS a later commit replays the earlier commit's tree — a ledger/file regen amended into the dropped commit's neighbor is lost. Re-verify the working tree after any rebase surgery.
- `scripts/run-gcp-kvm-test.sh` runs the program as an unprivileged `mvm-test` user (Firecracker refuses root). A from-source RELEASE build wants the guest runtime built from the checkout and some step in that path prompts for sudo, which `mvm-test` cannot satisfy — the overlay cache is left incomplete ("runtime overlay artifact incomplete ... missing overlay.ext4") and every launch then fails closed with "run mvmctl bootstrap". The repo's own `just bdd::live-ci` lane avoids this: it builds a DEBUG mvmctl with `--features user,embed-host-bins`, which resolves the runtime overlay from the published channel instead of building it. The remote CARGO_TARGET_DIR is worktree-isolated at /opt/mvm/.mvm-test/target, not /opt/mvm/target.
- #5486 (security lane fix) merged; #5462 closed on the green dispatch. #5306's run->300 s item verified live on GCP Firecracker: sleep 320 exits 0 at 321 s.
- #5488 landed the same console-EIO and cookbook-env fixes in parallel with my #5369 branch — check `gh pr list` and recent merges before implementing; the remaining unique value was the policy-validate scenario + ledger promotion (PR #5511).
