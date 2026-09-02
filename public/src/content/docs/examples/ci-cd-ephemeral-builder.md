---
title: CI/CD ephemeral builder
description: Use mvm in CI without preserving accidental runtime state.
---

CI should prefer disposable runtime guests and explicit build artifacts.

## Basic CI shape

```sh
export MVM_HOME="$PWD/.mvm-ci"

mvmctl doctor --json
mvmctl machine build ./ci-worker --json
mvmctl run --timeout 600 --receipt /tmp/mvm-run-receipt.json -- ./scripts/test.sh
```

Keep generated receipts as build artifacts when they are useful for audit or
debugging. Do not persist the full runtime state unless the job explicitly
needs a cache.

## Cache policy

It is reasonable to cache:

- Nix store/substituter state in the builder environment;
- downloaded release artifacts after verification;
- manifest build slots for trusted branches.

Avoid caching:

- guest runtime directories from untrusted jobs;
- snapshots that may contain secrets or source code;
- broad host directories mounted read-write into the guest.

## Cleanup

```sh
mvmctl machine stop --all --yes
mvmctl manifest prune --orphans --dry-run
mvmctl cache prune --orphan-builds
```

Use dry-run first on shared runners. `machine stop --all` refuses to run
without a confirmation, so a non-interactive job has to pass `--yes`.
