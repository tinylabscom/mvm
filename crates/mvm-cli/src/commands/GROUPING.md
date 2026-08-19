# CLI command grouping map (Plan 178 / ADR-027) — LOCKED

Old→new mapping, settled (decisions D1–D6). ~57 flat top-level variants →
top-level daily verbs + a small set of noun groups; internals hidden.
**Clap group = `commands/<group>/` subdirectory, one file per subaction**
(folds in Plan 153's directory split).

## Principles
1. Daily-driver verbs / primary entry points stay top-level.
2. No single-member or semantically-forced groups (no `net`, no `store`).
3. Don't super-group commands that already own subcommands (avoids 3-level
   nesting): `image`/`catalog`/`manifest`/`artifact` stay separate.
4. Internal/subprocess commands hidden from `--help`.

## Top-level

**Daily verbs / entry points:**
`up` · `run` · `exec` · `invoke` · `ls` · `console` · `down` · `logs`
· `dev` · `doctor` · `init`
(run-family `up`/`run`/`exec`/`invoke` collapse is committed-intended,
deferred to Task 7 — see plan.)

**Already-grouped domains kept top-level** (each owns subcommands):
`image` · `catalog` · `manifest` · `artifact` · `network` · `secret`
· `bundle` · `deps` · `storage` · `cache` · `pool` · `session` · `volume`
· `snapshot`

## Groups (clap group = directory)

**`build/`** (D1) — `build image`(was the bare `build`) · `build compile`
· `build validate` · `build kernel`(from flat `kernel.rs`).

**`vm/`** — act on an existing/running VM: `vm pause` · `resume` · `snapshot`
· `ttl`(was `set-ttl`) · `wait` · `boot-report` · `diff` · `cp` · `fs`
· `proc` · `sandbox` · `forward`. (`session`/`volume`/`snapshot` already
own subcommands → kept top-level; revisit if they read better under `vm`.)

**`trust/`** — provenance (extends existing `trust add/list/remove`):
`trust attest` · `receipt` · `audit`. (`sign` is NOT here — the only `sign`
is `env::sign`, install/entitlement re-signing → `env sign`. `bundle`/`deps`
already own subcommands → keep top-level; fold in only if it reads better.
The clear single-verb wins are `attest`/`receipt`/`audit`.)

**`ops/`** — `ops metrics` · `ops config` · `ops mcp`.

**`env/`** (D5) — `env bootstrap` · `cleanup` · `uninstall` · `update`
· `sign` (`env::sign` — re-sign mvmctl+supervisors with the VMM entitlements).
Lift `dev`/`doctor`/`init` OUT of `env/` to their own top-level modules so
`env/` = the `env` group 1:1.

## Hidden (`#[command(hidden)]`)
`shell-init` · `reconcile` · `persistent-builder`
(`__qemu-vsock-bridge` already hidden.)

## Settled decisions
- D1 `build` group (not `pkg`). D2 image/catalog/manifest/artifact separate.
- D3 no `net` (keep `network`); `forward`→`vm`. D4 no `store`.
- D5 `env` group; dev/doctor/init top-level. D6 run-family → Task 7 (intended).
