# CLI command grouping map (Plan 178 / ADR-077) — Task 1

Locks the old→new mapping before any code moves. ~57 flat top-level
variants → ~12 top-level + ~7 noun groups, internals hidden.

## Principles

1. Daily-driver verbs and primary entry points stay top-level (short paths).
2. No single-member groups; no awkward double-noun (`build build`,
   `net network`) — if a group's dominant leaf shares its name, keep that
   leaf top-level instead.
3. Internal/subprocess commands are hidden from `--help`.
4. The run-family (`up`/`run`/`exec`/`sandbox`/`invoke`) collapse is
   deferred to Task 7 (read each impl first); listed top-level here unchanged.

## Top-level (12) — kept flat

`up` · `run` · `exec` · `invoke` · `ls` · `console` · `down` · `logs`
· `build` · `dev` · `doctor` · `init`

(`build` and `dev` are already group-shaped: `dev {up,down,shell,status}`;
`build` stays the primary build verb with its args.)

## Groups

**`vm <sub>`** — act on an existing/running VM:
`pause` `resume` `snapshot` `ttl`(was `set-ttl`) `wait` `boot-report`
`diff` `cp` `fs` `proc` `session` `volume` `sandbox` `forward`

**`image <sub>`** — image / artifact sourcing & inspection:
`cache`(was the `image` leaf — inspect cached OCI) `catalog` `manifest`
`artifact` `kernel`

**`pkg <sub>`** — build-time helpers beyond the top-level `build`:
`compile` `validate`
(kept out of `build` to avoid the `build build` leaf/group clash)

**`trust <sub>`** — provenance & signing (extends existing `trust`):
`sign` `bundle` `attest` `receipt` `audit` `deps`

**`store <sub>`** — local storage & caches:
`storage`(dm-thin pool) `cache`(XDG cache) `pool`(warm supervisor pool)

**`net <sub>`** — networking:
`network`→ its verbs surface as `net {create,list,remove}`; **`forward`
stays under `vm`** (it's VM-scoped), so `net` is just the dev-network verbs.
⚠ TENSION: if `net` ends up single-purpose, keep `network` top-level instead.

**`ops <sub>`** — observability / operator:
`metrics` `bench` `config` `mcp`

**`secret <sub>`** — unchanged.

## Hidden (`#[command(hidden)]`)

`shell-init` (shell-eval plumbing) · `reconcile` (registry converge,
internal) · `boot-report` → moves under `vm` AND stays user-visible? No —
`boot-report` is a debugging readout; keep it `vm boot-report`, visible.
Hide: `shell-init` · `reconcile` · `persistent-builder`.
(`__qemu-vsock-bridge` already hidden — leave.)

## Open decisions for ratification

- **D1 `pkg` group** for `compile`/`validate` — or keep both top-level? (They
  avoid the `build build` clash but `pkg` is a new noun.)
- **D2 `image cache`** rename of the bare `image` leaf — acceptable, or keep
  `image` as a leaf-with-default-subcommand?
- **D3 `net`** — group `{network verbs}` or keep `network` top-level (and
  drop the `net` group)?
- **D4 `store`** vs folding `cache`/`pool`/`storage` elsewhere.
- **D5 run-family** — Task 7 reads `up`/`run`/`exec`/`sandbox`/`invoke` and
  proposes the collapse; not pre-decided here.

## Full per-command disposition

| current | → | new path |
|---|---|---|
| up, run, exec, invoke, ls, console, down, logs, build, dev, doctor, init | | (top-level, unchanged) |
| set-ttl | → | vm ttl |
| pause, resume, snapshot, wait, boot-report, diff, cp, fs, proc, session, volume, sandbox, forward | → | vm \<same\> |
| image | → | image cache |
| catalog, manifest, artifact, kernel | → | image \<same\> |
| compile, validate | → | pkg \<same\> |
| sign, bundle, attest, receipt, audit, deps | → | trust \<same\> |
| storage, cache, pool | → | store \<same\> |
| network | → | net (verbs lift) |
| metrics, bench, config, mcp | → | ops \<same\> |
| secret | | secret (unchanged) |
| bootstrap, cleanup, uninstall, update | → | **TBD Task 6** — env-lifecycle home (under `dev`? top-level? a `self` group?) |
| shell-init, reconcile, persistent-builder | → | hidden |
| __qemu-vsock-bridge | | already hidden |
