# Plan 144 — CLI command directory normalization

Status: proposed (sequenced for later in the rearchitecture; no code lands yet)

## Goal

Every command lives in its own subdirectory so the layout is uniform
and easy to reason about: one directory per command group, one file per
subaction. No flat multi-subaction files. **Layout only — no change to
the CLI surface, no change to how dispatch is wired.**

## Current state (verified 2026-06-03)

Most of `commands/` is already directory-split. Only two files break the
pattern by packing multiple subactions into one flat file:

```
commands/
  mod.rs        323  Cli struct + Commands enum + dispatch + run()  (untouched)
  tests.rs     2711  CLI integration tests                          (untouched)
  image.rs     1795  FLAT  — Pull/Ls/Inspect/Rm in one file    ← split
  catalog.rs    143  FLAT  — List/Search/Info in one file       ← split
  cmd_audit.rs  270  audit-envelope wrapper                          (untouched)
  shared/       852  11 helper modules                          (already a dir)
  vm/        17 847  33 files, per-command split                (already a dir)
  env/        7 748  per-command split + helper modules         (already a dir)
  ops/        5 472  per-command split                          (already a dir)
  build/      2 017  per-command split                          (already a dir)
  manifest/     909  mod.rs + ls/info/rm/prune/verify/tag/…      (already a dir)
  bundle/       752  mod.rs + export/fetch/install/gc            (already a dir)
  deps/        1824  mod.rs + inspect/audit                      (already a dir)
  trust/        252  mod.rs + add/list/remove                    (already a dir)
  storage/      240  mod.rs + info/gc                            (already a dir)
```

So the actual work is small and mechanical: convert `image.rs` and
`catalog.rs` into directories that match the `manifest/` shape (the
existing template for a verb that owns internal subcommands).

## What changes

### W1 — `image.rs` → `image/` (the big one, 1795 lines)

`image.rs` already declares an `Args` struct, a `#[command(subcommand)]`
enum, and a `run()` that matches on it. Split the subaction bodies into
sibling files; `mod.rs` keeps the enum + `run()` dispatch.

```
image/
  mod.rs       Args + subcommand enum + run() dispatch  (unchanged logic)
  pull.rs      Pull body
  ls.rs        Ls body
  inspect.rs   Inspect body
  rm.rs        Rm body
```

Move-only: each `run()` arm's body becomes `pull::run(...)` etc.; the
match in `mod.rs` calls them. No behaviour change.

### W2 — `catalog.rs` → `catalog/`

Same split, mirrors `manifest/`:

```
catalog/
  mod.rs       Args + subcommand enum + run() dispatch
  list.rs      List body
  search.rs    Search body
  info.rs      Info body
```

That's the whole refactor. Everything else already satisfies
"one directory per group."

## Explicitly untouched

- `commands/mod.rs` — the top-level `Commands` enum and dispatch `match`
  stay exactly as they are. (Distributing that dispatch into the groups
  is a *separate* architectural change, deliberately not in scope here.)
- `vm/`, `env/`, `ops/`, `build/`, `manifest/`, `bundle/`, `deps/`,
  `trust/`, `storage/`, `shared/` — already directories, left alone.
- Helper modules (`env/apple_container.rs`, `vm/policy_resolver.rs`,
  etc.) stay where they are.
- The CLI surface: `mvmctl image pull`, `mvmctl catalog list`, etc. are
  byte-identical before and after.

## Verification

- [ ] `cargo build -p mvm-cli`
- [ ] `cargo test -p mvm-cli` (esp. `commands::tests` help/arg snapshots
  — a snapshot diff means the surface moved; it must not)
- [ ] `cargo run -- image --help` and `cargo run -- catalog --help`
  byte-identical to pre-refactor
- [ ] `just lint` (fmt --all + clippy -D warnings)

## Success criteria

- [ ] No multi-subaction flat file remains under `commands/`; `image/`
  and `catalog/` are directories with one file per subaction.
- [ ] Every command group is a directory following the `manifest/`
  shape (`mod.rs` dispatch + one file per subaction).
- [ ] CLI surface and all `--help` output unchanged.

## Out of scope

- Distributing the top-level dispatch out of `commands/mod.rs` into
  per-group enums (would shrink mod.rs but is an architecture change,
  not a layout one — separate plan if ever wanted).
- Nested verb namespaces (`mvmctl vm up`).
- Splitting `tests.rs`.
