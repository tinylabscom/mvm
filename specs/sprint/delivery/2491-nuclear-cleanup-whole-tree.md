# 2491 — `cleanup --nuclear` wipes the whole mvm root

`mvmctl env cleanup --nuclear` was an allow-list of thirteen paths. It therefore
spared every state directory added after that list was written, while its help
text and its `DELETE-EVERYTHING` prompt both said it deleted everything. On the
host this was found on, 18 of 31 entries under `~/.mvm` survived it, including
`checkpoints` (7.3 GB) and `snapshots` (5.0 GB) — roughly 12 GB reachable by no
cleanup tier at all.

The failure mode was structural rather than a missing name: an allow-list of
"everything" is wrong the moment the next subsystem lands, and nothing forced
whoever added `images/` or `machines/` to notice this file. The only verb that
actually cleared the tree was `env uninstall --all`, which also removes
`/var/lib/mvm` and the `mvmctl` binary and needs `sudo` — so there was no way to
reclaim the tree and keep the install.

## Delivered

- `crates/mvm-cli/src/commands/env/cleanup.rs`:
  - `build_plan_at` split into `selective_plan` (`--cache` / `--state`) and
    `nuclear_plan` (`--nuclear`). The split is the point: the selective tiers
    stay enumerated because a directory they do not name is one they are
    supposed to leave alone, while nuclear is defined by subtraction — walk
    `mvm_home()`, take every entry. The root directory itself survives so its
    0700 mode cannot be re-established wrong by a later `ensure_home_dir()`.
  - `Identity` enum (`Wipe` / `Keep`) and `IDENTITY_PATHS`, behind the new
    `--keep-identity` flag (clap `requires = "nuclear"`, so it cannot be passed
    where it would silently do nothing). Spares `keys`, `audit`, `attestation`,
    `secrets`, `secret-bindings`, `egress-ca`, `.secret-store.key`,
    `snapshot.key`, `config.toml` — private keys, the material encrypted under
    them, the chain those keys sign, and the hand-written config. They travel as
    one set because sparing any alone is useless: without `keys` the audit chain
    is unverifiable, without `.secret-store.key` `secrets` is an undecryptable
    blob.
  - `confirm_tier` takes the `Identity` so its warning states which of the two
    things the caller asked for. The interactive `DELETE-EVERYTHING` gate is
    still required either way — `--keep-identity` still destroys templates,
    images, machines, checkpoints and snapshots irreversibly.
  - `first_running_vm` now delegates to
    `mvm_vmm::host::process_liveness::state_dir_has_live_process` via a new
    `first_running_vm_at(&Path)` seam.
- `public/src/content/docs/reference/cli-commands.md`: rows for `--state`,
  `--nuclear`, `--nuclear --keep-identity`, `--dry-run` and `--force`, none of
  which had ever been documented, plus a note on when to reach for this rather
  than `uninstall --all`.

## Guard fix carried in the same change

The running-VM refusal that makes any tier sweep safe read only `libkrun.pid`.
The shared probe in `mvm-vmm` knows five markers — `libkrun.pid`, `hvf.pid`,
`fc.pid`, `qemu.pid`, `pid` — and its own comment states it is meant to be the
single list every liveness probe reads. A running HVF, Firecracker or QEMU guest
therefore read as stopped, and HVF is the auto-detect default on macOS 26+ Apple
Silicon.

This was latent while `--nuclear` could not touch `machines/`, `checkpoints/` or
`snapshots/`. Widening nuclear is what makes it reachable, so it is fixed here
rather than tracked separately. The shared probe also stops counting a macOS
zombie as alive, which the local `kill(pid, 0)` did.

## Tests

16 in `commands::env::cleanup::tests`, up from 11.

- `tier_nuclear_covers_a_directory_no_list_knows_about` — the load-bearing one.
  It is the assertion the allow-list version cannot pass at any length, because
  its failure mode was always the next unlisted name.
- `tier_nuclear_takes_every_entry_under_the_root` — diffs the plan against a
  live `read_dir` of the root rather than against a second hardcoded list.
- `tier_nuclear_keep_identity_spares_exactly_the_identity_paths` — asserts both
  directions: identity spared, workload state still taken.
- `tier_nuclear_empties_the_root_but_leaves_it_in_place`.
- `tier_nuclear_lists_the_in_root_cache_exactly_once`.
- `running_vm_guard_sees_a_non_libkrun_backend` across all four non-libkrun
  markers, `running_vm_guard_ignores_a_dead_pid` (a spawned-then-reaped child,
  so the PID is deterministically dead), `running_vm_guard_returns_none_on_an_empty_root`.
- `commands::tests::test_cleanup_keep_identity_requires_nuclear`, and
  `test_cleanup_defaults`'s exhaustive `Args` destructuring extended to the new
  field so a future flag cannot be added without touching the shape test.

The shared `populate` fixture now creates the directories the old list never
knew about, so every test in the module runs against a realistic root instead of
the 2025-era one.

## Explicitly not delivered

- `env uninstall --all` is unchanged. It already wipes the whole tree correctly;
  it is only bundled with binary removal. Sharing one plan-builder between the
  two was considered and deferred — it is a real de-duplication, but it drags
  the sudo/`/var/lib/mvm` path into this change for no user-visible gain.
- No top-level `mvmctl cleanup` alias. The verb stays under `env`.
- No claims-ledger or ADR change. Nothing here alters a security property; the
  guard fix restores an invariant the shared probe already documented.

## Witnesses

- `cargo nextest run -p mvm-cli` — 1761 passed.
- `cargo nextest run --workspace` — 11612 passed.
- `cargo test --workspace --doc`, `cargo +nightly fmt --all`,
  `cargo clippy --workspace --all-targets -- -D warnings` — clean.
- `xtask check-no-spec-refs-in-comments`, `check-single-home`,
  `check-test-home-isolation`, `check-file-size`, `check-cli-runtime-surface`,
  `check-deferrals`, `check-honesty` — clean.

`check-single-home` earned its keep here: a first draft handled a cache pointed
outside the mvm root, and the gate flagged `MVM_CACHE_DIR` as a deleted env var.
`mvm_cache_dir()` is unconditionally `<mvm_home>/cache` and takes no override of
its own, so that branch was dead code and was removed along with its two tests.
