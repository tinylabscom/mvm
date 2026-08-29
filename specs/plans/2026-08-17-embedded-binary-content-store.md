# Content-addressed store for mvm-cli's nested build artifacts

Backing: historical
Validation: none

**Status: Phase 1–2 COMPLETE (2026-08-17). Phases 3–5 open.**

## Why

`cargo build` sits on two progress lines — `mvm-cli(build)` and `mvmctl(bin)` —
and the reason is one build script. `crates/mvm-cli/build.rs` runs two nested
builds, and neither could tell a fresh artifact from a stale one:

| Leg | Work | Reuse before this plan |
| --- | --- | --- |
| musl cross-compile of 6 embedded host binaries (`cargo zigbuild`) | ~163s | `PROFILE == "debug"` **and** `prebuilt.is_file()` |
| native per-VM helpers, 4–6 nested `cargo build`s of the `mvm-hostd` closure | ~13s warm, far more cold | none |

`PROFILE == "debug"` plus "the file exists" proves nothing about the bytes, so
it had to refuse every other profile: `--release`, `release-witness` and each
`--target` paid the full cross-compile into their own nested target dir. The
helper leg ran on every `cargo check` and `clippy` too, because cargo runs
build scripts for those.

Nothing was shared across worktrees, profiles or target triples —
`shared_nested_target_dir` shares only across feature fingerprints inside one
`target/<profile>/`. With ~36 worktrees on a dev host, that cost was paid over
and over.

## Measurements

Fresh worktree, aarch64 macOS, `[build] jobs = 6`, `cargo build --timings`.

### Before

| Workload | Total | `mvm-cli` build script | Share |
| --- | --- | --- | --- |
| Cold, fresh worktree | 359s | **332.7s** | **93%** |
| Warm, after a one-line `mvm-core` edit | ~18s | **14.3s** | **79%** |
| Warm no-op | 5.1s | not re-run | — |

The script starts at t=16.4s and runs to t=349s; every other crate finishes
underneath it. `mvm-cli` the crate is 9.1s and cannot start until the script
ends. That is why those two progress lines are what you watch.

### After

| Workload | Before | After |
| --- | --- | --- |
| Cold build, fresh worktree | 359s | **45.5s** |
| ↳ `mvm-cli` build script within it | 332.7s | **0.4s** |
| Cold build, second fresh worktree | 359s | 60.2s |
| Edit `mvm-cli/src` (the most-edited crate) | re-ran both legs | **7.7s**, script not re-run |
| Edit `mvm-core`, warm worktree | ~18s | 15.5s |
| Full-workspace `clippy --all-targets` (pre-commit hook) | spawned 4–6 nested builds | 6.0s warm |
| `--release`, empty nested target dir — build script only | ≥163s musl leg, always | **0.6s** |

Under `--release` the store hit leaves 136.7s of `mvmctl` itself: that is the
`lto = true` + `codegen-units = 1` link of the final binary, a deliberate
release-profile choice and now the honest remaining cost. It was previously
hidden behind the build script rather than absent.

The first `--release` build on a host still pays for the per-VM helpers, which
are keyed per profile (a release helper is not a debug helper) and so have
nothing to hit until one release build has published them.

## What changed

Key both legs on content: the binary's real dependency closure taken from the
manifest graph, plus `Cargo.lock`, `rust-toolchain.toml`, the pinned zig /
cargo-zigbuild identity, the target triple, features, and a flavour that
separates a musl static from a native host build of the same package.

- `crates/mvm-cli/build_embed_cache.rs` — new build-script module: closure
  walk, manifest parsing, tree hashing, key derivation, store I/O.
- Store at `~/.cache/mvm/embed/<key>/<binary>`, outside `target/`, so it is
  shared across worktrees, profiles and triples. Atomic publish (temp +
  rename), because concurrent worktree builds race it.
- `MVM_EMBED_NO_CACHE=1` opts out of both the store and the dev fallback.
- The watch set is now derived from the same closure. `mvm-cli`'s own 251
  files are downstream of these binaries and cannot affect them, so they no
  longer re-run either leg; the blanket walk over every workspace crate is
  gone.

### The dev trade is preserved deliberately

A key miss means the closure genuinely changed, and rebuilding the musl set
costs ~163s. Making that correct-but-slow on every edit would have regressed
the inner loop the plan set out to fix, so the dev profile keeps reusing a
stale embedded binary exactly as it did before. What changed is that the key
now *knows* it is stale, so it says so through `cargo:warning=` — the one
channel cargo surfaces without `-vv`. `--release` and `release-witness` always
rebuild on a miss.

A store hit also seeds the nested target dir the fallback reads from.
Without that, a worktree whose binaries all came from the store had nothing to
fall back to, and the *first* source edit there paid a full cross-compile —
moving the cost rather than removing it.

### Known residual

In a store-seeded fresh worktree the first `mvm-core` edit costs ~52s rather
than ~15s: the aux-helper leg has no stale fallback by design (a stale
supervisor silently produces a guest that ignores your edit — #2058), so a key
miss must rebuild, and its nested target dir is cold in a worktree that never
populated it. Steady state after that is unchanged.

## Relationship to other plans

- Supersedes the *freshness* half of
  `specs/plans/2026-08-15-aux-helper-binary-freshness.md`. That plan proposed
  adding watch coverage (`crates/mvm-vmm/src` is watched by nothing;
  `mvm-hostd`/`mvm-core` use unreliable directory-level `rerun-if-changed`).
  A content key subsumes that: it cannot match unless the bytes are the ones
  this tree produces. Its other two items — the two divergent
  `mvm-network-endpoint` resolvers, and `pack_stage0_work_disk` writing a
  multi-GB non-sparse file — are independent and still stand.
- Does **not** re-litigate `specs/plans/334-build-critical-path.md`. Its five
  refuted hypotheses stand: dependency count, crate splitting for the serial
  chain (measured at 1%), the tree-sitter `opt-level` override, feature
  ping-pong, and cross-invocation thrash. 334's baseline was a *warm*
  `cargo build -p mvm-cli`; the cold and per-profile costs this plan addresses
  were outside what it measured.
- `f29d9ce24` (#1561) added a stub embed mode and `884ff8555` (#1683) removed
  it. This is not that: nothing is stubbed, and every embedded binary is real
  bytes with a real hash.

## Open work

- [x] **Bound the store.** Was unbounded — 48 entries / 424 MB after a single
      day on one branch, and `cargo clean`, `just clean-dev-state` and
      `mvmctl cache prune` all miss it because it deliberately lives outside
      both `target/` and `MVM_HOME`. Now LRU-evicted to a 4 GiB ceiling
      (`MVM_EMBED_CACHE_MAX_BYTES` overrides) after each build. Eviction keys
      on mtime rather than atime, since `noatime` mounts would make every
      entry look equally stale, and a restore touches its entry so the one a
      dozen worktrees keep reusing is not the one deleted.
- [ ] **Phase 3** — delete the ~120 lines of phantom `#[cfg(test)]` tests in
      `build.rs` (cargo never builds a build script as a test target, and they
      call `configured_embed_tools_from`, which is not in scope).
- [x] **Phase 3** — `MVM_LIBKRUN_HEADER` was read at `build.rs` to decide
      whether the 6th helper builds, but had no `rerun-if-env-changed` there
      (only in `libkrun-sys/build.rs`), so changing it did not re-select the
      helper set. Closed 2026-08-28 by deleting the probe along with the whole
      aux-helper leg —
      `specs/plans/2026-08-28-build-script-drops-the-aux-helper-leg.md`. The
      `libkrun.h` check now lives in `just build-supervisors`, where a host
      probe belongs and where no fingerprint depends on it.
- [ ] **Phase 4a** — dead edges: `mvm-runtime → libkrun-sys` has zero use
      sites; `mvm-cli → mvm-net` is used only from `#[cfg(test)]`;
      `mvm-hostd → mvm-fs` is used from one bin, not the lib.
- [~] **Phase 4b — measured and DECLINED.** The shape is real: `mvm-build`
      pulls all of `mvm-sdk` (13k LOC, 5 tree-sitter grammars, ~24 MB of
      generated C at `opt-level = 3`) to use one item 8 times,
      `compile::deps_audit` (691 lines); `mvm-hostd` uses that plus
      `mvm_sdk::ir`, which is a pure re-export of `mvm_contract::ir` it already
      depends on. The payoff is not.

      From the cold timing data, `mvm-sdk` sits on the critical path between
      `mvm-agentd` (ends 25.5s) and `mvm-build` (starts 28.3s) and contributes
      **~2.8s of a 45.5s post-store cold build (~6%)**. It does not reduce the
      closure: the grammars stay via `mvm-cli`, which genuinely parses
      decorators. Its larger prize — skipping the grammars in the nested
      aux-helper build, where `mvm-hostd`'s closure is compiled a second time —
      was already taken by the Phase 1–2 content store, which turns that build
      into a cache hit.

      Against ~6%: relocating `verify_sealed_volume`, the claim-11 sealed-volume
      verifier, and a closure-budget bump (linux sits at 239 of 239). Declined
      on the same basis Plan 334 declined crate splitting, and under this
      plan's own pre-committed rule to stop below ~10%. Re-open only with a new
      argument, not a re-reading of these numbers.

- [ ] **Phase 4c** (gate on cold evidence) — `mvm-cli → mvm-hostd` (173 sites)
      and `mvm-client → mvm-hostd` (29) are the same narrow cluster:
      `audit::*`, `supervisor::{tools,verify_audit_chain}`, `plan_admission`,
      `keyholder`. Extracting ~7k LOC frees both from 49k LOC of `mvm-hostd`.
- [x] **Phase 5 — sccache measured; the documented cross-worktree win does not
      exist.** `basedirs` is correctly set and the cache is well under its
      ceiling, yet the machine-wide Rust hit rate is ~2.5% across ~35k
      compiles. Controlled experiment, one crate, same source and `CARGO_HOME`,
      varying only the target directory:

      | Run | Result |
      | --- | --- |
      | cold, target dir A | 2 hits / 100 misses |
      | target dir A wiped, rebuilt | **70 hits / 79 misses** |
      | identical source, target dir B | **0 hits / 152 misses** |

      The target directory's full path is part of the key, and every worktree
      has its own, so cross-worktree dedup cannot happen — `basedirs` is
      necessary but not sufficient, and the config's "same target-directory
      *name*" condition understates it. What sccache actually buys here is
      re-populating one checkout after `cargo clean`; within a live target dir
      cargo already caches deps. The Justfile comment claiming cross-worktree
      hits has been corrected. Whether to keep the wrapper at all is now a
      decision with numbers behind it rather than an assumption.
- [~] **Phase 5 — worktree hygiene, partly done.** 49 worktrees / 261 GB at the
      time of measurement. `just worktrees-prune APPLY=1` reclaimed 5 clean
      checkouts. Five more sit on branches already merged into main — including
      one at 48 GB — but every one of them carries uncommitted source edits,
      and two are open in an editor (`lsof` shows `zed` holding 43 and 5 files).
      A merged branch does not mean a disposable working tree. Left alone
      deliberately; reclaiming that ~50 GB needs their owner, not a sweeper.

`scripts/dev-env.sh` (Phase 5, done) exported `MVM_HOME`, `CARGO_TARGET_DIR`
and `CARGO_HOME` with `${VAR:-default}`, so a value inherited from another
worktree won. Two source trees then shared one target dir; cargo fingerprints
embed absolute paths, so alternating between them recompiled the workspace and
concurrent builds serialized on one lock, silently. `AGENTS.md` already
documented the intended behaviour. It is now authoritative, warns when it
reclaims, and `MVM_DEV_ENV_KEEP_INHERITED=1` opts out.
