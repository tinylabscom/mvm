# Content-addressed store for mvm-cli's nested build artifacts

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

- [ ] **The store is unbounded and nothing sweeps it.** Every distinct content
      key keeps its artifacts forever: 48 entries / 424 MB after a single
      day's work on one branch, and each key holds a multi-MB static binary.
      `cargo clean`, `just clean-dev-state` and `mvmctl cache prune` all miss
      it because it deliberately lives outside both `target/` and `MVM_HOME`.
      Needs an LRU bound or a prune verb before this ships widely — the
      failure mode is a slowly filling disk with no command that reports it,
      which is the same shape as the 282 GB of unswept `.mvm-test` roots that
      `just clean-dev-state` was added for.

- [ ] **Phase 3** — delete the ~120 lines of phantom `#[cfg(test)]` tests in
      `build.rs` (cargo never builds a build script as a test target, and they
      call `configured_embed_tools_from`, which is not in scope).
- [ ] **Phase 3** — `MVM_LIBKRUN_HEADER` is read at `build.rs` to decide
      whether the 6th helper builds, but has no `rerun-if-env-changed` there
      (only in `libkrun-sys/build.rs`), so changing it does not re-select the
      helper set.
- [ ] **Phase 4a** — dead edges: `mvm-runtime → libkrun-sys` has zero use
      sites; `mvm-cli → mvm-net` is used only from `#[cfg(test)]`;
      `mvm-hostd → mvm-fs` is used from one bin, not the lib.
- [ ] **Phase 4b** — `mvm-build` pulls all of `mvm-sdk` (13k LOC, 5
      tree-sitter grammars, ~24 MB of generated C at `opt-level = 3`) for one
      item used 8 times, `compile::deps_audit` (691 lines). `mvm-hostd` uses
      that plus `mvm_sdk::ir`, which is a pure re-export of `mvm_contract::ir`
      it already depends on. Moving `deps_audit` to a leaf and gating the
      grammars behind an `analyze` feature takes them off the serial path —
      and out of the aux-helper leg's nested rebuild, where they are currently
      compiled a second time.
- [ ] **Phase 4c** (gate on cold evidence) — `mvm-cli → mvm-hostd` (173 sites)
      and `mvm-client → mvm-hostd` (29) are the same narrow cluster:
      `audit::*`, `supervisor::{tools,verify_audit_chain}`, `plan_admission`,
      `keyholder`. Extracting ~7k LOC frees both from 49k LOC of `mvm-hostd`.
- [ ] **Phase 5** — re-measure sccache. `basedirs` is correctly set and the
      cache is 12 GiB of a 60 GiB ceiling, so it is neither misconfigured nor
      evicting, yet the live Rust hit rate is 4.20% (257 hits / 5,861 misses)
      against the ~84% its own config documents as measured. Find the gap
      before changing anything.
- [ ] **Phase 5** — worktree hygiene: 36 worktrees, 87 GB. Plan 334 named this
      the largest remaining lever and left it out of scope.

`scripts/dev-env.sh` (Phase 5, done) exported `MVM_HOME`, `CARGO_TARGET_DIR`
and `CARGO_HOME` with `${VAR:-default}`, so a value inherited from another
worktree won. Two source trees then shared one target dir; cargo fingerprints
embed absolute paths, so alternating between them recompiled the workspace and
concurrent builds serialized on one lock, silently. `AGENTS.md` already
documented the intended behaviour. It is now authoritative, warns when it
reclaims, and `MVM_DEV_ENV_KEEP_INHERITED=1` opts out.
