# Content-addressed store for mvm-cli's nested build artifacts

Key both legs of `crates/mvm-cli/build.rs` on content instead of on profile,
so reuse proves freshness rather than assuming it — and can therefore be
shared across worktrees, profiles and target triples.

**Measured**, fresh worktree, aarch64 macOS, `jobs = 6`:

| Workload | Before | After |
| --- | --- | --- |
| Cold build | 359s | **45.5s** |
| ↳ `mvm-cli` build script within it | 332.7s (93%) | **0.4s** |
| Edit `mvm-cli/src` | re-ran both nested legs | **7.7s**, script not re-run |
| Edit `mvm-core`, warm | ~18s (script 14.3s) | 15.5s |
| Workspace `clippy --all-targets` | spawned 4–6 nested `cargo build`s | 6.0s warm |
| `--release`, empty nested target dir — script only | ≥163s musl leg, always | **0.6s** |

What is left under `--release` is 136.7s of `mvmctl` itself — the
`lto = true` / `codegen-units = 1` link. That cost was always there; the build
script was hiding it.

The old rule — `PROFILE == "debug"` **and** the file exists — could prove
nothing about the bytes, so `--release`, `release-witness` and every
`--target` paid the full ~163s musl cross-compile into their own nested target
dir, and the per-VM helper leg had no reuse at all so it ran on every
`cargo check` and `clippy`.

The key covers each binary's real dependency closure (walked from the manifest
graph, not a hand list), `Cargo.lock`, `rust-toolchain.toml`, the pinned
toolchain, target and features. Deriving the closure also narrowed the watch
set: `mvm-cli`'s 251 files are downstream of these binaries and no longer
re-run either leg.

**The dev trade is kept on purpose.** A key miss means the sources really
changed, and rebuilding costs ~163s, so the dev profile still reuses a stale
embedded binary rather than regress the inner loop. The difference is that the
key now knows it is stale and says so via `cargo:warning=`, the one channel
cargo surfaces without `-vv`. The `MVM_EMBEDDED_BINS_REUSED` env var it used
to set for this has never had a reader. `MVM_EMBED_NO_CACHE=1` opts out of
both the store and the fallback.

A store hit also seeds the nested target dir the fallback reads from —
without it, a worktree whose binaries all came from the store had nothing to
fall back to and its first source edit paid a full cross-compile, moving the
cost instead of removing it.

Residual, documented: in a store-seeded fresh worktree the first `mvm-core`
edit is ~52s, because the aux-helper leg has no stale fallback by design
(#2058) and its nested target dir is cold there.

Also: `scripts/dev-env.sh` exported `MVM_HOME`, `CARGO_TARGET_DIR` and
`CARGO_HOME` with `${VAR:-default}`, so a value inherited from another
worktree won and two source trees shared one target dir — cargo fingerprints
embed absolute paths, so alternating recompiled the workspace and concurrent
builds serialized on one lock, silently. `AGENTS.md` already documented the
intended behaviour; it now implements it, warns when it reclaims, and honours
`MVM_DEV_ENV_KEEP_INHERITED=1`.

Supersedes the freshness half of
`specs/plans/2026-08-15-aux-helper-binary-freshness.md`. Does not re-litigate
`specs/plans/334-build-critical-path.md`, whose five refuted hypotheses stand;
its baseline was a warm `cargo build -p mvm-cli`, and the cold and per-profile
costs addressed here were outside it.

Full log and the open Phase 3–5 items in
`specs/plans/2026-08-17-embedded-binary-content-store.md`.
