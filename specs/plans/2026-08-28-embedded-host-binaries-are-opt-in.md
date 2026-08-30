# Take `mvm-cli`'s build script off the inner loop entirely

Backing: shipped-source
Validation: the_default_build_embeds_nothing

**Status:** DELIVERED
**Date:** 2026-08-28
**Owner:** mvm

## Summary

`specs/plans/2026-08-28-build-script-drops-the-aux-helper-leg.md` deleted the
build script's second leg and took a key miss from 60.37s to 0.13s. It did not
stop the script *running*: the musl cross-compile leg was still unconditional,
so cargo re-executed `mvm-cli(build)` on every edit that touched any of the 648
files it watched.

This makes that leg opt-in, behind the `embed-host-bins` feature. With the
feature off the script writes an empty `EMBEDDED` table, watches four files, and
returns — so cargo runs it once per fingerprint and never again on the inner
loop. `just embed` and the tag-push release workflow turn it on.

The argument is not wall time; at 0.13s there was little left to win. It is that
a dev build should not carry hidden work, and that the one place a shipped
artifact gets its payload should be a named, reviewable line in the release
workflow rather than a side effect of every `cargo build`.

## The trap this had to avoid

Emitting no `rerun-if-*` line at all does not mean "never re-run". It restores
cargo's *default*, which re-runs the build script whenever any file in the
package changes — all 251 of `mvm-cli`'s. That is worse than the status quo, and
it is silent. The unembedded arm therefore emits four explicit watches
(`build.rs`, `build_support.rs`, `build_embed_cache.rs`,
`src/host_binaries/manifest.rs`), which are the only inputs that can change what
it writes.

Verified: with the feature off, `touch crates/mvm-core/src/lib.rs` followed by
`cargo build -p mvmctl --bin mvmctl -vv` shows zero `build-script-build`
executions.

## What an unembedded binary does

Every host-side verb works. What it cannot do is bootstrap a builder VM, so
`host_binaries::extract::ensure_extracted` refuses up front:

> this mvmctl was built without the embedded Linux host binaries, so it cannot
> bootstrap a builder VM. Rebuild with `just embed` …

It refuses *before* creating the cache directory. An empty extract would
otherwise surface later as a missing file and read as a corrupted cache rather
than as a build that was never asked to embed anything.

## Keeping both configurations honest

Gating `embedded_binaries.rs` and `host_binaries_extract.rs` on the feature
would leave the default configuration — the one nearly every `cargo test` uses —
asserting nothing whatsoever about the embedded set. So the gating is paired:

- `tests/unembedded_host_binaries.rs` (`#![cfg(not(feature = ...))]`) asserts the
  table is empty, that both extraction entry points refuse, that the message
  names the fix, and that no cache directory is left behind.
- `tests/embedded_binaries.rs` + `tests/host_binaries_extract.rs`
  (`#![cfg(feature = ...)]`) keep the payload assertions.
- In `host_binaries_manifest.rs` only the one payload test is gated; the three
  manifest-constant tests hold in both.

`dispatch_host_bin_dir.rs` joins the gated set for the same reason — it calls
`ensure_extracted` and asserts the dir is populated, which is exactly the
behaviour the unembedded build refuses.

A second test had to change for a subtler reason.
`signature_verifying_build_avoids_the_fast_codegen_link_path` asserted that
`e2e-documented-surface.sh` never passes `--features` to `cargo-fast.sh`, as a
proxy for "the aws-lc build does not use the fast-codegen wrapper". The proxy
held only while the featureless arm passed no features at all, so adding
`embed-host-bins` to both arms broke it without breaking anything real —
`embed-host-bins` pulls no aws-lc. The assertion now names `$E2E_FEATURES`
directly, which is what it was always trying to say.

The feature-on lane runs in `lint-features` in `ci.yml`, which already installs
the pinned zig. Without it the entire cross-compile leg would be exercised for
the first time by a tag-push release — the same invisible-until-release gap that
`check-mvm-host-binaries-sync` exists to close for the flake mirror.

## What changed

- [x] `embed-host-bins` feature on `mvm-cli` and on the root `mvmctl` package,
      default off.
- [x] Added to `BUILD_ONLY` in `xtask/src/check_two_surfaces.rs`. It gates
      acquisition, not behaviour — both settings expose the same verbs — so it
      belongs beside `release-artifact-bootstrap`, not inside `host` or `user`.
- [x] `build.rs` split into `embedding_requested`, `emit_pinned_toolchain_env`,
      `write_unembedded_table` and `embed_host_binaries`. The pinned-toolchain
      env vars are emitted under both arms, because `doctor` reports what the
      embed toolchain *would* be even when this build did not use it.
- [x] `ensure_extracted` refuses on an empty table before any filesystem work.
- [x] `just embed` recipe; `MVMCTL_RELEASE_FEATURES` in `release.yml` gains the
      feature; `lint-features` gains a feature-on lane.
- [x] The five scripts that boot VMs build with the feature
      (`e2e-documented-surface.sh` — both arms — `e2e-launch-modes.sh`,
      `check-hvf-oci-allow-host-smoke.sh`, `check-hvf-warm-restore.sh`,
      `local-aarch64-no-kvm-smoke.sh`). `test-app-deps-ci-gate.sh` deliberately
      does not: it boots nothing.
- [x] CLAUDE.md and the contributor development guide say the toolchain is
      needed at `just embed` time rather than at `cargo build` time.

## The zig toolchain follows the feature

`ci.yml` installed the pinned zig in nine jobs, because every `mvm-cli` build
used to cross-compile. Only `lint-features` still does. Each of the other eight
was traced to what it actually runs before its step was removed:

| job | why it no longer needs zig |
|---|---|
| `lint-core`, `lint-policy` | workspace check/test, no `embed-host-bins` |
| `test-workspace`, `test-workspace-aarch64` | same |
| `test-release-witness` | builds `mvm-fs`/`core`/`contract`/`hostd`/`agentd` — never `mvm-cli` |
| `test-linux` | `just bdd`, whose builder-VM scenarios are `@live`-gated and skipped |
| `boot-latency`, `guest-image-boot` | `cargo test --test runtime_boot_bench`, which "deliberately excludes the builder VM and Nix image build path" |

Tracing rather than pattern-matching found a defect in this change:
`just bdd-live-ci` sets `MVM_BDD_LIVE=1`, which admits the `@live` scenarios
that *do* boot real microVMs, and it built `--features user` — no payload. It
now builds `user,embed-host-bins`, and `bdd.yml`'s live job keeps its zig step
while its hermetic job drops one it never needed.

## Deliberately not done
- **`MVM_EMBED_CACHE_MAX_BYTES` and `MVM_EMBED_CACHE_DIR` have no
  `rerun-if-env-changed`.** Changing the store's ceiling or its location does
  not re-run the build script, so neither takes effect until something else
  invalidates it. Small and real; left out of this change because it is about
  the store rather than about whether the leg runs.

  This is the *only* store finding that survived checking. The claim that
  `prune` was not holding its ceiling — carried in an earlier revision of the
  aux-leg plan and in that PR's description — was wrong; see that plan's
  "Deliberately not done" for how. Separately, the rationale recorded in this
  host's `~/.cargo/config.toml` for raising the ceiling to 64 GiB is a cache
  miss costing "~17.8s of nested `cargo build` on the aux-helper leg". That leg
  no longer exists, so the insurance the raise was buying is obsolete — a host
  config decision, not a repo one.
