# Build dependency decisions

Backing: preview
Validation: none — this records decisions taken on measurements; it is not a claim of enforcement.

Several issues asked for a smaller or faster release build. Each was measured and
declined; the reasons are recorded so they are not re-derived.

## Decisions

| Issue | Decision | Evidence | What would reopen it |
|---|---|---|---|
| [#4538](https://github.com/tinylabscom/mvm/issues/4538), [#4543](https://github.com/tinylabscom/mvm/issues/4543) — narrow or remove `gix` | Keep `gix` as the vendored umbrella crate | The `mvmctl` closure is 545 crates (`cargo tree -p mvmctl -e normal,build --prefix none \| sort -u \| wc -l`), 81 of them `gix-*`. `image_source/git_rules.rs` uses repository open with isolated options, commit/tree/blob lookup, config snapshots, the index and its entry flags, the worktree attribute and ignore stack, glob case handling and object ids. Keeping every sub-crate that needs removes about 12 of 545 crates, roughly 2%: diff, filter, protocol, transport, url, refspec, pathspec, revision, shallow, submodule, packetline, macros and `encoding_rs`. | A replacement for the identity code that does not need a repository implementation, or a measured build-time budget that 12 crates would meet. |
| [#4541](https://github.com/tinylabscom/mvm/issues/4541) — build every shipped binary under one profile | Keep `mvmctl` on `release-min` and the daemons and SDK library on `--release` | `mvm-hostd`, the GPU shim core and `mvm-hostlib` rely on `catch_unwind`, which needs panic=unwind. Under `release-min` (panic=abort) a panic inside the SDK library kills the host Python or Node process. Moving `mvmctl` to `--release` loses the size profile (opt-level z, fat LTO, abort) that its size budget and `tests/release_assets.rs` pin. Panic strategy is profile-wide, so the shared dependencies compile twice. | A decision that the daemons and SDK library may abort on panic, with tests for the new crash behaviour. |
| [#4560](https://github.com/tinylabscom/mvm/issues/4560) — narrow features in the `mvm-builder-guest` closure | Leave the features as they are | The musl guest closure (`cargo tree -p mvm-builder-guest --target aarch64-unknown-linux-musl -e normal,build --prefix none`, repeat-marker `(*)` stripped before `sort -u`) is 134 unique crates; the 144 in the issue counts the same crate twice when one line carries `(*)`. The only multi-crate saving is `url`: removing it from `mvm-core` takes the closure to 106 (28 crates: `idna`, the `icu_*` family, `zerovec`, `yoke`, `form_urlencoded`, `percent-encoding`, and their proc-macros). `url` 2.5.8 has no feature that drops `idna`, and `mvm-core` uses it in `registry_pack/application.rs` to validate application locators, so the saving needs either the registry-pack module gated out of the guest or a hand-written host parser. That changes locator validation for a 28-crate gain. The other candidate features are worth one crate each at most: `chrono` without `clock` would drop `iana-time-zone` (and `mvm-contract` and host crates enable `clock` anyway), and `regex` without `perf` would drop `aho-corasick` at a matching speed cost. `serde_json` is already `default-features = false`. | A decision that locator validation no longer needs a full URL parser, or a build-time budget the 28 crates would meet. |
| [#4561](https://github.com/tinylabscom/mvm/issues/4561) — unify the workspace on one `rand` | Nothing to unify in this tree; the remaining duplicate is third-party | Every workspace crate, `mvm-agentd` and `hickory-proto` included, is already on `rand` 0.10.2 / `rand_core` 0.10.1; the issue's premise of a 0.8 pin is out of date. `cargo tree -d -i rand` shows one other copy, `rand` 0.9.4 with `rand_core` 0.9.5, reached only through `sigstore-tsa` 0.11.0 (`sigstore-verify`, behind `manifest-verify`). Collapsing it means forking or downgrading a signature-verification dependency, which is not done. `deny.toml` already lists `rand` and `rand_core` in the audited skip baseline with that reason. | `sigstore-verify` releasing on the `rand` 0.10 generation. |

## Limits

- The 12-crate figure comes from the package metadata closure, not a
  feature-resolved build.
- The #4560 figures are for the musl target; the host-target closure is 149 unique crates.
- No wall-clock measurement of the double compile was taken.
