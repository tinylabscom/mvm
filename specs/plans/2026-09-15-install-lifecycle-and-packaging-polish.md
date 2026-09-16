# Install lifecycle: a monitored URL, an atomic upgrade, and a way out

Backing: shipped-source
Validation: check-sprint-append

**Issues:** epic [#3277](https://github.com/tinylabscom/mvm/issues/3277); [#3268](https://github.com/tinylabscom/mvm/issues/3268), [#3269](https://github.com/tinylabscom/mvm/issues/3269), [#3270](https://github.com/tinylabscom/mvm/issues/3270), [#3271](https://github.com/tinylabscom/mvm/issues/3271), [#3272](https://github.com/tinylabscom/mvm/issues/3272), [#3273](https://github.com/tinylabscom/mvm/issues/3273), [#3274](https://github.com/tinylabscom/mvm/issues/3274), [#3331](https://github.com/tinylabscom/mvm/issues/3331)

## Outcome

Installing, upgrading and removing `mvmctl` are all first-class, tested, and
observable. The integrity posture — mandatory checksum verification and
tag-pinned keyless signature verification — is unchanged or stronger, never
traded for convenience.

We are already ahead of the field on integrity: `install.sh` verifies the
SHA-256 manifest and fails closed, then verifies the cosign bundle against an
identity regexp pinned to `release.yml@refs/tags/*`. An adjacent computer-use
sandbox project's 1421-line installer performs no checksum or signature check at
all and leans entirely on OS code-signing, with Linux getting nothing. What they
do better is everything *around* the download: a stable monitored URL, a baked
version so the happy path makes no API call, versioned install directories with
an atomic swap, a real uninstaller, and CI that runs the installer against older
releases and across distros.

## Gaps

| # | Gap | Evidence |
| --- | --- | --- |
| I1 | The documented install URL is an unpinned `raw.githubusercontent.com/.../main/install.sh` fetch, and nothing checks it is still serving | `public/src/content/docs/install/macos.md:27`, `install/linux.md:37` |
| I2 | Every install makes an unauthenticated `api.github.com` call to resolve the latest tag — rate-limited, and a hard failure behind a proxy | `install.sh:48-58` |
| I3 | Binaries are installed straight over the previous set, so a failed upgrade leaves `mvmctl` and its adjacent host binaries torn apart — worse for us than for a single-binary tool, because adjacency is a requirement | `install.sh` install step |
| I4 | No uninstaller exists anywhere | — |
| I5 | Signature verification warns and continues when `cosign` is absent, on both the install and self-update paths — this is exactly the "Claim 20 limits" carve-out | `install.sh:95-119`, `crates/mvm-cli/src/update.rs` |
| I6 | `tests/install_sh.rs` tests the current script against synthetic assets only; nothing runs the current installer against older published releases, and nothing runs the released Linux binary across distros, though we ship `-unknown-linux-gnu` and glibc drift is unmeasured | `tests/install_sh.rs` |
| I7 | The Nix package hardcodes `version = "0.18.0-rc.1"`, so it drifts from `Cargo.toml` silently | `nix/packages/mvmctl.nix:54` |
| I8 | No written boundary between what a Nix check asserts and what the Rust harness asserts, against ~4000 lines of `nix/lib` | `nix/tests/` |
| I9 | `nix/ops/README.md` still instructs contributors to install Lima and run `mvmctl dev up`; both were removed | `nix/ops/README.md` |

## WS1 — A URL worth publishing

Issue: [#3268](https://github.com/tinylabscom/mvm/issues/3268).

- [x] Serve `install.sh` from the docs site at a stable vanity path, and point
      every install page at it.
- [x] Add a scheduled workflow that curls the published URL and asserts HTTP
      200, a text content type, and a marker string, filing an issue on failure.
      The adjacent project runs this daily across ten vanity URLs; the cost is
      one cron job and it catches a silently broken front door.
- [x] Keep the raw GitHub path working, undocumented, as a fallback.
- [x] Correct the published host to the Worker-attached `runmvm.com`; the
      legacy `gomicrovm.com` redirect drops request paths. Check the production
      hostname after every site deploy, not only the generated Worker URL.

## WS2 — Resolve the version without an API call

Issue: [#3269](https://github.com/tinylabscom/mvm/issues/3269).

- [x] Bake a default version sentinel into `install.sh`, updated by a
      post-publish step in `.github/workflows/release.yml`.
- [x] Fall back to the API only on a confirmed 404 for the baked version.
- [x] Note for review: this changes nothing about claim 20. A baked version
      resolves the same signed manifest and the same verification ladder.
- [x] Extend `tests/install_sh.rs` to cover the baked path, the 404 fallback,
      and an explicit `MVM_VERSION` override.

## WS3 — Atomic upgrade and rollback

Issue: [#3270](https://github.com/tinylabscom/mvm/issues/3270).

- [x] Install into a versioned directory and swap a `current` symlink
      atomically, so `mvmctl` and its adjacent `mvm-hvf-supervisor` /
      `mvm-network-endpoint` / `assets/` are never observed half-swapped.
      Layout: `<lib>/<n>-<version>/` holds the whole release, `<lib>/current`
      names one, and every `PATH` entry is a link through `current`, so the
      rename of `current` is the entire swap. Both places hold the full set
      because `current_exe` resolves links on Linux and not on macOS.
- [x] Install every host binary the release carries, not a hand-kept list
      (#3342). Only the optional libkrun supervisor older releases bundled is
      left out.
- [x] Roll back to the previous version on any post-extract failure, including
      a codesign failure. `mvmctl bootstrap` stays outside the atomic step: it
      prepares state under `~/.mvm`, not the release, and a network failure is
      no reason to discard verified binaries.
- [x] Leave the Homebrew path alone; it owns its own cellar.
- [x] Test a mid-upgrade failure and assert the previous set still runs.

## WS4 — An uninstaller

Issue: [#3271](https://github.com/tinylabscom/mvm/issues/3271).

- [x] `uninstall.sh` (and `mvmctl uninstall` calling the same logic) that stops
      running supervisors, validates the daemon PID and aborts rather than
      signal an ambiguous process, removes the versioned install dirs and
      symlink, and prompts before touching `~/.mvm`. Shipped as
      `mvmctl env uninstall`, which runs the embedded script. It **refuses**
      while a machine is running rather than stopping supervisors — stopping a
      user's machines is not the uninstaller's call — and stops only the
      per-tenant host-agent daemons, each confirmed by executable first.
- [x] Every path through `mvm-core::config` helpers. Never inline `$HOME`.
      The Rust side does; the script mirrors `mvm_home` for the one path it
      needs (the state directory) and asks the installed `mvmctl` for the rest.
- [x] Test: uninstall with a running machine refuses; with none, it removes
      exactly the install set.

## WS5 — Verify the signature without a host `cosign`

Issue: [#3272](https://github.com/tinylabscom/mvm/issues/3272).

- [ ] Verify the Sigstore bundle in-process in Rust for `mvmctl update`
      (`crates/mvm-cli/src/update.rs`), so the self-update path stops being
      best-effort.
- [ ] Have `install.sh` prefer `mvmctl verify-release` once a binary exists on
      disk, falling back to `cosign` and then to the current warning.
- [ ] Delete the "Claim 20 limits" carve-out from
      `specs/adrs/001-microvm-security-posture.md` once the third path refuses
      an unsigned artifact like the other two.
- [ ] Weigh the closure cost first: a bundle verifier is a real dependency, and
      the limit-dependencies rule applies. If the cost is unacceptable, record
      that decision in the ADR instead of leaving the limits note unexplained.

## WS6 — Compat CI

Issue: [#3273](https://github.com/tinylabscom/mvm/issues/3273).

- [ ] A workflow running the *current* installer against the last N *published*
      releases, on a macOS and a Linux runner.
- [ ] A workflow running the released Linux binary in debian, ubuntu, rocky and
      fedora containers, to make glibc drift visible. This also quantifies what
      staying on `-unknown-linux-gnu` costs us versus musl.
- [ ] A cold first-run smoke on Linux that executes the exact commands from
      `public/src/content/docs/install/linux.md`, triggered by edits to that
      page or to `install.sh`. The macOS equivalent can only cover install plus
      `doctor` until a self-hosted Apple Silicon runner exists (#3011).

## WS7 — Nix hygiene

Issue: [#3274](https://github.com/tinylabscom/mvm/issues/3274).

- [x] Read the version via `importTOML` from `Cargo.toml` in
      `nix/packages/mvmctl.nix` instead of the hardcoded `0.18.0-rc.1`.
      `nix/packages/mvm-sdk-cdylib.nix` carried the same literal and reads the
      manifest too; `_release-prep` no longer rewrites either file.
- [x] Use `cargoLock.lockFile` rather than a hand-maintained `cargoHash`, so an
      unrelated lock bump does not turn the package red. Already true: the
      package vendors through `nix/lib/static-crates-cargo-deps.nix`, which is
      nixpkgs' `importCargoLock` over the committed `Cargo.lock`. There was no
      `cargoHash`, and `Cargo.lock` has no non-registry sources needing
      `outputHashes`.
- [x] Write the check/harness boundary down in `nix/lib/factories/README.md`:
      a Nix check provides the package and session environment; the Rust
      harness owns the behavioral assertions. Two catalogs drift, and the drift
      is invisible until one of them is wrong.
- [x] Sweep `nix/ops/README.md` and any sibling doc still naming Lima or
      `mvmctl dev up`.

## Acceptance

- [ ] A new macOS user and a new Linux user each run one command from a
      monitored URL, with mandatory checksum verification and signature
      verification that no longer depends on a host `cosign`.
- [ ] A failed upgrade leaves a working previous install.
- [ ] `uninstall.sh` exists, is tested, and refuses ambiguity.
- [x] `nix/packages/mvmctl.nix` cannot drift from `Cargo.toml`.
- [ ] `just ci` and every xtask gate green.
