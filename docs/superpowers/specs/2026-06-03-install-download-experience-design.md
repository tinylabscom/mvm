# Install & download experience — design

Date: 2026-06-03
Branch: `feat/install-download-experience`
Status: approved (brainstorm)

## Problem

Two gaps in how users acquire mvm, plus one UX defect on the kernel compile path:

1. **`install.sh` does not exist.** The one-liner
   `curl -fsSL https://raw.githubusercontent.com/tinylabscom/mvm/main/install.sh | sh`
   is documented in `README.md`, `getting-started/installation.md`,
   `install/macos.md`, and `install/linux.md` — but the file is not in the
   repo, so the documented install path is broken.
2. **No Homebrew formula/tap.** `brew install` is not an option today.
3. **The kernel-download command is undocumented for users.**
   `mvmctl kernel build --source download` is real and shipped but only
   described in Rust doc-comments — there is no user-facing page.
4. **`mvmctl kernel build` (compile path) goes silent for minutes.** A
   single `ui::info` line prints, then `run_stage0` blocks for 3–10 min with
   no terminal output, and `--verbose` does not change that. The build
   output exists (the VM serial console at `console.log`) but is never
   surfaced.

## What already exists (do NOT rebuild)

- **Kernel download:** `crates/mvm-cli/src/update.rs::download_kernel()` +
  `crates/mvm-cli/src/commands/kernel.rs`. Fetches
  `vmlinux-<arch>-<variant>` from the release matching the binary's own
  version tag, SHA-256-verifies against
  `kernel-<arch>-checksums-sha256.txt`, caches to
  `~/.cache/mvm/builder-vm/<arch>/kernels/<variant>/vmlinux`. Pinned to the
  binary's release tag per ADR-046.
- **Kernel publish CI:** `.github/workflows/kernel-build.yml` builds both
  variants on native aarch64 + x86_64 runners and uploads the `vmlinux-*`
  assets + checksums on `v*` tags.
- **Binary release CI:** `.github/workflows/release.yml` builds `mvmctl` for
  all 4 targets (`{aarch64,x86_64}-apple-darwin`,
  `{x86_64,aarch64}-unknown-linux-gnu`), packages
  `mvmctl-<target>.tar.gz` (binary + `resources/` + man pages), generates
  `checksums-sha256.txt`, cosign-signs every tarball, and creates the
  GitHub Release.
- **Self-update:** `mvmctl update` (`update.rs`) already does
  download → checksum → optional cosign → smoke-tested in-place swap. The
  installer mirrors this verification posture so both acquisition paths
  behave identically.

So the CI/release workflows are done. The work is: the installer, the
Homebrew tap, the docs, and the compile-path logging.

## Deliverables

### 1. `install.sh` (repo root)

POSIX `sh`, `set -eu`. Mirrors `update.rs` verification.

- **Platform detection** → target triple, same 4 targets as
  `update.rs::detect_target()`. Unknown platform → clear error and exit.
- **Version resolve:** `MVM_VERSION` if set (e.g. `v0.15.2`), else query
  `${MVM_UPDATE_API_URL:-https://api.github.com}/repos/tinylabscom/mvm/releases/latest`
  for `tag_name`.
- **Download** `mvmctl-<target>.tar.gz` and `checksums-sha256.txt` from
  `${MVM_UPDATE_DOWNLOAD_URL:-https://github.com}/tinylabscom/mvm/releases/download/<tag>/`.
- **Verify:**
  - sha256 via `shasum -a 256` (macOS) or `sha256sum` (Linux); compare to
    the `checksums-sha256.txt` line for the tarball. Mismatch → delete +
    abort.
  - If `cosign` is on `PATH`: `cosign verify-blob` against the
    `<tarball>.bundle` using the same OIDC issuer + identity regexp as
    `update.rs::verify_signature`. Absent cosign → warn + continue
    (non-fatal, matches `update.rs`).
  - `MVM_SKIP_HASH_VERIFY=1` honored as the documented escape, with a
    stderr warning. Never used in CI.
- **Install:** extract to a `mktemp -d` dir; place `mvmctl` and `resources/`
  into `MVM_INSTALL_DIR` (default `~/.local/bin`); `chmod 755` the binary.
  Use `sudo` only when the target dir is not writable.
- **macOS codesign:** `codesign --entitlements resources/mvmctl.entitlements
  -f -s -` (ad-hoc) on the installed binary so Hypervisor.framework accepts
  it — fulfills the promise already written in `install/macos.md`.
- **PATH hint:** if `MVM_INSTALL_DIR` is not on `$PATH`, print the line to
  add to the shell profile.
- **Env knobs:** `MVM_VERSION`, `MVM_INSTALL_DIR`, `MVM_SKIP_HASH_VERIFY`,
  `MVM_UPDATE_API_URL`, `MVM_UPDATE_DOWNLOAD_URL` (last two for hermetic
  tests, same names `update.rs` uses).

### 2. Homebrew — binary-download tap formula (Option A)

- **`packaging/homebrew/mvmctl.rb`** — formula source. `on_macos`/`on_linux`
  + `on_arm`/`on_intel` blocks, each with the per-target tarball `url` +
  `sha256`. `install` does `bin.install "mvmctl"`, installs `resources/`,
  and on macOS re-codesigns with `resources/mvmctl.entitlements`.
  `caveats` point at the libkrun Homebrew trio. Installed via
  `brew install tinylabscom/mvm/mvmctl`.
- **`.github/workflows/update-homebrew-tap.yml`** — on `release: published`,
  download the 4 release tarballs (or read their checksums from the release
  assets), render `mvmctl.rb` from the template with the new version + 4
  sha256s, and push to the `tinylabscom/homebrew-mvm` tap repo. Runs
  `brew style` / `brew audit --formula` on the rendered formula before
  pushing.
- **Secret:** the workflow needs `HOMEBREW_TAP_TOKEN` (a token with push
  access to `tinylabscom/homebrew-mvm`). The default `GITHUB_TOKEN` cannot
  push to a second repo.
- **One-time manual setup** (documented in the release doc, §4): create the
  empty `tinylabscom/homebrew-mvm` repo and add the `HOMEBREW_TAP_TOKEN`
  secret. The implementer does not create the tap repo.

### 3. Kernel docs — `public/src/content/docs/guides/kernels.md`

Documents `mvmctl kernel build`:

- `--which {builder,workload}`, `--all`, `--source {compile,download,auto}`,
  `--arch {aarch64,x86_64}`.
- Cache path: `~/.cache/mvm/builder-vm/<arch>/kernels/<variant>/vmlinux`.
- `download` is pinned to the binary's own release tag (ADR-046) and
  SHA-256-verified against `kernel-<arch>-checksums-sha256.txt`.
- When to compile vs download: compile is host-arch only (Stage 0 cannot
  cross-compile); the other arch must be downloaded.
- `MVM_SKIP_HASH_VERIFY` caveat.
- Added to the Astro sidebar; linked from the builder-VM guide.

### 4. Release / downloads doc — `public/src/content/docs/reference/releases.md`

Ties the `v*`-tag pipeline together:

- `release.yml` (binaries + images) and `kernel-build.yml` (kernels) — what
  triggers them, the full asset list per release.
- How each consumer pulls from a release: `install.sh`, `brew`,
  `cargo install mvmctl`, `mvmctl update`,
  `mvmctl kernel build --source download`.
- Cosign verification (issuer + identity regexp) for the security-conscious.
- The one-time Homebrew-tap setup from §2 (tap repo + `HOMEBREW_TAP_TOKEN`).

### 5. Compile-path logging — `mvmctl kernel build` + shared `dev up` Stage 0

- **Always (quiet mode):** an elapsed-time heartbeat (~every 20 s), e.g.
  `still compiling… (2m10s elapsed)`, so the multi-minute compile is never
  dead-silent.
- **`--verbose`:** forward every new `console.log` line (the VM serial
  console — includes the inner `nix build` output, B1: raw/complete, boot
  noise included) to stderr as the build runs.
- **Implementation seam:** `run_stage0` already boots the builder VM with
  `console.log` as the serial console, and
  `libkrun_builder::wait_with_panic_detector_until` already tails that file
  for the kernel panic banner. Extend that tail loop with a progress mode
  (`Quiet` → heartbeat, `Verbose` → forward lines). Plumb `cli.verbose`
  from `kernel.rs` → `build_kernel_via_stage0`
  (`commands/env/apple_container.rs`) → the Stage 0 builder call. Both
  `mvmctl kernel build` and `dev up`'s first build share this path, so both
  benefit.

## Testing

- **`install.sh`:** Rust integration test (`tests/install_sh.rs`) serving
  release fixtures (a fake `mvmctl-<target>.tar.gz` whose `mvmctl` is a
  shell stub printing a version, plus a matching `checksums-sha256.txt`)
  over a local HTTP server, with `MVM_UPDATE_API_URL` /
  `MVM_UPDATE_DOWNLOAD_URL` / `MVM_INSTALL_DIR` pointed at it. Assert: binary
  lands and is executable; a tampered checksum is rejected and the binary is
  not installed. `shellcheck install.sh` added as a CI lint.
- **Homebrew:** unit-test the sha256-render step (template + 4 digests →
  expected `.rb`); `brew style` / `brew audit` gate inside the tap workflow.
- **Logging:** unit-test the heartbeat formatter (elapsed seconds →
  `Nm Ss`) and the verbose line-forward predicate — no live VM needed.
- **Docs:** existing `xtask check-doc-claims` / `check-no-overclaim` gates
  apply to the two new doc pages.

## Out of scope (YAGNI)

- Pre-fetching kernels or images inside `install.sh` — left to first
  `dev up` / `mvmctl kernel build`.
- Windows installer (`install.ps1`) — Windows is not a supported local host.
- A cask or source-build Homebrew formula — Option A (binary-download tap
  formula) only.
- Filtered/clean verbose output (B2) — verbose is raw `console.log` (B1).
