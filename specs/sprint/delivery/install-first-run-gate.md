# A new user's first command is a release gate

Backing: shipped-source
Validation: cargo nextest run -p mvmctl --test install_sh --test smoke_fresh_install --test pin_installer_default --test release_assets

Following the README on 2026-09-24 — `curl -fsSL https://runmvm.com/install.sh | sh`,
then `mvmctl machine run --image alpine -- echo hello` — could not start a
microVM on any platform. The installer baked `DEFAULT_VERSION="v0.17.0"`, whose
release publishes no `kernel-<arch>-*` artifacts, so the first run died on a 404.
Its fallback asked GitHub for `releases/latest`, which answered
`boot-image/v0.1.5`. Nothing in the release pipeline ever ran the one-liner and
the first command, so nothing could have noticed.

## What changed

- **Installer default.** `install.sh` now installs the newest stable CLI release
  by default: tags of the form `v<major>.<minor>.<patch>`, not drafts, not
  prereleases, publishing this platform's archive, newest by version rather than
  by publication date. Other trains (`boot-image/*`, `revocations`) and GitHub's
  latest marker are ignored. The response is tokenized and walked by nesting
  depth in POSIX `awk`, because a fresh host has no JSON tool. That keeps it
  independent of key order and formatting, and it handles GitHub's 1.3 MB,
  100-release response in about 0.1 s on BSD, GNU and BusyBox tools.
  `MVM_VERSION` still pins any tag. The baked `DEFAULT_VERSION` is used only
  when the releases API cannot be reached, or when it lists no qualifying
  release, and the installer says when it falls back.
- **Prereleases are excluded**, deliberately. `release.yml` now publishes every
  tag as a prerelease: release candidates stay one, and a stable tag is promoted
  only after its first-run smoke passes. "Not a prerelease" therefore means
  "a fresh install booted it".
- **Release gate.** `release.yml` gains `first-run-smoke`, which runs after
  `verify-release` because the first run downloads the kernels that
  `kernel-build.yml` attaches after publication. It runs
  `scripts/smoke-fresh-install.sh <tag>` on the self-hosted Apple Silicon runner
  (HVF) and on hosted `ubuntu-latest` with KVM (Firecracker), and uploads each
  transcript. It also gains `promote-release`, the only step that marks a stable
  tag as a full release and as GitHub's latest, and that dispatches the site
  bake. The workers dispatch has moved out of the `release` job.
  `release-boot-image.yml` and `revocations.yml` create their releases with
  `--latest=false`.
- **`just smoke-fresh-install [version]`** runs the same script locally. It uses
  a throwaway `HOME` under `/tmp` and an `env -i` environment, pipes `install.sh`
  into `sh` with the default bootstrap, then runs
  `machine run --image alpine -- echo <token>` with stdin from `/dev/null`. The
  token must appear on stdout within the budget (install 1200 s, first command
  600 s). Homebrew stays on the PATH when the host has it;
  `MVM_SMOKE_NO_HOMEBREW=1` removes it.
- **One writer for the offline fallback.** `scripts/pin-installer-default.sh`
  writes `DEFAULT_VERSION` and the three archive hashes together. It takes them
  only from a promoted release, and only from a checksum manifest that
  `cosign verify-blob` accepts under that tag's `release.yml` identity.
  `workers.yml` bakes through the script. `_release-prep` pins
  `--newest` instead of setting `DEFAULT_VERSION` to the version it prepares:
  that tag did not exist yet, and its hashes were left as the previous
  release's, so the fallback could never have installed it.
- **PR CI compiles the release feature set.** `lint-features-embed`, which
  already has the pinned zig, now runs
  `cargo check --locked -p mvmctl --bins --features "$MVMCTL_RELEASE_FEATURES"`,
  reading the set out of `release.yml`. Run on this branch, it fails with
  exactly the `builder_vm_artifact_names` error that stopped v0.18.0-rc.2, and
  it passes under `-D warnings` once #3678's fix is applied.
- **Bootstrap no longer requires Homebrew on macOS.** `mvmctl bootstrap`
  refused with "Homebrew is not installed" before preparing anything, so the
  installer's bootstrap failed on every Mac without Homebrew, and the first run
  then did all the preparation itself. The check now only reports.

## Evidence

`just smoke-fresh-install v0.18.0-rc.1` on macOS 26 Apple Silicon:

- With Homebrew on the PATH, the smoke **fails**. The install and bootstrap
  finish in 139 s, then the first command exits 1 after 6 s with
  `initramfs version mismatch: expected 0.18.0-rc.1, got Some("0.18.0")`. This
  is the defect #3510 fixed on `main`.
- Without Homebrew, it passes: installed in 19 s, token printed in 17 s. In this
  case the bootstrap stops at the Homebrew check, so it never caches the
  mismatched initramfs, and the first run downloads the correct one. The two
  runs differ only in `/opt/homebrew/bin`, which is why the smoke keeps Homebrew
  on the PATH by default.

## Checked, no change needed

- A `machine run` with an idle inherited stdin pipe blocked before any output on
  v0.17.0. `main` has not read an idle pipe since #2908 (`classify_stdin`
  polls with a zero timeout, with pipe-level tests in `vm/invoke.rs`). The fix
  is in v0.18.0-rc.1 and later.
- The download-failure guidance on `main` names the mvm-managed builder and no
  host Nix setup (`download_failure_guidance_uses_mvm_managed_builder_without_sudo`).

## Not yet proven

- The Linux lane of `first-run-smoke` has not run. A hosted runner's first run
  must install Firecracker through `mvmctl bootstrap`, using the runner's
  passwordless `sudo`. If that fails, promotion stays blocked until it is fixed
  or the lane is changed.
- `cargo check` catches feature-gating breaks. It does not catch differences
  between the `release-min` profile and the dev profile.
- No published stable release has a signed `checksums-sha256.txt.bundle` yet,
  so `pin-installer-default.sh` cannot authenticate v0.17.0 or anything
  earlier. The checked-in fallback stays at v0.17.0 until the first release cut
  under this workflow is promoted.
