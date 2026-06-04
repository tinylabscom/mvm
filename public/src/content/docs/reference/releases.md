---
title: "Releases & downloads"
description: "How mvm's v* release tags publish binaries, kernels, and images — and how each install path consumes them."
---

Every `v*` git tag fires two GitHub Actions workflows that publish a single
GitHub Release:

- **`release.yml`** builds `mvmctl` for all four targets
  (`aarch64`/`x86_64` × macOS/Linux), packages each as
  `mvmctl-<target>.tar.gz` (binary + `resources/` + man pages), generates
  `checksums-sha256.txt`, cosign-signs every tarball, and also builds the
  dev / builder / default-microvm / builder-vm / runtime-overlay images.
- **`kernel-build.yml`** builds the slim builder + workload kernels on native
  aarch64 and x86_64 runners and uploads `vmlinux-<arch>-<variant>` +
  `kernel-<arch>-checksums-sha256.txt`.

## How each install path consumes a release

| Path | What it pulls |
|------|---------------|
| `install.sh` (curl one-liner) | `mvmctl-<target>.tar.gz` + `checksums-sha256.txt` (+ cosign `.bundle` if cosign present) |
| `brew install tinylabscom/mvm/mvmctl` | the same tarball, via the tap formula |
| `cargo install mvmctl` | source from crates.io (published by `publish-crates.yml`) |
| `mvmctl update` | the tarball for the latest release, in-place swap |
| `mvmctl kernel build --source download` | `vmlinux-<arch>-<variant>` + `kernel-<arch>-checksums-sha256.txt`, pinned to the binary's own release tag |

## Verifying provenance

All release tarballs are cosign-signed (keyless, GitHub OIDC). To verify
manually:

```bash
cosign verify-blob \
  --bundle mvmctl-<target>.tar.gz.bundle \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp 'https://github.com/tinylabscom/mvm/.github/workflows/release.yml@refs/tags/.*' \
  mvmctl-<target>.tar.gz
```

`install.sh` and `mvmctl update` run this automatically when `cosign` is on
`PATH`.

## Homebrew tap setup (one-time, maintainers)

The `update-homebrew-tap.yml` workflow renders the formula on each release and
pushes it to the `tinylabscom/homebrew-mvm` tap. To enable it once:

1. Create an empty public repo `tinylabscom/homebrew-mvm` with a `Formula/`
   directory.
2. Add a repository secret `HOMEBREW_TAP_TOKEN` to `tinylabscom/mvm` — a token
   (fine-grained PAT or deploy key) with **push** access to the tap repo. The
   default `GITHUB_TOKEN` cannot push to a second repository.

After that, every `v*` release auto-updates `Formula/mvmctl.rb` in the tap, and
`brew install tinylabscom/mvm/mvmctl` resolves the latest version.
