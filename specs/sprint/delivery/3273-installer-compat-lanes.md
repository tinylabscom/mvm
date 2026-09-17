# Installer back-compat, distro compat, and install-page smoke lanes

Issue #3273, plan
`specs/plans/2026-09-15-install-lifecycle-and-packaging-polish.md` WS6.

## The workflow

`.github/workflows/installer-compat.yml`, five jobs:

- **resolve** reads the releases API and picks what the other lanes run
  against (`scripts/installer-compat/matrix.sh`). A release counts when its
  tag starts with `v`, it is not a draft, and it publishes
  `checksums-sha256.txt` plus the target's `mvmctl-<target>.tar.gz`. That
  drops the `boot-image/*` tags, the asset-less tags, and `v0.0.1`'s
  `mvm-*`-named archives without a hand-kept list.
- **installer**: each of the newest three releases (dispatch input
  `release_count`), fresh, on `ubuntu-latest` and `macos-latest`. The install
  dir starts out holding two unrelated files. After install: `current` names a
  complete release directory for the tag, `mvmctl --version` reports it, every
  top-level executable and `assets/` in that release's own archive is linked
  through `current`, the installer's excluded payloads (read out of
  `install.sh`'s `EXCLUDED_PAYLOADS`) are nowhere, macOS binaries carry their
  profile's entitlement keys, and `doctor` runs to completion. Then
  `uninstall.sh` runs with a state directory present; a release whose mvmctl
  predates the `--quiesce` check must be refused with nothing removed, and
  `--force` then removes it. Only the unrelated files may remain, unchanged,
  and the state directory is kept.
  The macOS job installs the trusted historical libkrun runtime first because
  the immutable v0.16.1 Apple Silicon binary dynamically links libkrunfw.
- **upgrade** walks one prefix through those releases oldest to newest. After
  each step the replaced release directory is still complete and its mvmctl
  still runs, and entries the older release had and the newer dropped are gone.
  It then rolls back by re-running the installer pinned to the previous tag,
  checks the newer release is kept, and uninstalls.
- **distro** runs the newest full release, plus a newer prerelease, in
  `debian:stable`, `ubuntu:24.04`, `rockylinux/rockylinux:9` and
  `fedora:latest`, on `ubuntu-latest` and the free `ubuntu-24.04-arm` runner
  `ci.yml` already uses. Every executable in the archive goes through `ldd -v`
  before install, so the job summary carries host glibc, the highest glibc each
  release requires, and any `GLIBC_x.y not found` per binary, even when the
  install then fails. A loader error fails the job, except for the exact
  immutable pre-static tags named by the workflow and forwarded into the
  container; the focused suite asserts that forwarding boundary.
- **docs-smoke** extracts the One-liner, Pin a version and Verify blocks
  from `public/src/content/docs/install/linux.md` and runs them unchanged
  except, on a pull request, the installer URL, which points at the checkout's
  `install.sh`. `e2e-docs.yml` had no coverage of the install page.

Triggers: weekly (Monday 10:37 UTC), `workflow_dispatch`, and `pull_request`
path-filtered to the installer, uninstaller, install pages, the scripts and the
workflow. It is not a required check: every lane depends on release downloads
and public registries. The verdict logic is PR-gated instead —
`scripts/installer-compat/installer-compat.test.sh` runs in `ci.yml`'s
Invariant lane against synthetic releases served locally, through the real
`install.sh` and `uninstall.sh`, including cases that must fail. A scheduled
failure opens or updates one tracking issue; a green run closes it.

## Found while building it

- **The current installer could not install `v0.17.0`, its own baked default,
  on macOS.** The lane found that `v0.17.0` and earlier archives keep
  `mvmctl.entitlements` under `resources/`. Issue #3370 is now fixed: the
  installer adopts that legacy profile into `assets/`. Archive facts inspect
  both locations, the strict resources-layout fixture must install, and a
  refusal is tolerated only for an explicitly non-strict release whose archive
  genuinely lacks the named profile.
- **Rocky Linux 9 cannot run the pre-static releases.** `mvmctl` and
  `mvm-host-agent` from `v0.17.0` and `v0.18.0-rc.1` require `GLIBC_2.39`;
  Rocky 9 ships 2.34. Those immutable artifacts remain visible as exact-tag
  historical baselines after #3371; any later release with a loader error
  still makes the distro lane red.
- **The documented version pin did not pin.** `MVM_VERSION=v0.16.1 curl … | sh`
  sets the variable for `curl`, not for `sh`, so it installed the default
  release. Fixed in `install/linux.md`, `install/macos.md`,
  `getting-started/installation.md` and `public/src/lib/agent-skill.ts`.

## Verified only by a live run

The container runs, hosted macOS signing and `doctor`, real `ldd -v` output
formats, and the tracking-issue job.
