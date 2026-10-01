# Hostlib-carrying release artifacts (PS-15, #3724)

## What landed

The language SDKs load `libmvm_hostlib` in-process; until now nothing a
release published actually carried it, so a downloaded install depended on
the beside-`mvmctl` fallback alone.

- **Release tarball**: the release workflow builds `mvm-hostlib` per target
  alongside the per-VM host binaries and copies the cdylib into the tarball
  beside `mvmctl`, fail-closed like the host binaries (a missing build
  fails the job, never ships a partial tarball); the packaging step asserts
  the tarball listing names the library.
- **PyPI wheels**: `publish-pypi` runs a Linux + macOS matrix, builds the
  cdylib, embeds it at `mvm/_native/`, and builds a wheel per platform. A
  hatchling build hook (`hatch_build.py`) tags the wheel
  `py3-none-<platform>` — and only when the library is present: a local
  development build without it stays universal, and the sdist stays
  source-only (`mvm/_native` excluded). The smoke install asserts the
  installed package carries the library.
- **npm packages**: `publish-npm` builds both platform libraries on a
  matrix runner job, assembles `native/` in the pack job (refusing to
  publish unless both `libmvm_hostlib.so` and `.dylib` are present — the
  loader picks by platform file name), packs, and the smoke install
  asserts the installed package carries this platform's library.
  `package.json` ships `native/` in `files`.

Verified locally on macOS: platform-tagged wheel builds, passes `twine
check`, installs into a fresh venv with the library present; `npm pack`
includes `native/`; Python SDK (322) and TypeScript SDK test suites green;
actionlint clean on all three workflows.

## Remaining in PS-15

deb/rpm + AUR + nixpkgs derivation; ordered/idempotent crates.io publish;
per-artifact release smoke tests beyond the hostlib assertions added here.
