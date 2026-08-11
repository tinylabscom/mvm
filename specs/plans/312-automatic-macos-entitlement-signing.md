# Plan 312: Automatic macOS VM entitlement signing

**Status: COMPLETE**

## Goal

Make macOS entitlement signing an installation and update invariant instead of
a routine user action, while keeping an explicit repair path for source builds
and older installations.

## Delivered

- [x] Sign `mvmctl` and shipped VM supervisors during `install.sh`.
- [x] Sign the replaced executable and adjacent supervisors during
      `mvmctl update`.
- [x] Add the supervisor entitlement profile to the release assets and
      Homebrew installation path.
- [x] Model Virtualization.framework and Hypervisor.framework requirements as
      separate target roles.
- [x] Make `mvmctl doctor` validate role-specific entitlements and recommend
      reinstall/update before the advanced repair command.
- [x] Retain `mvmctl env sign` for source-build and legacy-install repair.
- [x] Cover the command surface, doctor mapping, shell syntax, and focused
      Rust compilation paths.

## Operational policy

On macOS, an install or update that cannot apply the required entitlements is
not a complete VM-ready installation. `MVM_SKIP_CODESIGN=1` remains an
explicit escape hatch for development and test environments; `doctor` then
reports the resulting missing entitlement state.

Verification: focused runtime, doctor, and CLI tests passed; installer tests
passed with a fake macOS `codesign`; the workspace test suite passed after the
one restricted-sandbox socket test was rerun with loopback permissions.
