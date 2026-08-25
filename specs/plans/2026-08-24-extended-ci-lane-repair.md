# Extended CI lane repair

Backing: shipped-source
Validation: check-sprint-append

## Outcome

Restore the scheduled Extended CI witnesses reported by issue #2830 without
weakening or skipping their build coverage.

## Work

- [x] Trust the `slp/krun` Homebrew tap before installing libkrun in every
      macOS Extended CI lane that compiles libkrun consumers.
- [x] Install libkrun in the release-only Apple workspace lane before its
      all-target build.
- [x] Supply the builder-image smoke with a placeholder for every binary in
      `nix/lib/mvm-host-binaries.nix`, including `mvm-builderd`.
- [x] Add structural regression tests for the trusted Homebrew install and
      builder binary set.
- [x] Run focused tests, formatting, workflow-path validation, workspace
      check, and workspace Clippy with warnings denied.

## Acceptance

The repair lands through a merged PR that closes #2830, and the next Extended
CI run completes its macOS libkrun, Apple, and Linux builder-image lanes.
