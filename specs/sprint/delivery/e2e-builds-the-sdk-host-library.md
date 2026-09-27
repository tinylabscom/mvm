# The documented-surface suite builds the SDK host library

Backing: shipped-source
Validation: cargo nextest run -p mvmctl --test github_actions_extended_e2e

The language SDKs drive machines in-process through `libmvm_hostlib` and find
it beside the `mvmctl` on `PATH`. The documented-surface script built only
`--bin mvmctl`, so after the SDKs stopped shelling out to `mvmctl`, both
runtime-SDK scenarios (`s31_launch_e2e/sdk_and_library_modes.feature:43` and
`:65`) failed on every lane with "the host library libmvm_hostlib.so was not
found". Extended CI runs nightly only, so no pull request saw it. The release
workflow runs the same suite before it signs anything, so it also blocked the
next CLI release.

The script now builds `mvm-hostlib` into the same target directory after
`mvmctl`. The helper check fails the run before the suite starts if the
library is missing. Checked locally: the Python SDK's resolver finds the built
library beside `mvmctl` on `PATH`.
