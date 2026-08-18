# Pages and boot-image signing deployments

The Pages workflow now installs both WASM targets used by the browser demo:
`wasm32-unknown-unknown` for the browser shim and `wasm32-wasip1` for the guest
workload.

The boot-image release train now targets the separate protected
`boot-image-signing` environment. The existing `release-signing` environment is
restricted to `v*` tags, so it rejected the train's `boot-image/v*` refs. The
repository environment must allow the `boot-image/v*` tag pattern and retain the
same required reviewers as the release-signing environment.

Focused workflow regression coverage passes: 16 tests.
