# Issue #2978 — SDK cdylib dependency surface

## Outcome

The default `mvm-sdk` non-dev dependency closure no longer contains
`mvm-http`, `rustls`, `ring`, `tokio`, or `tokio-rustls`. Authenticated remote
deployment remains available to `mvm-cli` through the explicit
`remote-deploy` feature.

## Witnesses

- `xtask check-sdk-cdylib-deps` resolves the exact default Cargo feature tree
  and rejects the host transport stack by exact crate name.
- The gate was observed failing before the feature split and passing after it.
- Default `mvm-sdk` tests pass with the remote client excluded.
- `mvm-sdk --features remote-deploy` tests pass with the client and its
  fail-closed transport tests enabled.
- Package-wide all-target/all-feature Clippy is warning-free for `mvm-sdk`
  and `xtask`.

## Remaining delivery

Rebase on the latest merge-queue head, run the full workspace and repository
gates, then merge the linked PR so GitHub closes issue #2978.
