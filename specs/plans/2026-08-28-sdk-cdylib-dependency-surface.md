# SDK cdylib dependency surface

Issue: #2978

## Goal

Keep the default `mvm-sdk` library closure used by
`libmvm_host_services.so` free of the host-only HTTP, TLS, and async stack,
without removing authenticated remote deployment from `mvmctl`.

## Work

- [x] Reproduce the dependency leak with `cargo tree` and add a regression
      gate that fails on `mvm-http`, `rustls`, `ring`, `tokio`, or
      `tokio-rustls` in the default non-dev closure.
- [x] Make `mvm-http` optional and put the remote deployment client behind an
      off-by-default `remote-deploy` feature.
- [x] Keep `mvmctl deploy` functional by enabling `remote-deploy` at the
      `mvm-cli` dependency boundary.
- [x] Verify default and feature-enabled `mvm-sdk` tests plus focused xtask
      tests and zero-warning package Clippy.
- [ ] Rebase on the latest merged queue head and pass workspace tests,
      workspace Clippy, formatting, and repository policy gates.
- [ ] Merge the repair through the queue and confirm issue #2978 closes from
      the merged PR.

## Security boundary

The shipping client remains fail-closed and authenticated when explicitly
enabled. The default guest-facing library stops compiling unreachable host
transport code and its native TLS dependency; the synchronous broker C ABI is
unchanged.
