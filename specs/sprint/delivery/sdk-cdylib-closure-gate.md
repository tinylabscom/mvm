# Pin the SDK cdylib closure free of the host HTTP/TLS/async stack

## Why now

The default `mvm-sdk` library is also built as `libmvm_host_services.so`, the
in-guest cdylib every language SDK loads. Its C ABI is synchronous
JSON-over-vsock. If the default closure picks up HTTP, TLS or an async runtime,
that cdylib stops cross-compiling — and the failure appears at the
cross-compile, a long way from the edit that caused it.

The closure is clean today: `deploy-remote` is off by default and carries the
only `mvm-http` edge. **Nothing was holding it that way.** The
dependency-cutting work is done; the gates are the gap. One default-on feature,
or one new unconditional dependency, silently puts a C TLS stack back.

## What ships

`xtask check-sdk-cdylib-deps` reads `cargo tree -p mvm-sdk -e no-dev,no-build
--locked` and refuses `mvm-http`, `ring`, `rustls`, `tokio`, `tokio-rustls` in
the default closure. It matches whole crate names, so `rustls-pemfile` and
`tokio-util` do not false-positive, and it reads crate names rather than the
feature name, so restructuring or renaming `deploy-remote` cannot blind it.

Wired into `check-all` (66 gates).

## Verified to bite

Not just green: setting `default = ["deploy-remote"]` — the exact regression it
exists for — makes it fail and name all five crates. Reverted after.

```
check-sdk-cdylib-deps: mvm-sdk's default non-dev closure pulls host-only
HTTP/TLS/async dependencies (mvm-http, ring, rustls, tokio, tokio-rustls).
```

## Provenance

The gate was written on `fix/2978-sdk-cdylib-deps`, which sat unmerged in a
stale worktree. That branch's other half — moving the remote transport behind an
off-by-default feature — landed separately, so only the gate was outstanding.
It is extracted here onto current `main` rather than rebased, because the
branch's `Cargo.toml` changes now conflict with the shipped feature layout and
would have had to be discarded during a rebase anyway.
