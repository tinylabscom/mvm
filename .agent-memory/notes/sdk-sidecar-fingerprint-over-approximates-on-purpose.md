---
title: The SDK sidecar staleness fingerprint over-approximates on purpose — do not narrow it
date: 2026-09-01
tags: [sdk-sidecar, cdylib, fingerprint, diagnostics, do-not-retry]
---

`sdk_cdylib_source_fingerprint` (`crates/mvm-build/src/guest_agent_build.rs`)
keys a cached sidecar to whole source trees:

```
Cargo.lock, Cargo.toml,
crates/mvm-contract/{Cargo.toml,src}
crates/mvm-core/{Cargo.toml,src}
crates/mvm-agentd/{Cargo.toml,src}
crates/mvm-host-services/{Cargo.toml,src}
```

Any edit anywhere in those crates invalidates it, whether or not the cdylib
closure can reach the changed code. Measured on a checkout tracking main: a
sidecar built at 12:01 was stale by 20:36 the same day, invalidated by four
merges. One of them (`38a5289d3d`) contributed exactly seven lines in
`crates/mvm-core/src/observability/metrics.rs` — nothing
`libmvm_host_services.so` calls.

So the warning is loud, and being loud is not the same as being wrong. If you
are tempted to narrow the input set to cut the noise: **don't.** The precise
alternative is a per-symbol reachability analysis across four crates, and
being wrong in that direction ships a guest a cdylib missing the verb it is
about to call. A false positive costs one line of text. A false negative costs
`unknown method` from inside a guest, where the error names the broker rather
than the stale image. The asymmetry is the whole design.

The cheap true statement is the one to reach for: the warning only matters if
the launch binds `--host-service`. Otherwise no sidecar is mounted and the line
is noise about an artifact the run never touched.

## Which crate owns the cdylib

`crates/mvm-host-services`, not `crates/mvm-sdk`. Its `[lib]` comment records
why the split happened: the package name is what makes cargo emit
`libmvm_host_services.so` directly, where living in `mvm-sdk` produced
`libmvm_sdk.so` and a nix rename established the filename every language SDK
dlopens.

Worth knowing because the docs lagged the move on both sides, and the warning
text inherited the wrong crate name from them. Fixed in the code by #3075 and
in `CLAUDE.md` / `mvm-sdk`'s package description here. An edit under
`crates/mvm-sdk` cannot invalidate a cached sidecar — it is not a fingerprint
input.
