# Drop the builder-route decision seam

`BuilderRoute` presented itself as the seam deciding whether a builder dispatch
takes the typed `mvm-builderd` route or "the legacy controlled-shell-job
channel". At its only generic-dispatch site it decided nothing:

```rust
let route = resolve_route(false, typed_opt_in(..));   // daemon_reachable: false, hardcoded
if route == BuilderRoute::LegacyShell { tracing::debug!(..) }
```

`daemon_reachable` was a literal `false`, so the resolver had one reachable
answer and the branch was an unconditional debug log. The real decision is
structural — a generic builder job has no typed equivalent — and
`xtask check-builder-shell-job-sites` is what actually keeps that surface
visible and shrinkable.

Gone: the `BuilderRoute` enum, `resolve_route`, `legacy_shell_diagnostic`,
`typed_opt_in`, and `BUILDERD_TYPED_OPT_IN_ENV` (`MVM_BUILDERD_TYPED`).

The flake-check route was gated behind that opt-in flag "until it gets the same
live proof". It now takes the daemon whenever one is reachable — reachability is
the whole decision. A caller that finds no daemon runs its own in-VM path, which
is not a legacy alternative but the only way to check a flake with no resident
daemon and no host nix.

## What this deliberately does not remove

The controlled-shell-job channel itself. `HostVmRequest::Run` is still the only
channel for a generic builder job — `dev_build` and `pool_build` both dispatch
through it, and the typed client covers only `BuildGuestImage` and `FlakeCheck`.
Removing it would need the WS-D migration that has not happened. What went is
the scaffolding that described a choice nobody was making.

## Gates

`fmt --all`, `clippy`, `nextest -p mvm-build -p mvm-cli` (3,064 pass),
`xtask check-all` (61 gates).
