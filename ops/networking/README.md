# `ops/networking/`

Bridge / TAP / iptables provisioning for the mvm host network.

**Status (decided 2026-04-30): lenient reading.** The bridge / TAP /
iptables setup stays in `crates/mvm-runtime/src/vm/network.rs` and
runs from `mvmctl dev up` / `mvmctl run`. Rationale: the
[mvm-nix-best-practices guide](../../specs/references/mvm-nix-best-practices.md)
hard rules (`flake.nix` / `devShells` / `shellHook`) target Nix
*entry points* that mutate the host on `nix develop` — they don't
target user-invoked CLI commands. `mvmctl dev up` is explicit, on
demand, and prints what it's about to change before doing it; that's
the visibility the host-mutation boundary is asking for. A separate
`ops/networking/bridge-setup.sh` would only re-introduce a setup
ritual without adding clarity (the user already typed the command
that runs the mutations).

If a later product decision flips this — for example, mvmd's
production target where bridge setup happens at deployment time, not
on first `mvmctl run` — the migration is mechanical: extract the
`iptables` / `ip link` / `bridge` calls from `network.rs` into
`bridge-setup.sh` here, and have `network.rs` precondition-check
that the bridge already exists.
