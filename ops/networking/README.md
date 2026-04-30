# `ops/networking/`

Bridge / TAP / iptables provisioning for the mvm host network.

Currently empty. **Status: deferred for product decision** (see W7
"Items deferred — needs your decision" in
[the plan](../../specs/plans/31-nix-best-practices-cleanup.md)):

- **Lenient reading of the guide**: `mvmctl dev up` and `mvmctl run`
  legitimately invoke `crates/mvm-runtime/src/vm/network.rs` to set up
  the bridge + TAP + iptables NAT. The guide's hard rule names these
  as forbidden in `flake.nix` / `devShells` / `shellHook`, not in
  user-invoked CLI commands. Status quo.
- **Strict reading**: extract the iptables/bridge/`ip link`
  invocations into `bridge-setup.sh` here, and have `network.rs`
  warn-and-exit if the bridge isn't already up. User runs this script
  once per host.

Until the call is made, the code in `network.rs` stays authoritative
and this directory is documentation-only.
