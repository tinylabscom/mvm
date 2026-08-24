# Nix guest FlowMux identity handoff

Issue [#2828](https://github.com/tinylabscom/mvm/issues/2828).

## Failure

The Nix-built guest init launched `mvm-egress-client` as the guest-agent uid
with only `CAP_NET_BIND_SERVICE`, but the client was also responsible for
mounting the labelled identity drive. That mount requires privilege, and the
resulting 0400 signing key must remain unavailable to both the workload and the
guest agent. The client therefore exited before opening its FlowMux session.

## Boundary

The drive probe and mount remain in the shared Rust implementation. The Nix
init invokes a short provisioning mode while still root, assigns only the 0400
signing key to reserved service uid 989, and unmounts the drive. It then starts
the long-lived egress client under that uid with `no_new_privs` and only
`CAP_NET_BIND_SERVICE`. The network parser never retains `CAP_SYS_ADMIN`, while
the workload, agent, and optional builder are prevented from reusing the
reserved uid.

The same provisioning also makes the root-owned forward proxy usable on the
secret-bearing path, where `mvm.vsock_egress` is intentionally absent. Public
trust and ingress inputs remain mode 0444; only the secret key changes owner.

## Verification

- The mkGuest structure test proves root provisioning precedes privilege drop,
  pins the dedicated uid, requires `no_new_privs` and the low-port bind
  capability, and rejects retained mount capability.
- Startup-mode unit tests cover serve mode, the provisioning command, root uid,
  invalid uid, missing input, unknown commands, and extra arguments.
- `mvm-agentd`'s full addon-enabled test suite and all mkGuest structure tests
  pass.
- Workspace Clippy passes with warnings denied; the Linux-gated all-target
  cross-check covers the Linux-only ownership handoff.
