# mvm-net

`mvm-net` defines the backend-neutral network provisioning and enforcement
seams for one machine. It owns traits and typed handles, not TAP creation,
firewall commands, or a particular mesh implementation.

## Who uses it

`mvm-backends`, `mvm-vmm` and `mvm-runtime` use its typed guest-service
surface. `mvm-build` implements the provider contract for builder networking. Fleet orchestrators can register a
custom WireGuard or Tailscale provider without changing this crate.

## How it works

`NetworkSpec` describes the admitted network request. A `NetworkProvider`
provisions that request and returns a `NetHandle` containing the identity and
resources required for later policy application and teardown. Providers are
registered by mode in `NetworkProviderRegistry`, allowing selection without
scattered backend matches.

Provisioning does not imply authorization: the default network policy comes
from `mvm-core` and denies traffic until an admitted policy is applied; egress
is enforced by the per-VM network endpoint, not by this crate. `GuestService` describes typed services carried over guest vsock
rather than opening untracked listeners.

## Main modules

| Module | Responsibility |
|---|---|
| `provider` | `NetworkProvider`, `NetworkSpec`, `NetHandle`, and errors |
| `registry` | Provider registration and lookup |
| `channel` | Backend-neutral guest service definitions |

## Design boundaries

The crate has no shell runner and performs no host mutation. Linux bridge/TAP
mechanics, packet observers, proxying, and fleet mesh setup live in concrete
implementations. Durable policy and protocol DTOs remain in `mvm-contract` and
`mvm-core` so all providers interpret the same admitted data.

## Developing

Run `cargo test -p mvm-net`. Trait changes must be exercised by every provider
implementation and should preserve teardown after partial provisioning
failures. Policy-related changes require both allow and deny tests.
