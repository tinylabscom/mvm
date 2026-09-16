# `ops/` — host-side operational scripts

Per the [`mvm-nix-best-practices` guide](../../specs/references/mvm-nix-best-practices.md),
**any script that mutates host state lives here**, not in `nix/`,
`devShells`, `shellHook`, or arbitrary places under `scripts/`.

The dividing line is whether the script changes something *outside its
own working directory*: filesystem permissions on system paths, group
membership, network interfaces, firewall rules, systemd units,
`/dev/kvm` accessibility, etc.

| Subdir | Purpose | When to run |
|---|---|---|
| [`bootstrap/`](bootstrap/) | First-time setup — system build dependencies and the Rust toolchain for a source checkout. | Once, manually, before the first `cargo build`. |
| [`permissions/`](permissions/) | One-shot privilege grants — `/dev/kvm` access, group membership. | Once per host, manually, with explicit sudo. |
| [`systemd/`](systemd/) | mvm systemd unit installation (Linux production hosts). | When deploying mvm as a managed service. |
| [`hetzner/`](hetzner/) | Cloud-init for a Hetzner test box (Linux+KVM) running the full workspace suite. | Ad hoc, when a macOS host isn't enough (live Firecracker, longer fuzz). |

Every script in `ops/` MUST have a header listing:
- What host state it changes
- Why elevated privileges are required
- Whether it's idempotent

There is no host network setup to script. Workload microVMs boot without a
NIC and their egress leaves over vsock to a per-VM host endpoint, so `mvmctl`
creates no host bridge, TAP device, or firewall rule.

Nothing invokes these scripts automatically — not `mvmctl`, not a flake
output. A contributor runs each one by hand.
