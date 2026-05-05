# `ops/` — host-side operational scripts

Per the [`mvm-nix-best-practices` guide](../specs/references/mvm-nix-best-practices.md),
**any script that mutates host state lives here**, not in `nix/`,
`devShells`, `shellHook`, or arbitrary places under `scripts/`.

The dividing line is whether the script changes something *outside its
own working directory*: filesystem permissions on system paths, group
membership, network interfaces, firewall rules, systemd units,
`/dev/kvm` accessibility, etc.

| Subdir | Purpose | When to run |
|---|---|---|
| [`bootstrap/`](bootstrap/) | First-time setup — install Lima, Homebrew, etc. | Once, manually, before `mvmctl dev up`. |
| [`permissions/`](permissions/) | One-shot privilege grants — `/dev/kvm` access, group membership. | Once per host, manually, with explicit sudo. |
| [`networking/`](networking/) | Bridge / TAP / iptables setup if not done by mvmctl. | Strict-mode pre-condition; otherwise mvmctl handles inline. |
| [`systemd/`](systemd/) | mvm systemd unit installation (Linux production hosts). | When deploying mvm as a managed service. |
| [`hetzner/`](hetzner/) | Cloud-init for a Hetzner test box (Linux+KVM) running the full workspace suite. | Per-PR or ad hoc, when Lima on macOS isn't enough (live Firecracker, longer fuzz). |

Every script in `ops/` MUST have a header listing:
- What host state it changes
- Why elevated privileges are required
- Whether it's idempotent

`mvmctl` itself **does not invoke these scripts automatically**. The
shell hook in `nix/devshells/host.nix` may *point* a contributor at
the right script, but it never runs one.
