# MVM Nix Development Best Practices

You are working in the `mvm` repository.

MVM is a Rust-based microVM manager for reproducible, isolated tenant runtimes using Nix, Lima, Firecracker, QEMU, NixOS images, TAP networking, snapshots, and host/runtime provisioning.

When adding or modifying Nix code, follow these rules.

## Core Principle

Use Nix for reproducible development, builds, packages, checks, tools, and image generation.

Do not use Nix dev shells to mutate the host.

The dev shell may expose tools and print diagnostics, but it must not perform privileged host setup.

## Hard Rules

- Use flakes as the canonical entrypoint.
- Keep `flake.lock` committed.
- Support `nix develop`, `nix build`, `nix run`, and `nix flake check`.
- Prefer explicit, readable Nix over clever Nix.
- Do not use top-level `with pkgs;`.
- Do not use `rec` unless there is a clear reason.
- Do not use `<nixpkgs>`.
- Do not rely on `$NIX_PATH`.
- Always quote URLs.
- Explicitly set `config = {}` and `overlays = []` when importing nixpkgs unless overlays are intentionally passed.
- Use `builtins.path { path = ./.; name = "mvm-source"; }` for reproducible source paths where applicable.
- Keep host setup separate from development shells.
- Never put `sudo`, `chown`, `chgrp`, `chmod`, `groupadd`, `usermod`, `ip link`, `iptables`, `nft`, `systemctl`, or bridge/TAP mutations in `flake.nix`, `devShells`, or `shellHook`.

## Host Mutation Boundary

These actions must not happen automatically from `nix develop`:

- creating `/var/lib/mvm`
- changing ownership of runtime directories
- changing `/dev/kvm` permissions
- adding users to groups
- creating TAP devices
- creating bridges
- changing firewall/NAT rules
- installing systemd units
- enabling services
- modifying host kernel settings

If host setup is needed, place it in explicit reviewed files:

- `ops/bootstrap/`
- `ops/systemd/`
- `ops/networking/`
- `ops/permissions/`
- `specs/adrs/`

The dev shell may print a warning like:

/dev/kvm is not accessible. Run the documented host bootstrap step.

But it must not fix it automatically.

## Recommended Repo Layout

Use this structure:

.
├── flake.nix
├── flake.lock
├── nix/
│   ├── packages/
│   ├── devshells/
│   ├── checks/
│   ├── apps/
│   ├── overlays/
│   ├── modules/
│   ├── images/
│   └── lib/
├── ops/
│   ├── bootstrap/
│   ├── networking/
│   ├── permissions/
│   └── systemd/
├── crates/
├── tests/
├── specs/
└── Justfile

## Flake Outputs Required

Expose these outputs where appropriate:

- packages.${system}.mvm
- packages.${system}.default
- apps.${system}.mvm
- apps.${system}.default
- devShells.${system}.default
- checks.${system}.default
- formatter.${system}
- nixosModules.default if MVM provides host/runtime modules
- overlays.default only if downstream users need MVM packages

## Systems

Support at least:

x86_64-linux
aarch64-linux
aarch64-darwin

Rules:

- Linux is the production target.
- Darwin/macOS is a development target.
- Firecracker/KVM features may be Linux-only.
- macOS dev shells may include Lima/QEMU tooling, but must not pretend KVM-only features work locally.

## Dev Shell Rules

The dev shell should include only tools needed to develop MVM:

- Rust toolchain
- cargo
- rustfmt
- clippy
- rust-analyzer
- pkg-config
- openssl
- qemu
- firecracker tooling where available
- lima where available
- jq
- just
- git
- nix tooling
- tap/network inspection tools where available

The shell hook may:

- print tool versions
- print MVM-specific diagnostics
- warn about missing `/dev/kvm`
- warn about unsupported OS features
- point to bootstrap documentation

The shell hook must not:

- mutate host permissions
- create runtime directories
- install services
- start daemons
- change networking
- run privileged commands

## Final Instruction

When implementing Nix for MVM, optimize for:

- reproducibility
- explicitness
- host safety
- Linux production correctness
- macOS developer ergonomics
- clean separation of tools vs host provisioning
- no hidden privileged side effects
