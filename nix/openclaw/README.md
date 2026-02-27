# OpenClaw — mvm microVM Template

A multi-tenant microVM template for the OpenClaw platform. Builds NixOS-based
Firecracker guests that receive per-tenant configuration at runtime via mvm's
config and secrets drives.

## Architecture

```
┌─────────────────────────────────────────────────┐
│  Firecracker microVM (same image per role)      │
│                                                 │
│  /mnt/config/   ← mvm config drive (read-only) │
│    config.json     instance metadata            │
│    gateway.toml    app config for this tenant   │
│    gateway.env     env overrides                │
│                                                 │
│  /mnt/secrets/  ← mvm secrets drive (read-only) │
│    secrets.json    tenant secrets               │
│    gateway-secrets.env  app secrets             │
│                                                 │
│  /mnt/data/     ← mvm data drive (read-write)  │
│    (persistent storage, optional)               │
│                                                 │
│  systemd → openclaw-gateway (or worker)         │
│    reads config from /mnt/config                │
│    reads secrets from /mnt/secrets              │
└─────────────────────────────────────────────────┘
```

Drives are mounted by device path (`/dev/vdb`, `/dev/vdc`, `/dev/vdd`),
not by filesystem label, because the minimal initrd
(`includeDefaultModules = false`) doesn't include the udev rules that
create `/dev/disk/by-label/` symlinks. Firecracker drive ordering is
deterministic, so device paths are stable.

## Variants

| Name               | Role    | vCPUs | Memory | Data Disk |
| ------------------ | ------- | ----- | ------ | --------- |
| `openclaw-gateway` | gateway | 2     | 1 GiB  | none      |
| `openclaw-worker`  | worker  | 2     | 2 GiB  | 2 GiB     |

## Build

Build with mvmctl (from repo root):

```bash
mvmctl template build openclaw
```

Or directly with Nix:

```bash
cd nix/openclaw
nix build .#tenant-gateway
nix build .#tenant-worker
```

Each output contains `vmlinux` (kernel) and `rootfs.ext4` (root filesystem)
ready for Firecracker.

## Usage

Fleet orchestration commands (tenants, pools, scaling) live in [mvmd](https://github.com/auser/mvmd):

```bash
# Create tenant with network isolation
mvmd tenant create acme --net-id 3 --subnet 10.240.3.0/24

# Create pools from template
mvmd pool create acme/gateways --template openclaw --role gateway
mvmd pool create acme/workers --template openclaw --role worker

# Build (one image per role, shared across all tenants)
mvmd pool build acme/gateways
mvmd pool build acme/workers

# Scale — each instance gets its own config/secrets drives
mvmd pool scale acme/workers --running 5
```

## File Structure

```
nix/openclaw/
├── flake.nix              Nix flake: builds vmlinux + rootfs.ext4 per role
├── mvm-profiles.toml      Profile/role → NixOS module mapping (consumed by mvm)
├── template.toml          mvm template metadata (variants, resources)
├── pkgs/
│   └── openclaw.nix       OpenClaw Node.js gateway package derivation
└── roles/
    ├── common.nix         Shared config (user, tmpfs, init service) — parameterized
    ├── gateway.nix        Gateway systemd service (reads /mnt/config, /mnt/secrets)
    └── worker.nix         Worker systemd service (reads /mnt/config, /mnt/secrets)
```
