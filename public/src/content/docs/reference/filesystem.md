---
title: Filesystem & Drives
description: Drive model, mount points, and filesystem layout inside microVMs.
---

## Drive Model

Each Firecracker microVM gets up to four virtio-block drives:

| Drive | Mount Point | Permissions | Purpose |
|-------|-------------|-------------|---------|
| `/dev/vda` | `/` | Read-write (ext4) or read-only (squashfs) | Root filesystem |
| `/dev/vdb` | `/mnt/config` | Read-only | Application configuration |
| `/dev/vdc` | `/mnt/secrets` | Read-only | API keys, tokens, credentials |
| `/dev/vdd` | `/mnt/data` | Read-write | Persistent data (survives restarts) |

## Root Filesystem

The rootfs is built by `mkGuest` and contains:

- **Busybox** — init system, core utilities
- **Guest agent** — vsock communication daemon
- **Your packages** — specified in the flake's `packages` parameter
- **Service scripts** — generated from `services.<name>` definitions
- **Health check configs** — generated from `healthChecks.<name>`

### ext4 vs squashfs

| | ext4 | squashfs |
|---|------|----------|
| Read-write | Yes | No (tmpfs overlays on `/etc`, `/var`) |
| Size | Larger | ~76% smaller (LZ4 compression) |
| Agent injection | Supported | Not supported (read-only) |
| Boot time | Similar | Similar |

## Config Drive

The config drive (`/dev/vdb`, mounted at `/mnt/config/`) contains non-sensitive configuration:

- `config.json` — mvm instance metadata (name, role, resources)
- Application config files injected via `--config-dir`

Files are written with mode 0444 (world-readable, read-only mount).

## Secrets Drive

The secrets drive (`/dev/vdc`, mounted at `/mnt/secrets/`) contains sensitive data:

- `secrets.json` — tenant-level secrets
- Application secrets injected via `--secrets-dir`

Security hardening:
- Uses tmpfs-backed file (never hits persistent storage)
- Drive image files are 0400 (root-only); at boot, secrets are copied to a tmpfs with 0440 `root:<serviceGroup>` so only service group members can read them
- Mount with `ro,noexec,nodev,nosuid`
- Recreated on every start (never reused)

## Data Drive

The data drive (`/dev/vdd`, mounted at `/mnt/data/`) is a persistent ext4 volume:

- Created once per instance (specified size)
- Survives restarts and snapshots
- Use for application state, databases, logs

Specify size with `--volume`:

```bash
mvmctl run --flake . --volume ./data:/data:1024
```

## Filesystem Layout

```
/                        # rootfs (ext4 or squashfs)
├── bin/                 # busybox symlinks
├── etc/
│   └── mvm/
│       ├── integrations.d/   # health check definitions (JSON)
│       └── probes.d/         # read-only probe definitions (JSON)
├── init                 # busybox init script
├── nix/store/           # Nix packages
├── mnt/
│   ├── config/          # /dev/vdb (ro) — config drive
│   ├── secrets/         # /dev/vdc (ro) — secrets drive
│   └── data/            # /dev/vdd (rw) — data drive
└── var/                 # runtime state (tmpfs on squashfs)
```

## Host-Side Layout

On the host (inside the Lima VM), mvm stores data at:

```
~/.mvm/                  # MVM_DATA_DIR
├── templates/
│   └── <name>/
│       └── revisions/
│           └── <hash>/
│               ├── vmlinux
│               ├── rootfs.ext4 (or rootfs.squashfs)
│               └── warm-meta.json (if warmed)
└── vms/
    └── <name>/
        ├── firecracker.pid
        ├── firecracker.socket
        ├── firecracker.log
        ├── console.log
        ├── fc-base.json
        ├── vmlinux
        ├── rootfs.ext4
        └── volumes/
            ├── config.ext4
            ├── secrets.ext4
            └── data.ext4
```
