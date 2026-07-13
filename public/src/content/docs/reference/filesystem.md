---
title: Filesystem & Drives
description: Drive model, mount points, and filesystem layout inside microVMs.
---

## Drive Model

Each microVM gets up to four virtio-block drives on the supported workload
backends:

| Drive | Mount Point | Permissions | Purpose |
|-------|-------------|-------------|---------|
| `/dev/vda` | `/` | Read-write (ext4) or read-only (squashfs) | Root filesystem |
| `/dev/vdb` | `/mnt/config` | Read-only | Application configuration |
| `/dev/vdc` | `/mnt/secrets` | Read-only | API keys, tokens, credentials |
| `/dev/vdd` | `/mnt/data` | Read-write | Persistent data (survives restarts) |

## Root Filesystem

The rootfs is built by `mkGuest` and contains:

- **Busybox** — init system, core utilities
- **Overlay-aware boot logic** — the `/init` path and `/mvm/runtime` mount point
  needed to bring the guest runtime online
- **Guest agent** — present directly in dev/preferred-overlay images; provided by
  the sealed runtime overlay on overlay-required boots
- **Your packages** — specified in the flake's `packages` parameter
- **Service scripts** — generated from `services.<name>` definitions
- **Health check configs** — generated from `healthChecks.<name>`

### Runtime Overlay

Sealed workload boots can attach a second **read-only, verity-protected runtime
overlay** that is mounted inside the guest at `/mvm/runtime`.

- The overlay carries the guest runtime binaries such as `mvm-guest-agent`,
  `mvm-guest-netinit`, and `mvm-egress-client`.
- Only **guest-executed** runtime binaries belong in this artifact. Host-side
  helpers and bootstrap tools stay outside the overlay.
- The rootfs keeps the mount point and boot logic, but sealed
  `RequiredOverlay` images intentionally omit the baked fallback binaries.
- The overlay is **version-matched** to the running `mvmctl` build; mvm does
  not attach an arbitrary "latest" overlay.
- The overlay is mounted read-only in the guest. A backend that cannot provide
  that read-only contract must stay on the fallback policy instead of using
  `RequiredOverlay`.
- Before attach, mvm re-verifies the cached `overlay.ext4`, `overlay.verity`,
  `overlay.roothash`, and `VERSION` files against the recorded
  `checksums-sha256.txt` manifest and refuses the boot on any mismatch.
- The artifact is shared across microVMs from the local cache under
  `~/.cache/mvm/runtime-overlay/<version>/<arch>/`.

### Runtime updates

Runtime overlay updates are a **next-boot** operation:

- A stopped VM can pick up a newer version-matched overlay the next time it
  starts.
- A running VM keeps the overlay version it booted with until restart.
- mvm does **not** support hot-swapping or live-remounting a different runtime
  overlay into an already-running guest.

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
- Application config files from host directories you mounted yourself

Files are written with mode 0444 (world-readable, read-only mount).

## Secrets Drive

The secrets drive (`/dev/vdc`, mounted at `/mnt/secrets/`) contains sensitive data:

- `secrets.json` — tenant-level secrets
- Application secret files from host directories you mounted yourself

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
mvmctl machine run --flake . --volume ./data:/data:1024
```

For managed encrypted local volumes and workspace cleanup policy, see
[Persistent workspaces](/guides/persistent-workspaces/).

## Filesystem Layout

```
/                        # rootfs (ext4 or squashfs)
├── bin/                 # busybox symlinks
├── etc/
│   └── mvm/
│       ├── integrations.d/   # health check definitions (JSON)
│       └── probes.d/         # read-only probe definitions (JSON)
├── init                 # busybox init script
├── mvm/
│   └── runtime/         # read-only runtime overlay mount point when attached
├── nix/store/           # Nix packages
├── mnt/
│   ├── config/          # /dev/vdb (ro) — config drive
│   ├── secrets/         # /dev/vdc (ro) — secrets drive
│   └── data/            # /dev/vdd (rw) — data drive
└── var/                 # runtime state (tmpfs on squashfs)
```

## Host-Side Layout

On the host (on Linux) or inside the builder VM (on macOS), mvm stores data at:

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
        ├── runtime/
        │   └── v.sock          # per-VM Firecracker vsock UDS
        └── volumes/
            ├── config.ext4
            ├── secrets.ext4
            └── data.ext4
```

The shared guest-runtime overlay cache lives separately under
`~/.cache/mvm/runtime-overlay/<version>/<arch>/` and contains the sealed
`overlay.ext4`, `overlay.verity`, `overlay.roothash`, `VERSION`, and
`checksums-sha256.txt` metadata reused by every VM that boots that runtime
version.
