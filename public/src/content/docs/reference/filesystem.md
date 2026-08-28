---
title: Filesystem & Drives
description: Drive model, mount points, and filesystem layout inside microVMs.
---

## Drive Model

A microVM built with `mkGuest` gets these virtio-block drives at fixed slots.
`/init` mounts the config and secret drives itself, before any user volume is
attached:

| Drive | Mount Point | Permissions | Purpose |
|-------|-------------|-------------|---------|
| `/dev/vda` | `/` | Read-write (ext4) or read-only (squashfs) | Root filesystem |
| `/dev/vdb` | `/mnt/config` | Read-only (`ro,noexec,nosuid,nodev`) | mvm instance metadata |
| `/dev/vdc` | `/mnt/secrets` | Read-only (`ro,noexec,nosuid,nodev`) | Runtime-delivered credentials |

There is no fixed `/dev/vdd` data drive and no `/mnt/data` mount. Later slots are
assigned dynamically — the runtime overlay and the SDK sidecar arrive as
`mvm.runtime_data=/dev/vdN` / `mvm.sdk_dev=/dev/vdN` on the kernel cmdline, and
your own `--mount host:guest:SIZE` disk images take the slots after those.

`/mnt/config` and `/mnt/secrets` are runtime-owned. The host mount policy refuses
any user share that sits inside or shadows them, and `/mnt` is not an allow-root
at all: **a user mount path must be under `/data` or `/work`.**

## Root Filesystem

The rootfs is built by `mkGuest` and contains:

- **Busybox** — init system, core utilities
- **Overlay-aware boot logic** — the `/init` path and `/mvm/runtime` mount point
  needed to bring the guest runtime online
- **Guest agent** — present directly in dev/preferred-overlay images; provided by
  the sealed runtime overlay on overlay-required boots
- **Your packages** — specified in the flake's `packages` parameter
- **The entrypoint** — rendered from the flake's required `entrypoint` parameter
- **Probe drop-ins** — one `/etc/mvm/probes.d/<name>.json` per `healthChecks.<name>` entry

`mkGuest` generates no service scripts: the top-level `services` attribute and
the `entrypoint.services` form are recorded but **not implemented** — the
multi-service supervisor is unwired, so nothing in the image starts or supervises
them.

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
  `~/.mvm/cache/runtime-overlay/<version>/<arch>/`.

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
- `/init` mounts it `ro,noexec,nosuid,nodev`
- Recreated on every start (never reused)

The `serviceGroup` argument to `mkGuest` does **not** affect this drive. Like
`services` and `volumeMounts`, it is recorded in `passthru.mvm` and warned about
at eval time; nothing re-owns or re-modes the secret files at boot.

The stronger property is that raw secret *values* never reach the guest at all:
mvm substitutes credentials host-side at the per-VM egress endpoint. See the
secrets guide rather than shipping values in on this drive.

## Persistent Disk Volumes

There is no built-in data drive. Persistent storage is a user disk volume: a
three-part `--mount` spec (`--volume` is an alias) whose third field is a size in
MB. The host path is an **ext4 disk image file** mvm creates and attaches as
virtio-blk — not a directory. A two-part spec is a live host-directory share over
virtio-fs instead.

Volumes are **read-only unless you write `:rw`**, and the guest mount path must
be under `/data` or `/work`:

```bash
# 1 GB writable ext4 disk image, mounted at /data/store in the guest
mvmctl machine run --flake . --mount ./store.img:/data/store:1024:rw
```

`:rw` requires `--profile dev` or `--profile permissive`. A *transient* run's
share is read-only under every profile.

For managed encrypted local volumes and workspace cleanup policy, see
[Persistent workspaces](/guides/persistent-workspaces/).

## Filesystem Layout

```
/                        # rootfs (ext4 or squashfs)
├── bin/                 # busybox symlinks
├── etc/
│   └── mvm/
│       ├── integrations.d/   # integration definitions (JSON); not written by mkGuest
│       └── probes.d/         # probe drop-ins (JSON) — where healthChecks land
├── init                 # busybox init script
├── mvm/
│   └── runtime/         # read-only runtime overlay mount point when attached
├── nix/store/           # Nix packages
├── mnt/                 # runtime-owned; not a user mount allow-root
│   ├── config/          # /dev/vdb (ro) — config drive
│   └── secrets/         # /dev/vdc (ro) — secrets drive
├── data/                # user mount allow-root
├── work/                # user mount allow-root
└── var/                 # runtime state (tmpfs on squashfs)
```

## Host-Side Layout

On the host (on Linux) or inside the builder VM (on macOS), mvm stores data at:

```
~/.mvm/                  # MVM_HOME
├── templates/
│   └── <name>/
│       └── revisions/
│           └── <hash>/
│               ├── vmlinux
│               ├── rootfs.ext4 (or rootfs.squashfs)
│               └── warm-meta.json (if warmed)
└── vms/
    └── <name>/
        ├── fc.pid              # Firecracker pid file (libkrun.pid / qemu.pid / hvf.pid for the others)
        ├── fc.socket           # Firecracker API socket
        ├── firecracker.log
        ├── console.log
        ├── run-info.json
        ├── vmlinux
        ├── rootfs.ext4
        ├── config.ext4
        ├── secrets.ext4
        └── runtime/
            └── v.sock          # per-VM Firecracker vsock UDS
```

Every backend shares this one per-VM directory with disjoint file names, so the
marker file (`fc.pid`, `libkrun.pid`, `qemu.pid`, `hvf.pid`) is what identifies
which VMM owns a running VM.

The shared guest-runtime overlay cache lives separately under
`~/.mvm/cache/runtime-overlay/<version>/<arch>/` and contains the sealed
`overlay.ext4`, `overlay.verity`, `overlay.roothash`, `VERSION`, and
`checksums-sha256.txt` metadata reused by every VM that boots that runtime
version.
