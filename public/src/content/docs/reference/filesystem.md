---
title: Filesystem & Drives
description: Drive model, mount points, and filesystem layout inside microVMs.
---

## Drive Model

A microVM boots the universal initramfs; its guest agent mounts every drive.
The root is the one drive at a fixed slot:

| Drive | Mount Point | Permissions | Purpose |
|-------|-------------|-------------|---------|
| `/dev/vda` | `/` | Read-only (ext4 or squashfs) | Root filesystem |

Later slots are assigned per boot — the runtime overlay, the SDK sidecar and
the per-boot identity drive among them, named to the agent at activation — and
your own `--mount host:guest:SIZE` disk images take the slots after those.
There is no config drive, no secrets drive, no fixed `/dev/vdd` data drive and
no `/mnt/data` mount.

`/mnt/config` and `/mnt/secrets` stay reserved. The host mount policy refuses
any user share that sits inside or shadows them, and `/mnt` is not an allow-root
at all: **a user mount path must be under `/data` or `/work`.**

## Root Filesystem

The root drive is attached read-only, and the host never rewrites the image
behind it: the image is hashed when a launch is admitted, that digest is what the
signed plan records, and a cached image such as the default development rootfs
is shared by every later launch. An ext4 rootfs whose journal still needs replay
cannot be mounted from a read-only device, so it is refused before boot rather
than repaired in place — see
[Troubleshooting](/guides/troubleshooting/#refusing-to-boot--its-ext4-journal-needs-replay).

The rootfs is built by `mkGuest` and contains:

- **Busybox** — core utilities. The root carries no init: PID 1 is the
  initramfs agent
- **Mount points** — `/mvm/runtime` and `/mvm/sdk`, where the agent mounts the
  runtime overlay and the SDK sidecar
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
- The artifact is shared across microVMs from the local cache: under
  `~/.mvm/cache/runtime-overlay/<version>/<arch>/` when it was assembled at
  this CLI's version (from a source checkout's guest runtime, or a release
  binary's own signed one), or
  `~/.mvm/cache/image-set/<root-sha256>/runtime-overlay/<member-version>/<arch>/`
  when it came from the pinned image set.

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

## Config and secrets drives

No workload boot attaches a config drive or a secrets drive, and the guest
mounts nothing at `/mnt/config` or `/mnt/secrets`. Credentials reach a workload
through the host-side substitution endpoint as placeholders (see
[Secrets and credentials](/guides/secrets-and-credentials/)); files reach it
through `--mount` shares under `/data` or `/work`.

The `serviceGroup` argument to `mkGuest` does **not** affect file ownership. Like
`services` and `volumeMounts`, it is recorded in `passthru.mvm` and warned about
at eval time.

Raw secret *values* never reach the guest at all: mvm substitutes credentials
host-side at the per-VM egress endpoint.

## Persistent Disk Volumes

There is no built-in data drive. Persistent storage is a user disk volume: a
three-part `--mount` spec (`--volume` is an alias) whose third field is a size in
MB. The host path is an **ext4 disk image file** mvm creates and attaches as
virtio-blk — not a directory. A two-part spec is a host directory instead,
snapshotted into a read-only ext4 image when a transient run boots.

Volumes are **read-only unless you write `:rw`**, and the guest mount path must
be under `/data` or `/work`:

```bash
# 1 GB writable ext4 disk image, mounted at /data/store in the guest
mvmctl machine run --flake . --mount ./store.img:/data/store:1024:rw
```

A writable disk image is accepted under every profile that allows volumes —
`standard`, the default `dev`, and `--prod --profile standard` included —
because the guest writes into its own ext4 image file, never into the host
filesystem. A host *directory* is
different: a *transient* run's directory share is read-only under every
profile, and a persistent machine refuses a directory volume under every
profile, because it cannot attach a live host directory. Register a snapshot
with `mvmctl machine volume mount` to bring a directory into one.
`--profile restrictive` accepts no volume at all.

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

The shared guest-runtime overlay cache lives separately — under
`~/.mvm/cache/image-set/<root-sha256>/runtime-overlay/<member-version>/<arch>/` for the pinned image
set's member, `~/.mvm/cache/runtime-overlay/<version>/<arch>/` for an overlay
assembled from a guest runtime (a source build's, or a release binary's own) —
and contains the sealed
`overlay.ext4`, `overlay.verity`, `overlay.roothash`, `VERSION`, and
`checksums-sha256.txt` metadata reused by every VM that boots that runtime
version.
