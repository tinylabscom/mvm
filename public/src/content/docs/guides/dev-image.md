---
title: Dev Image
description: How the dev image works, how to customize it, and how to rebuild it.
---

The **dev image** is a minimal Linux VM image (kernel + ext4 rootfs) used by `mvmctl dev` to provide a build environment. It contains Nix, Git, GCC, Cargo, and other tools needed to build microVM images.

## How it works

When you run `mvmctl dev up`, the CLI:

1. Checks `~/.cache/mvm/dev/` for cached `vmlinux` and `rootfs.ext4`
2. If missing, builds the image from `nix/dev-image/flake.nix` (requires Nix with a Linux builder)
3. If Nix build fails (e.g. no Linux builder on macOS), downloads a pre-built image from the matching GitHub release

The dev image is built using the same `mkGuest` helper that builds all microVM images, so it follows the same conventions (busybox init, vsock communication, no SSH).

## Customizing the dev image

The dev image flake lives at [`nix/dev-image/flake.nix`](https://github.com/auser/mvm/blob/main/nix/dev-image/flake.nix). It imports the parent flake at `nix/` and calls `mkGuest` with a list of packages.

### Adding packages

Edit the `packages` list in `nix/dev-image/flake.nix`:

```nix
packages = [
  # ... existing packages ...

  # Add your packages here
  pkgs.jq
  pkgs.ripgrep
  pkgs.python3
];
```

Any package available in [nixpkgs](https://search.nixos.org/packages) can be added.

### Adding services

To run a service inside the dev image, add a `services` block:

```nix
mvm.lib.${system}.mkGuest {
  name = "mvm-dev";
  hostname = "mvm-dev";

  packages = [ ... ];

  services.my-daemon = {
    command = "${pkgs.somePackage}/bin/daemon --flag";
  };
};
```

See the [Nix Flakes guide](/guides/nix-flakes) for the full `mkGuest` API.

## Building the dev image locally

### Prerequisites

- **Nix** installed on the host
- **Linux builder** configured (required on macOS since the image targets Linux)

### Build

```bash
# Build for the current architecture
nix build ./nix/dev-image

# Build for a specific architecture
nix build ./nix/dev-image#packages.aarch64-linux.default
nix build ./nix/dev-image#packages.x86_64-linux.default
```

The output is a Nix store path containing `vmlinux` (kernel) and `rootfs.ext4` (root filesystem).

### Force a rebuild

The CLI caches the dev image at `~/.cache/mvm/dev/`. To force a rebuild after modifying the flake:

```bash
# Remove the cached image
rm -rf ~/.cache/mvm/dev/

# Rebuild on next dev up
mvmctl dev up
```

Or copy the built artifacts directly:

```bash
STORE_PATH=$(nix build ./nix/dev-image --no-link --print-out-paths)
mkdir -p ~/.cache/mvm/dev
cp "$STORE_PATH/vmlinux" ~/.cache/mvm/dev/
cp "$STORE_PATH/rootfs.ext4" ~/.cache/mvm/dev/
```

### macOS: setting up a Linux builder

macOS cannot build Linux images natively. You need a Linux builder for Nix:

**Option 1 -- Temporary** (run in a separate terminal):

```bash
nix run 'nixpkgs#darwin.linux-builder'
```

**Option 2 -- Permanent** (add to `/etc/nix/nix.conf`):

```
builders = ssh-ng://builder@linux-builder aarch64-linux /etc/nix/builder_ed25519 4 1 kvm,big-parallel - -
builders-use-substitutes = true
```

Then restart the Nix daemon:

```bash
sudo launchctl kickstart -k system/org.nixos.nix-daemon
```

## CI builds

The release workflow (`.github/workflows/release.yml`) builds dev images for both `aarch64-linux` and `x86_64-linux` on native runners. The resulting `dev-vmlinux-{arch}` and `dev-rootfs-{arch}.ext4` artifacts are uploaded to each GitHub Release. This is the fallback source when local Nix builds aren't available.

## Flake structure

```
nix/
├── flake.nix                    # Parent flake — defines mkGuest (production)
├── firecracker-kernel-pkg.nix
├── minimal-init.nix
├── guest-agent-pkg.nix
├── dev/                         # Sibling flake — dev variant of mkGuest
│   └── flake.nix
└── dev-image/                   # Dev environment image
    ├── flake.nix                # Calls mkGuest with dev tools
    └── flake.lock
```

The dev image flake references the parent via a relative path (`mvm.url = "path:.."`), so changes to the kernel or init system are picked up automatically on the next build.
