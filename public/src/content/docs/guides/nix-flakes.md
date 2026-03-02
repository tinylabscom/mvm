---
title: Writing Nix Flakes
description: Create custom Nix flakes that build microVM images for mvm.
---

mvm uses Nix flakes to produce reproducible microVM images. Each build runs `nix build` inside the Lima VM, producing a kernel and rootfs.

## Minimal Flake

```nix
{
  inputs = {
    mvm.url = "github:auser/mvm?dir=nix";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
  };

  outputs = { mvm, nixpkgs, ... }:
    let
      system = "aarch64-linux";
      pkgs = import nixpkgs { inherit system; };
    in {
      packages.${system}.default = mvm.lib.${system}.mkGuest {
        name = "my-app";
        packages = [ pkgs.curl ];

        services.my-app = {
          command = "${pkgs.python3}/bin/python3 -m http.server 8080";
        };

        healthChecks.my-app = {
          healthCmd = "${pkgs.curl}/bin/curl -sf http://localhost:8080/";
          healthIntervalSecs = 5;
        };
      };
    };
}
```

## mkGuest API

| Parameter | Description |
|-----------|-------------|
| `name` | VM name (used in image filename) |
| `packages` | Nix packages to include in the rootfs |
| `hostname` | Guest hostname (default: same as `name`) |
| `users.<name>.uid` | User ID (optional, auto-assigned from 1000) |
| `users.<name>.group` | Group name (optional, defaults to user name) |
| `users.<name>.home` | Home directory (optional, defaults to `/home/<name>`) |
| `services.<name>.command` | Long-running service command (supervised with respawn) |
| `services.<name>.preStart` | Optional setup script (runs as root before the service) |
| `services.<name>.env` | Optional environment variables (`{ KEY = "value"; }`) |
| `services.<name>.user` | Optional user to run as (must exist in `users`) |
| `services.<name>.logFile` | Optional log file path (default: `/dev/console`) |
| `healthChecks.<name>.healthCmd` | Health check command (exit 0 = healthy) |
| `healthChecks.<name>.healthIntervalSecs` | How often to run the check (default: 30) |
| `healthChecks.<name>.healthTimeoutSecs` | Timeout for each check (default: 10) |

## What mkGuest Provides

`mkGuest` handles everything automatically:

- **Firecracker kernel** (vmlinux) — tuned for microVM workloads
- **Busybox init** — sub-5s boot, no systemd overhead
- **Guest agent** — vsock-based health checks, status reporting, snapshot coordination
- **Networking** — eth0 configured via kernel boot args, NAT through Lima
- **Drive mounting** — `/mnt/config` (ro), `/mnt/secrets` (ro), `/mnt/data` (rw)
- **Service supervision** — automatic restart on failure with backoff

## Adding Services

Services defined in `services.<name>` are supervised by the init system:

```nix
services.my-app = {
  # Setup (runs once as root before the service starts)
  preStart = "mkdir -p /tmp/data";

  # Long-running process (supervised, auto-restart on failure)
  command = "${pkgs.nodejs}/bin/node /app/server.js";

  # Environment variables
  env = {
    PORT = "8080";
    NODE_ENV = "production";
  };

  # Run as a specific user (must be defined in users)
  user = "app";

  # Log to a file instead of console
  logFile = "/var/log/my-app.log";
};
```

## Health Checks

Health checks defined in `healthChecks` are automatically written to `/etc/mvm/integrations.d/` at build time. The guest agent picks them up on boot:

```nix
healthChecks.my-app = {
  healthCmd = "${pkgs.curl}/bin/curl -sf http://localhost:8080/health";
  healthIntervalSecs = 10;
  healthTimeoutSecs = 5;
};
```

Query health status from the host:

```bash
mvmctl vm status
mvmctl vm inspect <name>
```

## Custom Users

```nix
users.app = {
  uid = 1000;
  group = "app";
  home = "/home/app";
};

services.my-app = {
  command = "${pkgs.nodejs}/bin/node /app/server.js";
  user = "app";
};
```

## Rootfs Types

By default, `mkGuest` produces an ext4 rootfs. For smaller images, use squashfs:

```nix
mvm.lib.${system}.mkGuest {
  name = "my-app";
  rootfsType = "squashfs";  # LZ4-compressed, ~76% smaller
  # ...
};
```

Squashfs images are read-only — the init system mounts tmpfs overlays on `/etc` and `/var` automatically.

## Build Process

When you run `mvmctl build --flake .`:

1. The flake is copied into the Lima VM
2. `nix build` runs inside the Lima VM
3. The resulting closure is packed into the rootfs
4. Kernel and rootfs artifacts are cached
5. Subsequent builds with unchanged `flake.lock` reuse the cache

## Profiles

The `--profile` flag selects which Nix output to build:

```bash
mvmctl build --flake . --profile minimal
mvmctl build --flake . --profile gateway
```

These map to `packages.${system}.<profile>` in the flake.
