---
title: Writing Nix Flakes
description: Create custom Nix flakes that build microVM images for mvm.
---

mvmctl uses Nix flakes to produce reproducible microVM images. Each build runs `nix build` inside the Linux environment (Lima VM on macOS, native on Linux), producing a kernel and rootfs. The same rootfs works on all backends (Firecracker, Apple Container).

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
| `serviceGroup` | Default service user/group name (default: `"mvm"`). Services run as this user; secrets are readable by this group. |
| `users.<name>.uid` | User ID (optional, auto-assigned from 1000) |
| `users.<name>.group` | Group name (optional, defaults to user name) |
| `users.<name>.home` | Home directory (optional, defaults to `/home/<name>`) |
| `services.<name>.command` | Long-running service command (supervised with respawn) |
| `services.<name>.preStart` | Optional setup script (runs as root before the service) |
| `services.<name>.env` | Optional environment variables (`{ KEY = "value"; }`) |
| `services.<name>.user` | User to run as (default: `serviceGroup`) |
| `services.<name>.logFile` | Optional log file path (default: `/dev/console`) |
| `healthChecks.<name>.healthCmd` | Health check command (exit 0 = healthy) |
| `healthChecks.<name>.healthIntervalSecs` | How often to run the check (default: 30) |
| `healthChecks.<name>.healthTimeoutSecs` | Timeout for each check (default: 10) |

## What mkGuest Provides

`mkGuest` handles everything automatically:

- **Firecracker kernel** (vmlinux) — tuned for microVM workloads
- **Busybox init** — sub-5s boot, no systemd overhead
- **Guest agent** — vsock-based health checks, status reporting, snapshot coordination
- **Networking** — eth0 configured via kernel boot args, NAT to host network
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

  # Run as a specific user (default: serviceGroup, which defaults to "mvm")
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
mvmctl logs <name>       # view guest console (includes health check results)
mvmctl logs <name> -f    # follow in real time
```

## Users

All services run as a built-in non-root user (default: `mvm`, uid 900) — never as root. Secrets at `/mnt/secrets` are owned by `root:<serviceGroup>` with mode `0440`, so only members of the service group can read them. Custom users are automatically added to this group.

To change the default service user/group name, set `serviceGroup`:

```nix
mvm.lib.${system}.mkGuest {
  name = "my-app";
  serviceGroup = "app";  # default: "mvm"
  # ...
};
```

To run a service as a custom user, define it in `users` and reference it in the service. The custom user is automatically added to the service group for secrets access:

```nix
users.app = {
  uid = 1000;
  group = "app";
  home = "/home/app";
};

services.my-app = {
  command = "${pkgs.nodejs}/bin/node /app/server.js";
  user = "app";  # overrides the default serviceGroup user
};
```

The `preStart` script always runs as root regardless of the `user` setting, so it can perform privileged setup like mounting filesystems or creating directories.

## Rootfs Types

By default, `mkGuest` produces an **ext4** rootfs. The build system also supports **squashfs** for smaller, read-only images (~76% smaller with LZ4 compression). When using squashfs, the init system mounts tmpfs overlays on `/etc` and `/var` automatically.

## Service Builder Helpers

The guest library provides high-level helpers that return a `{ package, service, healthCheck }` set. Compose them with `mkGuest`:

### mkPythonService

Build a Python HTTP service using `python3.withPackages` (nixpkgs packages only):

```nix
let
  pythonApp = mvm.lib.${system}.mkPythonService {
    name = "my-api";
    src = ./.;
    pythonPackages = ps: [ ps.flask ];
    entrypoint = "app/main.py";
    port = 8080;
    env = { WORKERS = "2"; };
  };
in
  mvm.lib.${system}.mkGuest {
    name = "my-api";
    packages = [ pythonApp.package ];
    services.app = pythonApp.service;
    healthChecks.app = pythonApp.healthCheck;
  };
```

### mkStaticSite

Serve static files with busybox httpd (zero extra packages):

```nix
let
  site = mvm.lib.${system}.mkStaticSite {
    name = "docs";
    src = ./public;
    port = 8080;
  };
in
  mvm.lib.${system}.mkGuest {
    name = "docs";
    packages = [ site.package ];
    services.www = site.service;
    healthChecks.www = site.healthCheck;
  };
```

### mkNodeService

Build a Node.js service with npm install + tsc:

```nix
let
  app = mvm.lib.${system}.mkNodeService {
    name = "my-app";
    src = fetchGit { url = "..."; rev = "..."; };
    npmHash = "sha256-...";
    entrypoint = "dist/index.js";
    port = 3000;
  };
in
  mvm.lib.${system}.mkGuest {
    name = "my-app";
    packages = [ app.package ];
    services.app = app.service;
    healthChecks.app = app.healthCheck;
  };
```

All three helpers return the same shape: `{ package, service, healthCheck }`. This makes it easy to swap between runtimes or compose multiple services in a single guest.

## Build Process

When you run `mvmctl build --flake .`:

1. The flake is copied into the Linux environment (Lima VM on macOS, native on Linux)
2. `nix build` runs inside that environment
3. The resulting closure is packed into the rootfs
4. Kernel and rootfs artifacts are cached
5. Subsequent builds with unchanged `flake.lock` reuse the cache

The same rootfs works on all backends (Firecracker, Apple Container, microvm.nix, Docker).

## Profiles

The `--profile` flag selects which Nix output to build:

```bash
mvmctl build --flake . --profile minimal
mvmctl build --flake . --profile gateway
```

These map to `packages.${system}.<profile>` in the flake.

## Running an LLM agent inside a microVM

[`nix/images/examples/llm-agent/`](https://github.com/auser/mvm/tree/main/nix/images/examples/llm-agent)
is a worked example that boots `claude-code` inside a Firecracker
microVM. It pulls the agent binary from
[`numtide/llm-agents.nix`](https://github.com/numtide/llm-agents.nix)
(binary cache at `cache.numtide.com`), runs it as a per-service uid
under `setpriv` with seccomp tier `network`, and reads the Anthropic
API key from `/run/mvm-secrets/claude-code/anthropic-api-key` so the
secret never enters the rootfs.

```bash
mkdir -p ~/.config/mvm/secrets
printf '%s\n' 'sk-ant-…' > ~/.config/mvm/secrets/anthropic
chmod 0400 ~/.config/mvm/secrets/anthropic

mvmctl template create claude-code-vm \
  --flake ./nix/images/examples/llm-agent \
  --profile minimal --role agent --cpus 2 --mem 1024
mvmctl template build claude-code-vm

mvmctl up --template claude-code-vm \
  --add-dir "$PWD:/workspace:rw" \
  --secret-file "$HOME/.config/mvm/secrets/anthropic:claude-code/anthropic-api-key"
```

Why a microVM and not a process sandbox: process sandboxes share the
host kernel and trust it. A microVM gives the agent its own kernel,
so a kernel exploit can't pivot to the host.

The example's full security composition (per-service uid, seccomp,
secrets mode, verified boot) is documented in the
[example README](https://github.com/auser/mvm/tree/main/nix/images/examples/llm-agent#readme)
and threat-modelled in
[ADR-002](https://github.com/auser/mvm/blob/main/specs/adrs/002-microvm-security-posture.md).
