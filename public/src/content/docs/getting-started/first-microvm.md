---
title: Your First MicroVM
description: Write a Nix flake and boot a Firecracker microVM.
---

This guide walks through writing a Nix flake that builds a microVM image, then booting it with mvm.

## Understanding the Layers

mvm runs a three-layer stack (Lima is only used when KVM isn't available natively):

```
Your macOS/Linux Host
  └── Lima VM (only on macOS or Linux without /dev/kvm)
        └── Firecracker microVM (your workload)
```

| Layer | Access command | Has your project files? |
|-------|---------------|------------------------|
| Host | Your normal terminal | Yes |
| Lima VM | `mvmctl dev` or `mvmctl shell` | Yes (~ mounted read/write) |
| Firecracker microVM | (headless, no SSH) | No (isolated filesystem) |

Firecracker microVMs are **headless workloads** with no SSH access — they communicate via vsock only.

:::note
On Linux with `/dev/kvm`, the Lima layer is skipped entirely — the host IS the Linux environment. `mvmctl dev` drops you into a native dev shell instead.
:::

## Write a Flake

Create a `flake.nix` in your project:

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
        name = "hello";
        packages = [ pkgs.curl ];

        services.hello = {
          command = "${pkgs.python3}/bin/python3 -m http.server 8080";
        };

        healthChecks.hello = {
          healthCmd = "${pkgs.curl}/bin/curl -sf http://localhost:8080/";
          healthIntervalSecs = 5;
          healthTimeoutSecs = 3;
        };
      };
    };
}
```

`mkGuest` handles everything internally — the Firecracker kernel, busybox init, guest agent, networking, drive mounting, and service supervision are all built into the image automatically. You just define your services and health checks.

## Build and Run

```bash
# Build the image (runs nix build inside the Lima VM)
mvmctl build --flake .

# Boot a headless Firecracker VM
mvmctl run --flake . --cpus 2 --memory 1024
```

## Check Health

```bash
# Ping the guest agent
mvmctl vm ping

# Query health check status
mvmctl vm status
```

## Run with Config and Secrets

Pass custom files to the guest drives:

```bash
mkdir -p /tmp/config /tmp/secrets
echo '{"port": 8080}' > /tmp/config/app.json
echo 'API_KEY=sk-...' > /tmp/secrets/app.env

mvmctl run --flake . \
    --config-dir /tmp/config \
    --secrets-dir /tmp/secrets
```

Inside the guest, config files appear at `/mnt/config/` and secrets at `/mnt/secrets/`.

## Stop

```bash
mvmctl stop
```

## Next Steps

- [Writing Nix Flakes](/guides/nix-flakes/) — the full `mkGuest` API
- [Templates](/guides/templates/) — build once, reuse everywhere
- [Config & Secrets](/guides/config-secrets/) — inject files at boot
