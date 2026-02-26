# User Guide: Writing Nix Flakes for mvm

This guide explains how to create custom Nix flakes that build microVM images for mvm worker pools.

## Overview

mvm uses Nix flakes to produce reproducible microVM images. Each pool references a flake and a profile. The build process runs inside an ephemeral Firecracker VM with Nix installed, producing a root filesystem and kernel.

## Flake Structure

A minimal mvm-compatible flake:

```nix
{
  description = "My mvm worker image";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";
  };

  outputs = { self, nixpkgs }: let
    system = "x86_64-linux";
    pkgs = nixpkgs.legacyPackages.${system};
  in {
    packages.${system} = {
      minimal = pkgs.buildEnv {
        name = "mvm-minimal";
        paths = with pkgs; [ busybox curl ];
      };

      baseline = pkgs.buildEnv {
        name = "mvm-baseline";
        paths = with pkgs; [ bash coreutils curl wget openssl ];
      };

      python = pkgs.buildEnv {
        name = "mvm-python";
        paths = with pkgs; [ python3 python3Packages.pip bash coreutils ];
      };
    };
  };
}
```

## Profiles

Profiles are named outputs within your flake. When you create a pool:

```bash
mvmctl pool create acme/workers --flake ./my-flake --profile baseline --cpus 2 --mem 1024
```

mvm builds the `baseline` output from `./my-flake`.

### Built-in Profiles

- **minimal** -- BusyBox + curl. Smallest image, fastest boot.
- **baseline** -- Standard shell utilities. Good for general workloads.
- **python** -- Python 3 + pip. For scripting and ML workloads.

## Build Process

When you run `mvmctl pool build <tenant>/<pool>`:

1. An ephemeral builder microVM starts with Nix pre-installed
2. The flake is copied into the builder VM
3. `nix build .#<profile>` runs inside the builder
4. The resulting closure is packed into an ext4 root filesystem
5. A revision hash is computed and stored
6. The `current` symlink is updated atomically

## Adding Services

To run services at boot, include systemd units in your flake:

```nix
baseline = pkgs.buildEnv {
  name = "mvm-baseline";
  paths = with pkgs; [
    bash coreutils curl
    (pkgs.writeTextDir "etc/systemd/system/my-app.service" ''
      [Unit]
      Description=My Application
      After=network.target

      [Service]
      ExecStart=/usr/bin/my-app
      Restart=always

      [Install]
      WantedBy=multi-user.target
    '')
  ];
};
```

## Data Disks

Pools can provision data disks per instance:

```bash
mvmctl pool create acme/workers --flake . --profile baseline --cpus 2 --mem 1024 --data-disk 1024
```

This creates a 1 GiB ext4 data disk mounted at `/data` inside each instance.

## Secrets

Tenant-level secrets are injected into instances via a read-only virtio block device mounted at `/run/secrets/`:

```bash
mvmctl tenant secrets set acme --from-file secrets.json
```

Inside the instance, access secrets at `/run/secrets/secrets.json`.

## Scaling

After building, scale the pool:

```bash
mvmctl pool scale acme/workers --running 4 --warm 2 --sleeping 2
```

- **Running** -- actively serving, full CPU
- **Warm** -- vCPUs paused, instant resume
- **Sleeping** -- snapshotted to disk, ~1s wake

## Updating Images

To deploy a new version:

1. Modify your flake
2. Re-build: `mvmctl pool build acme/workers`
3. New instances use the updated revision automatically
4. Existing running instances continue on the old revision until restarted

## Rollback

If a new revision is broken:

```bash
mvmctl pool rollback acme/workers --revision <hash>
```

This updates the `current` symlink without rebuilding.

---

## Templates

Templates are global, tenant-agnostic base images stored under `~/.mvm/templates/` (override with `MVM_DATA_DIR`). They let you build once and share artifacts across multiple pools.

### Scaffold a Template Project

```bash
mvmctl template init my-app --local
```

Creates a minimal directory with a Nix flake:

```
my-app/
  flake.nix     # NixOS microvm flake (edit to customize)
  .gitignore
  README.md
```

The scaffold is intentionally minimal. Add extra NixOS modules, role configs, or guest agent integration as needed.

### Create and Build

Register a single template:

```bash
mvmctl template create my-worker --flake ./my-app --profile minimal --role worker --cpus 2 --mem 1024
mvmctl template build my-worker
```

Or create multiple role variants at once:

```bash
mvmctl template create-multi my-app --flake ./my-app --profile minimal --roles gateway,worker --cpus 2 --mem 1024
mvmctl template build my-app-gateway
mvmctl template build my-app-worker
```

### Config-Driven Multi-Variant Builds

Define all variants in a `template.toml`:

```toml
[template]
template_id = "my-app"
flake_ref = "."
profile = "minimal"

[[variants]]
name = "my-app-gateway"
role = "gateway"
profile = "gateway"
vcpus = 4
mem_mib = 2048
data_disk_mib = 0

[[variants]]
name = "my-app-worker"
role = "worker"
profile = "minimal"
vcpus = 2
mem_mib = 1024
data_disk_mib = 512
```

Build all variants:

```bash
mvmctl template build my-app --config template.toml
```

### Inspect Templates

```bash
mvmctl template list              # show all templates (VM + local)
mvmctl template list --json       # JSON output
mvmctl template info my-worker    # show template details
mvmctl template info my-worker --json
```

### Delete

```bash
mvmctl template delete my-worker
mvmctl template delete my-worker --force   # skip confirmation
```

### Template Registry (Push / Pull / Verify)

Templates can be shared via S3-compatible object storage (AWS S3 or MinIO).

Configure the registry with environment variables:

```bash
export MVM_TEMPLATE_REGISTRY_ENDPOINT="https://s3.amazonaws.com"
export MVM_TEMPLATE_REGISTRY_BUCKET="mvm-templates"
export MVM_TEMPLATE_REGISTRY_ACCESS_KEY_ID="..."
export MVM_TEMPLATE_REGISTRY_SECRET_ACCESS_KEY="..."
export MVM_TEMPLATE_REGISTRY_REGION="us-east-1"          # default
export MVM_TEMPLATE_REGISTRY_PREFIX="mvm"                 # default
export MVM_TEMPLATE_REGISTRY_INSECURE="false"             # allow http://
```

Push, pull, and verify:

```bash
mvmctl template push my-worker                  # push current revision
mvmctl template push my-worker --revision abc123 # push specific revision
mvmctl template pull my-worker                  # pull latest from registry
mvmctl template verify my-worker                # verify local checksums
```

Push/pull/verify must run inside the Linux VM on macOS (`mvmctl shell`, then rerun).

### Cache Keys

Each template revision records a composite cache key: `SHA256(flake.lock hash + profile + role)`. When a pool references a template, the pool build checks this cache key. If it matches, artifacts are reused without rebuilding.

### Pool Integration

When creating a pool, set `--template` to link it to a template:

```bash
mvmctl pool create acme/workers --template my-worker --flake . --profile minimal --cpus 2 --mem 1024
```

On `mvmctl pool build acme/workers`, if the template's cache key matches (same flake.lock, profile, and role), artifacts are copied from the template -- no per-tenant rebuild needed. Use `--force` to bypass the cache.
