---
title: Templates
description: Build reusable microVM images and share them via a registry.
---

Templates are reusable microVM images built from Nix flakes. Build once, run anywhere. Share via an S3-compatible registry.

## Scaffold a Template

```bash
mvmctl template init my-service --local
```

Creates a minimal directory:

```
my-service/
├── flake.nix       # Nix flake via mkGuest
├── .gitignore
└── README.md
```

## From an Existing Flake

If you already have a Nix flake, register it directly:

```bash
mvmctl template create openclaw --flake ../openclaw --profile minimal --role worker
mvmctl template build openclaw
```

All flags have defaults: `--flake .`, `--profile default`, `--role worker`, `--cpus 2`, `--mem 1024`. Local flake paths are resolved to absolute paths at creation time.

## Build

```bash
mvmctl template build my-service
mvmctl template build my-service --force    # Rebuild even if cached
```

Builds run `nix build` inside the Lima VM to produce kernel + rootfs artifacts.

## Snapshots

Build with `--snapshot` to capture a fully booted, healthy VM state. Subsequent runs restore from this snapshot instead of cold-booting — sub-second startup instead of minutes.

```bash
# Build + snapshot (one-time, waits for all services to be healthy)
mvmctl template build my-service --snapshot

# Every subsequent run auto-detects the snapshot and restores instantly:
mvmctl run --template my-service --name svc
```

The snapshot process:
1. Builds the template normally (`nix build`)
2. Boots a temporary VM from the built artifacts
3. Waits for the guest agent to respond (health check)
4. Waits for all integrations to report healthy (e.g., gateway listening)
5. Pauses vCPUs and captures a full Firecracker snapshot (`vmstate.bin` + `mem.bin`)
6. Stores the snapshot alongside the template revision

No flags are needed on `run` — snapshot detection is automatic. If a template has a snapshot, it's used; otherwise the VM cold-boots.

## Share via Registry

Push and pull templates to S3-compatible storage:

```bash
mvmctl template push my-service
mvmctl template pull my-service
mvmctl template verify my-service     # Verify checksums
```

Configure the registry with environment variables:

```bash
export MVM_TEMPLATE_REGISTRY_ENDPOINT="https://s3.amazonaws.com"
export MVM_TEMPLATE_REGISTRY_BUCKET="mvm-templates"
export MVM_TEMPLATE_REGISTRY_ACCESS_KEY_ID="..."
export MVM_TEMPLATE_REGISTRY_SECRET_ACCESS_KEY="..."
```

## Multiple Roles

Create templates for multiple roles at once:

```bash
mvmctl template create-multi my-app --flake . --roles worker,gateway
mvmctl template build my-app-gateway
mvmctl template build my-app-worker
```

## Edit

Update an existing template's configuration:

```bash
# Increase memory for an existing template
mvmctl template edit openclaw --mem 2048

# Update multiple settings at once
mvmctl template edit my-service --cpus 4 --mem 4096

# Change the flake reference
mvmctl template edit my-service --flake /new/path
```

After editing, rebuild the template for changes to take effect:

```bash
mvmctl template build my-service --force
```

Available edit options:
- `--flake` - Update the Nix flake reference
- `--profile` - Change the flake package variant
- `--role` - Update the VM role (worker, gateway)
- `--cpus` - Change vCPU count
- `--mem` - Update memory in MiB
- `--data-disk` - Change data disk size in MiB

## Manage

```bash
mvmctl template list                   # List all templates
mvmctl template info my-service        # Show details + revisions
mvmctl template edit my-service --mem 2048  # Edit template settings
mvmctl template delete my-service      # Remove a template
```
