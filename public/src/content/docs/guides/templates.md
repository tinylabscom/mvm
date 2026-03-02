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

## Warm Snapshots

Warm snapshots automate cold boot → health wait → snapshot → store. Users never experience cold boot:

```bash
# One-time: build and warm
mvmctl template build my-service
mvmctl template warm my-service          # boots, waits for healthy, snapshots

# Every subsequent run is instant (<1s):
mvmctl run --template my-service --name svc
```

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

## Manage

```bash
mvmctl template list                   # List all templates
mvmctl template info my-service        # Show details + revisions
mvmctl template delete my-service      # Remove a template
```
