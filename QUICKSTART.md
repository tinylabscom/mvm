# mvm Quick Start

Get a Firecracker microVM running in under 5 minutes.

## Prerequisites

- macOS (Apple Silicon or Intel) or Linux with KVM
- [Homebrew](https://brew.sh/) (macOS only)

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/auser/mvm/main/install.sh | sh
```

Or build from source:

```bash
git clone https://github.com/auser/mvm.git
cd mvm
cargo build --release
cp target/release/mvm ~/.local/bin/
```

> Note: If `MVM_FC_VERSION` is set (e.g., via `firecracker --version` output), mvm normalizes it automatically to `vMAJOR.MINOR[.PATCH]`, so you don't need to tweak it manually. If your network blocks the default S3 bucket for builder artifacts, set `MVM_FC_ASSET_BASE` to a reachable S3-compatible endpoint (optionally `MVM_FC_ASSET_ROOTFS` / `MVM_FC_ASSET_KERNEL` to force filenames).

> Templates: Build a base image once and reuse it across tenants/pools. Create (`mvm template create ...`) or from a config (`mvm template build --config docs/examples/template.toml` for multiple roles), build it, then point pools at it (`mvm pool create tenant/pool --template <id> ...`). Pool builds reuse template artifacts; `mvm pool build --force` rebuilds the template first.

## Dev Mode (Single VM)

Bootstrap everything (Lima, Firecracker, kernel, rootfs) and launch a microVM:

```bash
mvm dev
```

That's it. You'll be dropped into an SSH session inside the microVM. Exit with `exit` -- the VM keeps running.

Other dev commands:

```bash
mvm status    # Check what's running
mvm ssh       # Reconnect to the running VM
mvm stop      # Stop the microVM
mvm destroy   # Tear down everything
```

## Deploy an OpenClaw App (3 Commands)

The fastest path from bare machine to a running deployment:

### 1. Prepare the host

```bash
mvm add host
```

Bootstraps the environment, initializes mTLS certificates, and prepares the machine for fleet operation. For production, pass `--ca ca.crt --signing-key coordinator.pub`.

### 2. Create a deployment

```bash
mvm new openclaw myapp
```

Creates a complete deployment end-to-end: allocates a network, creates a tenant, sets up gateway and worker pools, builds images, and scales up (1 gateway, 2 workers + 1 warm spare).

### 3. View your deployment

```bash
mvm connect myapp
```

Shows the deployment dashboard: network info, pool summary, instance table, and quick-reference commands for secrets, scaling, and instance management.

See [Onboarding Guide](docs/onboarding.md) for the full walkthrough.

## Multi-Tenant Mode (Granular)

For fine-grained control, use the individual tenant/pool/instance commands:

### 1. Create a tenant

```bash
mvm tenant create acme \
    --net-id 3 \
    --subnet 10.240.3.0/24 \
    --max-vcpus 16 \
    --max-mem 32768 \
    --max-running 8
```

### 2. Create a worker pool

```bash
mvm pool create acme/workers \
    --flake github:org/app \
    --profile minimal \
    --cpus 2 \
    --mem 1024
```

### 3. Build pool artifacts

```bash
mvm pool build acme/workers
```

### 4. Scale up

```bash
mvm pool scale acme/workers --running 3 --warm 1
```

### 5. Interact

```bash
mvm instance list acme/workers
mvm instance ssh acme/workers/i-a3f7b2c1
```

### 6. Sleep/wake for cost savings

```bash
mvm instance sleep acme/workers/i-a3f7b2c1   # Snapshot + stop
mvm instance wake acme/workers/i-a3f7b2c1    # Restore from snapshot
```

## Fleet Mode (Agent)

### Initialize mTLS certificates

```bash
mvm agent certs init
```

### Run the agent daemon

```bash
mvm agent serve --desired desired.json --interval-secs 30 --listen 0.0.0.0:4433
```

### One-shot reconcile

```bash
mvm agent reconcile --desired desired.json
```

## Desired State File

Create `desired.json`:

```json
{
  "schema_version": 1,
  "node_id": "node-1",
  "tenants": [
    {
      "tenant_id": "acme",
      "network": {
        "tenant_net_id": 3,
        "ipv4_subnet": "10.240.3.0/24"
      },
      "quotas": {
        "max_vcpus": 16,
        "max_mem_mib": 32768,
        "max_running": 8,
        "max_warm": 4,
        "max_pools": 10,
        "max_instances_per_pool": 32,
        "max_disk_gib": 500
      },
      "pools": [
        {
          "pool_id": "workers",
          "flake_ref": "github:org/app",
          "profile": "minimal",
          "instance_resources": {
            "vcpus": 2,
            "mem_mib": 1024,
            "data_disk_mib": 0
          },
          "desired_counts": {
            "running": 3,
            "warm": 1,
            "sleeping": 0
          }
        }
      ]
    }
  ],
  "prune_unknown_tenants": false,
  "prune_unknown_pools": false
}
```

## Next Steps

- [Onboarding Guide](docs/onboarding.md) -- end-to-end deployment walkthrough
- [Full CLI Reference](docs/cli.md)
- [Architecture Guide](docs/architecture.md)
- [Networking](docs/networking.md)
- [Agent & Reconciliation](docs/agent.md)
- [Security](docs/security.md)
