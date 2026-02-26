# End-to-End Smoke Test

Manual validation of the full mvm lifecycle. Requires a Linux host with `/dev/kvm` or macOS with Lima.

## Prerequisites

**macOS (via Lima):**
```bash
mvmctl bootstrap          # installs Lima + Firecracker + kernel + rootfs
mvmctl status             # verify Lima VM is running, FC "Installed, not running"
```

**Linux (native):**
```bash
# Ensure /dev/kvm exists
ls -la /dev/kvm

# Bootstrap (downloads Firecracker, installs dependencies)
mvmctl bootstrap

# Verify
mvmctl node info
```

## 1. Dev Mode Sanity Check

Verify the single-VM dev path still works:

```bash
mvmctl dev                # should auto-bootstrap if needed, then SSH into microVM
# inside the VM:
uname -a               # confirm you're in the guest
exit                   # exit SSH (VM keeps running)
mvmctl status             # should show microVM running
mvmctl stop               # clean shutdown
```

## 2. Add Host (Onboarding)

Prepare a machine to join the fleet with a single command:

```bash
# Dev mode (self-signed certs, no signing key)
mvmctl add host

# Production mode (with CA and coordinator signing key)
mvmctl add host --ca ca.crt --signing-key coordinator.pub --production
```

**Expected**: environment bootstrapped (Lima on macOS, Firecracker, kernel, rootfs), mTLS certificates initialized, signing key copied to `/etc/mvm/trusted_keys/` (if provided). Output shows next step: `mvmctl agent serve`.

Verify with:
```bash
mvmctl status             # Lima + FC installed
mvmctl node info          # node UUID, arch, vCPUs, memory
```

## 3. New Deployment (Onboarding)

Create a full OpenClaw deployment end-to-end with a single command:

```bash
# Auto-allocate network, build, and scale
mvmctl new openclaw smoke-app

# With explicit network overrides
mvmctl new openclaw smoke-app --net-id 99 --subnet 10.240.99.0/24

# With a custom flake reference
mvmctl new openclaw smoke-app --flake github:myorg/myflake
```

**Expected**: tenant `smoke-app` created with default quotas, gateway pool created (role: gateway, 2 vCPU, 1024 MiB), worker pool created (role: worker, 2 vCPU, 1024 MiB, 2048 MiB data disk), both pools built, gateway scaled to 1 running, workers scaled to 2 running + 1 warm. Output shows deployment summary and `mvmctl connect smoke-app` as next step.

Verify with:
```bash
mvmctl tenant list                          # smoke-app appears
mvmctl tenant info smoke-app                # shows quotas and network
mvmctl pool list smoke-app                  # gateways + workers
mvmctl pool info smoke-app/gateways         # role: gateway
mvmctl pool info smoke-app/workers          # role: worker
mvmctl instance list --tenant smoke-app     # instances across both pools
```

## 4. Connect Dashboard (Onboarding)

View the deployment dashboard:

```bash
mvmctl connect smoke-app
mvmctl connect smoke-app --json    # machine-readable output
```

**Expected**: shows network info (gateway IP, subnet, bridge), pool summary (roles, resources, counts), instance table (IDs, status, IPs), and quick reference commands for secrets, scaling, and instance listing.

## 5. Tenant Lifecycle (Granular)

Test the manual tenant workflow:

```bash
# Create a tenant with coordinator-assigned network
mvmctl tenant create smoke-test \
    --net-id 99 --subnet 10.240.99.0/24 \
    --max-vcpus 8 --max-mem 8192 --max-running 4

# Verify
mvmctl tenant list
mvmctl tenant info smoke-test
mvmctl tenant info smoke-test --json    # confirm JSON output works

# Check bridge was created
mvmctl net verify
```

**Expected**: tenant appears in list, info shows quotas and network config, bridge `br-tenant-99` exists.

## 6. Pool Lifecycle (Granular)

```bash
# Create a pool with explicit role
mvmctl pool create smoke-test/gateways \
    --flake . --profile minimal \
    --cpus 2 --mem 1024 --role gateway

# Create a worker pool (default role)
mvmctl pool create smoke-test/workers \
    --flake . --profile minimal \
    --cpus 2 --mem 1024

# Verify
mvmctl pool list smoke-test
mvmctl pool info smoke-test/workers

# Build artifacts (requires Nix inside the VM)
mvmctl pool build smoke-test/workers

# Set desired counts
mvmctl pool scale smoke-test/workers --running 2 --warm 1 --sleeping 1
```

**Expected**: pools appear in list, info shows flake ref / resources / role / desired counts. Build produces kernel + rootfs under `artifacts/revisions/`.

## 7. Instance Lifecycle

```bash
# List instances
mvmctl instance list --tenant smoke-test --pool workers

# Start an instance
INSTANCE_ID=$(mvmctl instance list --tenant smoke-test --pool workers --json | jq -r '.[0].instance_id')
mvmctl instance start smoke-test/workers/$INSTANCE_ID

# Verify it's running
mvmctl instance stats smoke-test/workers/$INSTANCE_ID

# SSH into the instance
mvmctl instance ssh smoke-test/workers/$INSTANCE_ID
# inside: uname -a, check /run/secrets if secrets were set
# exit

# Stop the instance
mvmctl instance stop smoke-test/workers/$INSTANCE_ID
mvmctl instance list --tenant smoke-test --pool workers   # should show Stopped
```

**Expected**: instance transitions Created -> Running -> Stopped. SSH works, stats show PID/IP/TAP.

## 8. Sleep / Wake Round-Trip

```bash
# Start the instance again
mvmctl instance start smoke-test/workers/$INSTANCE_ID

# Sleep it (snapshot to disk)
mvmctl instance sleep smoke-test/workers/$INSTANCE_ID

# Verify snapshot exists
mvmctl instance stats smoke-test/workers/$INSTANCE_ID   # should show Sleeping status

# Wake it back up
mvmctl instance wake smoke-test/workers/$INSTANCE_ID

# Verify it's running again with same network identity
mvmctl instance stats smoke-test/workers/$INSTANCE_ID
```

**Expected**: instance transitions Running -> Sleeping -> Running. Snapshot created and restored. IP and TAP device preserved.

## 9. Agent Reconcile (One-Shot)

Generate desired state from the tenants and pools you just created:

```bash
# Generate desired state from existing tenant/pool config
mvmctl agent desired --file /tmp/desired.json

# Inspect the generated file
cat /tmp/desired.json

# On macOS, copy the file into the Lima VM for the agent to read
# limactl copy /tmp/desired.json mvm:/tmp/desired.json

# Run one-shot reconcile
mvmctl agent reconcile --desired /tmp/desired.json

# Verify instances match desired state
mvmctl instance list --tenant smoke-test --pool workers
```

You can also write `desired.json` by hand or generate it from your own tooling. The schema is documented in [docs/agent.md](agent.md).

**Expected**: agent creates/starts instances to match desired counts. Two instances should be Running.

## 10. Agent Daemon + QUIC Round-Trip

```bash
# Generate certificates
mvmctl agent certs init --ca /tmp/ca.crt

# Start agent daemon in background
mvmctl agent serve \
    --desired /tmp/desired.json \
    --interval-secs 30 \
    --listen 127.0.0.1:4433 \
    --tls-cert /tmp/node.crt --tls-key /tmp/node.key --tls-ca /tmp/ca.crt &

AGENT_PID=$!
sleep 3

# Query node status via coordinator client
mvmctl coordinator status --node 127.0.0.1:4433

# Push updated desired state
mvmctl coordinator push --desired /tmp/desired.json --node 127.0.0.1:4433

# List instances via coordinator
mvmctl coordinator list-instances --node 127.0.0.1:4433 --tenant smoke-test

# Stop agent
kill $AGENT_PID
```

**Expected**: QUIC connection succeeds with mTLS. Status returns node info. Push accepted.

## 11. Bridge Verification

```bash
mvmctl net verify
mvmctl net verify --json
```

**Expected**: clean report — all tenant bridges correct, subnets match, no cross-tenant leakage.

## 12. Operational Commands

```bash
# Disk usage
mvmctl node disk

# Garbage collection
mvmctl pool gc smoke-test/workers
mvmctl node gc

# Audit events
mvmctl events smoke-test
mvmctl events smoke-test --last 5 --json

# Shell completions (verify generation)
mvmctl completions bash > /dev/null && echo "bash completions OK"
mvmctl completions zsh > /dev/null && echo "zsh completions OK"
```

## 13. Teardown

```bash
# Destroy the onboarding deployment
mvmctl tenant destroy smoke-app --force

# Destroy the granular smoke-test tenant
mvmctl tenant destroy smoke-test --force

# Verify clean state
mvmctl tenant list                # should be empty
mvmctl net verify                 # no bridges remaining
mvmctl node disk                  # storage freed
```

## Troubleshooting

| Symptom | Check |
|---------|-------|
| `Lima VM not running` | `limactl list` — start with `limactl start mvm` |
| `/dev/kvm not found` | Enable nested virtualization in Lima config or use bare-metal Linux |
| `pool build` fails | Check Nix is installed inside VM: `nix --version` |
| `instance start` hangs | Check FC logs: `mvmctl instance logs <path>` |
| Bridge not created | Run as root or check `CAP_NET_ADMIN` capability |
| QUIC connection refused | Verify cert paths and that agent is listening on the correct port |
| `mvmctl new` fails at build | Ensure bootstrap completed — run `mvmctl add host` first |
| `mvmctl connect` shows no instances | Deployment may still be building — check `mvmctl pool info <name>/workers` |

## Notes

- On macOS, all Firecracker operations happen inside the Lima VM. Network bridges and TAP devices are Lima-internal.
- On native Linux, operations run directly. Ensure the user has appropriate capabilities (`CAP_NET_ADMIN`, access to `/dev/kvm`).
- The smoke test is inherently stateful — run teardown between test runs.
- Sleep/wake requires that Firecracker snapshot support is available (check FC version >= 1.0).
- Sections 2–4 test the onboarding commands (`add host`, `new`, `connect`). Sections 5–6 test the same operations via granular CLI commands.
