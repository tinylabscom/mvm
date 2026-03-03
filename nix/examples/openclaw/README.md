# OpenClaw MicroVM Template

Nix-based Firecracker microVM running the [OpenClaw](https://openclaw.ai) MCP gateway.

## ⚠️ Important: First Boot Performance

**First boot takes 10-15 minutes** on macOS due to nested virtualization (macOS hypervisor → Lima → Firecracker). V8 compiles the 9.5MB bundled application during this time.

**Solution**: After the first successful boot, use the snapshot feature for instant subsequent boots (<5 seconds).

## Quick Start

### Option A: Patient First Boot

```bash
# Build and start (wait 10-15 minutes for first boot)
mvmctl template build openclaw --force
mvmctl run --template openclaw --name oc --cpus 4 --memory 4096

# Check logs to see progress
mvmctl logs -f oc
# Wait for: "listening on ws://127.0.0.1:3000"

# Verify it's running
curl http://172.16.0.3:3000/
```

### Option B: Build with Snapshot (Recommended)

```bash
# Build template WITH snapshot capture (waits for first boot, then saves state)
mvmctl template build openclaw --force --snapshot

# Now start with instant snapshot restore (<5 seconds)
mvmctl run --template openclaw --name oc --snapshot
```

The `--snapshot` flag on `template build` boots the VM once, waits for it to become healthy, captures the running state, then shuts down. Subsequent `run --snapshot` commands restore from this saved state instantly.

## Architecture

```
Host (macOS/Linux)
  └─> Lima VM (Ubuntu + KVM)
      └─> Firecracker microVM
          ├─> /mnt/config/   (config drive, read-only)
          ├─> /mnt/secrets/  (secrets drive, read-only)
          ├─> /mnt/data/     (data drive, optional, persistent)
          └─> OpenClaw gateway (Node.js, busybox init)
```

### Packaging

- **Source**: Official [nix-openclaw](https://github.com/openclaw/nix-openclaw) flake
- **Build**: Pure Nix derivation with pnpm frozen lockfile
- **Optimization**: 800+ Vite code-split chunks bundled into 9.5MB ESM file (esbuild `--packages=external`)
- **Updates**: `cd nix/examples/openclaw && nix flake update nix-openclaw`

### Why Is First Boot Slow?

Nested virtualization overhead:
- **Lima VM** (direct KVM): OpenClaw starts in ~6 seconds ✅
- **Firecracker** (nested via Lima): V8 compilation takes 10-15 minutes ⏱️

On native Linux with direct Firecracker access (no Lima), boot times match the Lima performance (~6 seconds).

## Variants

### Gateway (Default)

Lightweight MCP proxy, no persistent storage:

```bash
mvmctl run --template openclaw --name oc-gw
```

### Worker

Agent execution with persistent data disk:

```bash
mvmctl template build openclaw --profile tenant-worker
mvmctl run --template openclaw --name oc-worker --profile tenant-worker --data-disk 10G
```

## Configuration

### Via Environment Variables

```bash
# Create environment file
cat > /tmp/openclaw.env <<EOF
OPENCLAW_LOG_LEVEL=debug
ANTHROPIC_API_KEY=sk-ant-...
EOF

# Run with config
mvmctl run --template openclaw --name oc --config /tmp/openclaw.env
```

Inside the VM, files from `--config` appear at `/mnt/config/` and are sourced by the start script.

### Via OpenClaw Config File

```json
{
  "gateway": {
    "mode": "local",
    "port": 3000,
    "auth": {
      "enabled": true,
      "token": "..."
    }
  }
}
```

Place as `openclaw.json` in the config directory passed via `--config-dir`:

```bash
mkdir my-config
cat > my-config/openclaw.json <<EOF
{"gateway":{"mode":"local","port":3000}}
EOF

mvmctl run --template openclaw --name oc --config-dir ./my-config
```

If no `openclaw.json` is provided, a minimal default is generated automatically.

## Networking

- **Internal**: OpenClaw binds to `127.0.0.1:3000` (gateway) and `127.0.0.1:3002` (browser control)
- **External**: socat forwards from TAP interface (e.g., `172.16.0.3:3000`) to loopback
- **Host Access**: Use port forwarding:

```bash
mvmctl forward oc 3000
# Now access at http://localhost:3000
```

## Troubleshooting

### Health Checks Keep Failing

**During first boot**: This is normal for 10-15 minutes while V8 compiles. Wait for the log message:

```
listening on ws://127.0.0.1:3000
```

Check logs with:

```bash
mvmctl logs -f oc
```

### VM Never Starts (20+ Minutes)

Check for zombie Firecracker processes hogging CPU:

```bash
limactl shell mvm -- ps aux | grep firecracker
```

Kill any old processes:

```bash
limactl shell mvm -- sudo pkill -f firecracker
```

Then restart the VM.

### Testing Without Nested Virtualization

Verify the package works in Lima directly (bypasses nested virt):

```bash
limactl shell mvm
/nix/store/*-openclaw-bundled-*/bin/openclaw gateway --port 3000 --allow-unconfigured
# Should start in ~6 seconds
```

## Development

### Rebuild Template

```bash
mvmctl template build openclaw --force
```

### Update OpenClaw Version

```bash
cd nix/examples/openclaw
nix flake update nix-openclaw
cd ../../..
mvmctl template build openclaw --force --snapshot
```

### Modify Bundling

Edit `pkgs/openclaw-bundled.nix`. Current approach:
- Uses `--packages=external` to bundle only OpenClaw's 800 Vite chunks
- Keeps all node_modules imports external (avoids pnpm resolution issues)
- Result: 9.5MB single ESM file vs 800+ individual chunks

## Performance Summary

| Environment | Cold Boot | With Snapshot |
|-------------|-----------|---------------|
| Lima VM (KVM) | ~6 seconds | N/A (direct) |
| Firecracker (nested) | 10-15 minutes | <5 seconds ✅ |
| Firecracker (native Linux) | ~6 seconds | <5 seconds ✅ |

**Recommendation**: Always use `--snapshot` for development on macOS.

## See Also

- [OpenClaw Documentation](https://docs.openclaw.ai)
- [nix-openclaw Repository](https://github.com/openclaw/nix-openclaw)
- [mvm User Guide](../../docs/user-guide.md)
- [Firecracker Snapshots](../../docs/snapshots.md)
