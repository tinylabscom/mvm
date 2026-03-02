---
title: Troubleshooting
description: Common issues and their solutions.
---

## Lima VM Issues

### "Lima VM not found"

```
Error: Lima VM 'mvm' is not available. Run 'mvmctl setup' or 'mvmctl bootstrap' first.
```

**Fix**: Run `mvmctl bootstrap` (macOS) or `mvmctl setup` (Linux with Lima installed).

### "Failed to run command in Lima VM"

The Lima VM exists but is stopped.

**Fix**:
```bash
limactl start mvm
# or
mvmctl dev  # auto-starts Lima
```

### Lima VM is stuck

```bash
limactl stop mvm --force
limactl start mvm
```

If that fails:
```bash
mvmctl destroy
mvmctl bootstrap
```

## Firecracker Issues

### "Firecracker socket not responding"

The Firecracker process may have crashed. Check the logs:

```bash
mvmctl logs <name>
mvmctl logs <name> --hypervisor   # Firecracker logs
```

### "Failed to create TAP device"

**Cause**: Insufficient permissions or TAP device name collision.

**Fix**:
```bash
# Check for orphaned TAP devices (inside Lima VM)
limactl shell mvm bash -c "ip link show | grep tap"
```

### Instance won't start after sleep

Snapshot may be corrupted after a Firecracker version change.

**Fix**: Delete the snapshot and cold boot:
```bash
mvmctl snapshot delete <name>
mvmctl run --template <template> --name <name>
```

## Build Issues

### Nix build fails

```bash
# Test the flake locally first
mvmctl shell
nix build .#default

# Check for errors in the flake
nix flake check
```

### "Cache miss" rebuilds

If builds are slow despite no code changes, check that `flake.lock` hasn't changed. Any change to `flake.lock` invalidates the cache.

## Network Issues

### MicroVM has no internet

```bash
# Inside the Lima VM, check NAT rules
limactl shell mvm bash -c "sudo iptables -t nat -L"

# Check the TAP device exists
limactl shell mvm bash -c "ip link show tap0"
```

### Can't access project files inside microVM

The Firecracker microVM has an **isolated filesystem**. Use `mvmctl shell` to access the Lima VM where your home directory is mounted, or pass volumes with `--volume`.

## Performance Issues

### Lima VM is slow

Adjust resources:
```bash
mvmctl destroy
mvmctl dev --lima-cpus 8 --lima-mem 16
```

### Rootfs corrupted

Rebuild without destroying the Lima VM:
```bash
mvmctl setup --recreate
```

## Logging

```bash
RUST_LOG=debug mvmctl <command>
RUST_LOG=mvm=trace mvmctl <command>
```
