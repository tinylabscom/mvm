---
title: Troubleshooting
description: Common issues and their solutions.
---

## Lima VM Issues

### "Lima VM not found"

```
Error: Lima VM 'mvm-builder' is not available. Run 'mvmctl setup' or 'mvmctl bootstrap' first.
```

**Fix**: Run `mvmctl bootstrap` (macOS) or `mvmctl setup` (Linux with Lima installed).

### "Failed to run command in Lima VM"

The Lima VM exists but is stopped.

**Fix**:
```bash
limactl start mvm-builder
# or
mvmctl dev  # auto-starts Lima
```

### Lima VM is stuck

```bash
limactl stop mvm-builder --force
limactl start mvm-builder
```

If that fails:
```bash
mvmctl uninstall
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
limactl shell mvm-builder bash -c "ip link show | grep tap"
```

### Instance won't start after sleep

Snapshot may be corrupted after a Firecracker version change.

**Fix**: Delete the snapshot and cold boot:
```bash
mvmctl template build <template> --force
mvmctl up --template <template> --name <name>
```

## Build Issues

### Nix build fails

```bash
# Test the flake locally first
mvmctl dev shell
nix build .#default

# Check for errors in the flake
nix flake check
```

### "Cache miss" rebuilds

If builds are slow despite no code changes, check that `flake.lock` hasn't changed. Any change to `flake.lock` invalidates the cache.

### Stale flake.lock

```
error: flake does not provide attribute ...
```

**Cause**: Your `flake.lock` references an old nixpkgs or `mvm` flake version that doesn't have the expected outputs.

**Fix**:
```bash
nix flake update
mvmctl build --flake .
```

### Disk full

```
error: No space left on device
```

**Cause**: The Nix store or Lima disk is full.

**Fix**:
```bash
# Run garbage collection
nix-collect-garbage -d

# Check Nix store size (mvmctl doctor warns if >20 GiB)
mvmctl doctor
```

### Hash mismatch (fixed-output derivation)

```
error: hash mismatch in fixed-output derivation
  got: sha256-XXXX...
```

**Cause**: The `npmHash` or `outputHash` in your flake doesn't match the fetched content (e.g., upstream package changed).

**Fix**: Update the hash to the value shown after `got:` in the error message, or use `--update-hash`:

```bash
mvmctl template build my-service --update-hash
```

### Template not found

```
error: Template 'foo' not found
```

**Fix**: Check available templates:
```bash
mvmctl template list
```

### Timeout / Connection errors

```
error: timed out waiting for ...
```

**Cause**: Network connectivity issue or a service failed to start within the expected time.

**Fix**: Check that the Lima VM has internet access and that your service binds to the correct port. Use `mvmctl logs <name>` to inspect guest output.

## Network Issues

### MicroVM has no internet

```bash
# Inside the Lima VM, check NAT rules
limactl shell mvm-builder bash -c "sudo iptables -t nat -L"

# Check the TAP device exists
limactl shell mvm-builder bash -c "ip link show tap0"
```

### Can't access project files inside microVM

The Firecracker microVM has an **isolated filesystem**. Use `mvmctl dev shell` to access the Lima VM where your home directory is mounted, or pass volumes with `--volume`.

## Performance Issues

### Lima VM is slow

Adjust resources:
```bash
mvmctl uninstall
mvmctl dev up --lima-cpus 8 --lima-mem 16
```

### Wrong backend selected

Force a specific backend:
```bash
mvmctl up --flake . --hypervisor firecracker
mvmctl up --flake . --hypervisor apple-container
mvmctl up --flake . --hypervisor docker
mvmctl up --flake . --hypervisor qemu    # microvm.nix
mvmctl doctor   # check available backends
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
