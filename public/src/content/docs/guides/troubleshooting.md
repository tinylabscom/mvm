---
title: Troubleshooting
description: Common issues and their solutions.
---

## Lima VM Issues

### "Lima VM not found"

```
Error: Lima VM 'mvm-builder' is not available. Run 'mvmctl bootstrap' first.
```

**Fix**: Run `mvmctl bootstrap` (idempotent — installs Lima/Firecracker if missing, no-ops otherwise).

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
mvmctl up --manifest <template> --name <name>
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

Re-run `mvmctl bootstrap` — it's idempotent and repaves any corrupted rootfs from the upstream squashfs without destroying the Lima VM:
```bash
mvmctl bootstrap
```

## Logging

```bash
RUST_LOG=debug mvmctl <command>
RUST_LOG=mvm=trace mvmctl <command>
```

## Dev Image Signature Verification (plan 36)

### "Cosign verification failed for {variant}-image-{arch}.manifest.json"

The cosign-signed manifest didn't validate against the project's release-workflow OIDC identity. Treat this as a supply-chain incident until proven otherwise.

Triage in this order:

1. **Clock skew** — `date -u`. Sigstore signatures carry a tight time window. A host clock more than ~10 minutes off can fail otherwise-valid signatures.
2. **Re-download the pair** — manifest and `.bundle` belong together. A partial download from a previous attempt may have left only one file fresh.
3. **Verify with the cosign CLI** to localize the failure:
   ```bash
   cosign verify-blob \
     --bundle dev-image-aarch64.manifest.json.bundle \
     --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
     --certificate-identity-regexp "https://github.com/auser/mvm/.github/workflows/release.yml@refs/tags/v0.14.0" \
     dev-image-aarch64.manifest.json
   ```
   Same identity wording mvmctl uses internally.
4. **Open a security issue** if the signature is genuinely invalid against the official identity. Don't ship a workaround locally.

Emergency rotation when Sigstore TUF/Rekor is unavailable: `MVM_SKIP_COSIGN_VERIFY=1` keeps SHA-256 verification active while bypassing the signature check. Loud warnings; not for routine use.

### "Manifest is for v0.14.1 but mvmctl is v0.14.0"

Plan 36 pins `manifest.version` to `mvmctl --version` exactly. Either:
- Upgrade `mvmctl` to match (`brew upgrade mvmctl` / `cargo install mvmctl`); or
- Use a manifest from the matching release (re-export from the v0.14.0 release page).

### "Integrity check failed for dev-rootfs-aarch64.ext4"

SHA-256 of the downloaded artifact doesn't match the manifest's recorded digest. Possible causes, in order:

1. Mid-flight corruption — retry `mvmctl dev up` to re-download.
2. Mirror/CDN cache poisoning — rare but real; open a security issue with the SHA-256 you got vs what the manifest says.
3. The release was re-uploaded after the manifest was signed (publishing process bug) — wait for the next tag.

`MVM_SKIP_HASH_VERIFY=1` is the documented escape, but it disables the supply-chain check entirely. Investigate first.

### "Manifest is on the project's revocation list"

A `revocations` release entry has marked your mvmctl version unsafe. Read the recall reason in the failure message. Upgrade mvmctl to a non-revoked release.

### "Could not refresh revocation list … using cached copy"

Network failure during the 24-hour revocation-list refresh. mvmctl tolerates up to 7 days of cached staleness. After 7 days, revocation enforcement is silently skipped (with a warning) — refresh manually:

```bash
mkdir -p ~/.cache/mvm/revocations
curl -L -o ~/.cache/mvm/revocations/revoked-versions.json \
  https://github.com/auser/mvm/releases/download/revocations/revoked-versions.json
curl -L -o ~/.cache/mvm/revocations/revoked-versions.json.bundle \
  https://github.com/auser/mvm/releases/download/revocations/revoked-versions.json.bundle
```

For air-gapped hosts that can never reach github.com, see [Air-gapped Bootstrap](airgapped-bootstrap).
