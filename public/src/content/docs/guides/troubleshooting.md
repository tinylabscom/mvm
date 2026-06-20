---
title: Troubleshooting
description: Common issues and their solutions.
---

## Builder VM and Dev Shell Issues

The builder VM is the Linux environment mvmctl uses for Nix evaluation and image builds. You normally do not enter it yourself: `mvmctl build --flake .` is a host command that stages work for the builder VM and copies artifacts back to the host cache. `mvmctl dev shell` is only for manual debugging. See [Builder VM](/guides/builder-vm/) for the full model.

### "Dev VM is not running"

```
Error: Dev VM is not running. Start it with: mvmctl dev up
```

**Fix**: `mvmctl dev up` (idempotent — installs Firecracker if missing, no-ops otherwise).

### Dev VM is stuck

```bash
mvmctl dev down
mvmctl dev up
```

If that fails, rebuild from scratch:
```bash
mvmctl dev rebuild
```

Or for a full reset:
```bash
mvmctl uninstall
mvmctl bootstrap
```

### Builds hang or fail with the builder daemon not ready

Builds are driven by a resident `mvm-builderd` service inside the builder VM
(see [Builder VM → Resident builder control plane](/guides/builder-vm/)). If
builds hang at startup or fail before any build output, check the daemon's
readiness:

```bash
mvmctl doctor
# look for the "builder daemon" line — it scans the builder-VM state
# directories and probes each daemon's control socket.
```

- **Daemon absent / socket not answering**: the builder VM may not be up. Run
  `mvmctl dev up`, then re-check `mvmctl doctor`.
- **Still not ready after `dev up`**: recycle the builder VM with `mvmctl dev
  down && mvmctl dev up`; if it persists, `mvmctl dev rebuild`.

A build job can be cancelled from the host; the daemon stops the in-flight
operation and returns a cancellation result rather than leaving a wedged build.
You do not interact with `mvm-builderd` directly — everything goes through
`mvmctl`.

### Stage 0 builder panics with `BadActivate` on a fresh, isolated cache

```
thread 'fc_vcpu 1' panicked at .../virtio/mmio.rs:320:
Failed to activate device: BadActivate
```

**Cause**: A from-scratch Stage 0 builder bootstrap against a *completely
isolated, empty* cache (every one of `MVM_CACHE_DIR` / `MVM_DATA_DIR` pointed at
fresh temp dirs at once — e.g. the `core_demo_e2e` smoke test under full
isolation) can panic in the libkrun guest during virtio device activation,
before userspace. The Stage 0 device topology is identical to a warm build, so
this is not a device-count problem; it surfaces in the upstream VMM's
device-activation path under the bundled Stage 0 kernel. It does **not** occur on
a normal cold `mvmctl dev up` against the default cache.

**Fix**: Don't run a builder bootstrap against a fully-isolated empty cache. Use
the default cache, or pre-warm the builder once (`mvmctl dev up` with the default
cache) before pointing a test at an isolated `MVM_DATA_DIR`. If you must isolate,
let the run share the default `MVM_CACHE_DIR` so the builder VM image and nix
store are reused rather than rebuilt from zero. A contributor host with
`mkfs.ext4` available (e.g. `brew install e2fsprogs`) also avoids the warn-only
in-guest seed-store fallback that aggravates first-boot geometry on a cold cache.

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
# Check for orphaned TAP devices (inside the dev VM)
mvmctl dev shell -- ip link show | grep tap
```

### Instance won't start after sleep

Snapshot may be corrupted after a Firecracker version change.

**Fix**: Delete the snapshot and cold boot:
```bash
mvmctl build <project-dir> --force
mvmctl up <project-dir> --name <name>
```

## Build Issues

### Nix build fails

```bash
# Re-run the normal host-orchestrated build.
mvmctl build --flake .

# If you need an interactive Linux debug environment:
mvmctl dev shell
nix build .#default
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

**Cause**: The Nix store or dev VM disk is full.

**Fix**:
```bash
# Check Nix store size (mvmctl doctor warns if >20 GiB)
mvmctl doctor

# For manual cleanup inside a debug shell:
mvmctl dev shell
nix-collect-garbage -d
```

### Hash mismatch (fixed-output derivation)

```
error: hash mismatch in fixed-output derivation
  got: sha256-XXXX...
```

**Cause**: The `npmHash` or `outputHash` in your flake doesn't match the fetched content (e.g., upstream package changed).

**Fix**: Update the hash to the value shown after `got:` in the error message, or use `--update-hash`:

```bash
mvmctl build ./my-service --update-hash
```

### Manifest not found

```
error: no mvm.toml found
```

**Fix**: run from a project directory with `mvm.toml`, pass an explicit path,
or inspect built manifest slots:

```bash
mvmctl manifest ls
```

### Timeout / Connection errors

```
error: timed out waiting for ...
```

**Cause**: Network connectivity issue or a service failed to start within the expected time.

**Fix**: Check that the dev VM has internet access and that your service binds to the correct port. Use `mvmctl logs <name>` to inspect guest output.

## Network Issues

### MicroVM has no internet

```bash
# Inside the dev VM, check NAT rules
mvmctl dev shell -- sudo iptables -t nat -L

# Check the TAP device exists
mvmctl dev shell -- ip link show tap0
```

### Can't access project files inside microVM

The Firecracker microVM has an **isolated filesystem**. Use `mvmctl dev shell` to access the dev VM where your home directory is mounted, or pass volumes with `--volume`.

## Performance Issues

### Dev VM is slow

Adjust resources (or persist the override with `mvmctl config set dev_vm_cpus 8 && mvmctl config set dev_vm_mem_gib 16`):
```bash
mvmctl dev down
mvmctl dev up --cpus 8 --memory 16
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

### macOS: first-run codesigning for `apple-container` and `libkrun`

Both `mvmctl up --hypervisor apple-container` and (once plan 57 W3 wires guest boot) `mvmctl up --hypervisor libkrun` need ad-hoc codesigning before the macOS kernel will let the binary touch the hypervisor APIs:

- `com.apple.security.virtualization` — required by `Virtualization.framework` (the `apple-container` backend).
- `com.apple.security.hypervisor` — required by direct `Hypervisor.framework` callers (the `libkrun` backend).

On the **first** run of either backend, `mvmctl` ad-hoc signs itself with both entitlements and re-spawns the current invocation. The same signed binary covers both backends, so swapping `--hypervisor` between `apple-container` and `libkrun` does not re-sign.

What you'll see on the first run:

```
$ mvmctl up --flake . --hypervisor apple-container
INFO Signing binary with virtualization + hypervisor entitlements...
…starts the VM…
```

On macOS 14+ the ad-hoc signature is accepted by Gatekeeper without an extra prompt. If you had previously installed `mvmctl` from a Homebrew bottle signed against an older entitlement set (virtualization only), the re-spawn will trigger once on the next run after upgrade to lift the binary to both entitlements; subsequent runs are silent.

To pre-sign in CI (skip the re-spawn entirely), set `MVM_SIGNED=1` once the binary on disk already carries both entitlements — the wrapper trusts the env var and skips the codesign probe.

If the signing step itself fails, check that the Xcode command-line tools are installed:

```bash
xcode-select --install
codesign --version    # should report a build number
```

### No `/dev/kvm` available (cloud VMs without nested virt)

Hitting `KVM not available` on a cloud instance? Three options, in order of recommendation.

**Option 1 — Switch to a nested-virt instance type.** Most cloud providers added nested KVM in 2025–2026. After moving to one of these, Firecracker runs natively and you get full Tier 1 isolation:

| Provider | Nested-virt instance families |
|---|---|
| AWS | C8i / M8i / R8i (Feb 2026 onward) — e.g. `c8i.4xlarge` |
| GCE | n2 with `--enable-nested-virtualization` |
| Azure | Dasv5 / Easv5 |

**Option 2 — Use the Tier 3 Docker fallback.** Works in any environment with Docker Engine. **Reduced security tier** — see the [Matryoshka model](/security/matryoshka). The L1–L3 layers collapse to the host kernel, so claims 1, 2, and 3 do not hold. Use only for non-security-sensitive workloads (CI scratch, local experiments).

```bash
mvmctl up --flake . --hypervisor docker
# Suppress the per-run banner once you've acknowledged the tier:
export MVM_ACK_DOCKER_TIER=1
```

**Option 3 — PVM (advanced, external).** [SlicerVM's PVM mode](https://docs.slicervm.com/tasks/pvm/) runs real microVMs without `/dev/kvm` via a patched Firecracker plus a `kvm_pvm` host kernel module. mvm doesn't ship this — the maintenance cost (kernel patch + custom guest images, x86_64 only) is outside mvm's scope. If you need real microVM isolation on a non-nested-virt cloud VM and Option 1 isn't available, SlicerVM is the working answer in the ecosystem today.

### Rootfs corrupted

Re-run `mvmctl bootstrap` — it's idempotent and repaves any corrupted rootfs from the upstream squashfs without destroying the dev VM:
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
     --certificate-identity-regexp "https://github.com/tinylabscom/mvm/.github/workflows/release.yml@refs/tags/v0.14.0" \
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
  https://github.com/tinylabscom/mvm/releases/download/revocations/revoked-versions.json
curl -L -o ~/.cache/mvm/revocations/revoked-versions.json.bundle \
  https://github.com/tinylabscom/mvm/releases/download/revocations/revoked-versions.json.bundle
```

For air-gapped hosts that can never reach github.com, see [Air-gapped Bootstrap](airgapped-bootstrap).
