---
title: Troubleshooting
description: Common issues and their solutions.
---

## Builder VM Issues

The builder VM is the Linux environment mvmctl uses for Nix evaluation and image builds. It is headless — you never enter it, not even for debugging: `mvmctl build --flake .` is a host command that stages work for the builder VM and copies artifacts back to the host cache, streaming the build's own output to your terminal. See [Builder VM](/guides/builder-vm/) for the full model.

### "skipped — dev VM not running"

```
skipped — dev VM not running; run `mvmctl bootstrap` to verify
```

This is `mvmctl doctor` telling you a check was skipped because the builder VM is asleep, not a failure — it boots on demand.

**Fix**: `mvmctl bootstrap` (idempotent — pre-fetches or builds the builder VM image, no-ops if it's already warm).

### Builder VM store is stuck or degraded

```bash
mvmctl cache repair
```

This clears `~/.mvm/cache/builder-vm/` so the next `mvmctl bootstrap`/`mvmctl build` cold-rebuilds it. Use it for a dangling-store error such as `error: path '/nix/store/…-source/flake.nix' does not exist`.

Or for a full reset:

```bash
mvmctl env uninstall
mvmctl bootstrap
```

### "builder VM ... is already attached by another builder VM process"

The shared Nix store image is locked to one writer at a time. A second
`mvmctl build` now queues instead of failing, waiting up to
`MVM_BUILDER_LOCK_WAIT_SECS` (default `3600`). The wait message names the
process that holds the lock.

**Fix**: wait, or reduce the wait budget:

```bash
MVM_BUILDER_LOCK_WAIT_SECS=60 mvmctl build --flake .
```

Set `MVM_BUILDER_LOCK_WAIT_SECS=0` to restore the old fail-fast behavior.

**Avoid the queue entirely**: start a persistent builder session. Concurrent
builds that see a contended store image route through the live session instead
of waiting for the single-shot image lock:

```bash
mvmctl persistent-builder start --workspace .
mvmctl build --flake .   # concurrent builds share the session
mvmctl persistent-builder stop
```

Use `mvmctl build --no-persistent-builder` for a one-off build that must use
the single-shot path.

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
  `mvmctl bootstrap`, then re-check `mvmctl doctor`.
- **Still not ready after `bootstrap`**: repair the builder store with
  `mvmctl cache repair`, then `mvmctl bootstrap` again.

A build job can be cancelled from the host; the daemon stops the in-flight
operation and returns a cancellation result rather than leaving a wedged build.
You do not interact with `mvm-builderd` directly — everything goes through
`mvmctl`.

### Stage 0 builder panics with `BadActivate` on a fresh, isolated cache

```
thread 'fc_vcpu 1' panicked at .../virtio/mmio.rs:320:
Failed to activate device: BadActivate
```

**Cause**: A from-scratch Stage 0 builder bootstrap against a _completely
isolated, empty_ cache (`MVM_HOME` pointed at a fresh temp dir — e.g. the `core_demo_e2e` smoke test under full
isolation) can panic in the libkrun guest during virtio device activation,
before userspace. The Stage 0 device topology is identical to a warm build, so
this is not a device-count problem; it surfaces in the upstream VMM's
device-activation path under the bundled Stage 0 kernel. It does **not** occur on
a normal cold `mvmctl bootstrap` against the default cache.

**Fix**: Don't run a builder bootstrap against a fully-isolated empty cache. Use
the default cache, or pre-warm the builder once (`mvmctl bootstrap` with the default
cache) before pointing a test at an isolated `MVM_HOME`. Isolated roots
seed the builder VM image and runtime overlay opportunistically from the
default `~/.mvm/cache`, so a pre-warmed default cache keeps isolated runs
from rebuilding from zero. A contributor host with
`mkfs.ext4` available (e.g. `brew install e2fsprogs`) also avoids the warn-only
in-guest seed-store fallback that aggravates first-boot geometry on a cold cache.

## Firecracker Issues

### "Firecracker socket not responding"

The Firecracker process may have crashed. Check the logs:

```bash
mvmctl machine logs <name>
mvmctl machine logs <name> --hypervisor   # Firecracker logs
```

### "Failed to create TAP device"

**Cause**: Insufficient permissions or TAP device name collision.

**Fix**: There's no shell into the builder VM to inspect this directly.
Check `mvmctl doctor` for the resolved network backend, and
`mvmctl machine logs <name>` for the failing VM's own boot output.

### Instance won't start after sleep

Snapshot may be corrupted after a Firecracker version change.

**Fix**: Delete the snapshot and cold boot:

```bash
mvmctl build <project-dir> --force
mvmctl machine run --flake <project-dir> --name <name> -d
```

## QEMU backend

### `qemu-system-aarch64` or `mvmctl __qemu-vsock-bridge` linger after a run

After `mvmctl machine run --hypervisor qemu ...` exits, the CLI should reap both
the QEMU process and its detached `mvmctl __qemu-vsock-bridge` child. If either
process is still alive after the command returns, the `mvmctl` binary you ran is
likely stale — the teardown fix lives in the CLI binary itself.

**Fix**: rebuild from source and make sure that binary is the one on your PATH:

```bash
cargo build --release --bin mvmctl
# If you keep a manually-copied bin/mvmctl, recopy it:
cp target/release/mvmctl bin/mvmctl
```

### Preserving transient VM state for debugging

By default, transient runs remove their per-VM state directory under
`~/.mvm/vms/<name>/` at teardown. Set `MVM_PRESERVE_TRANSIENT_STATE=1` to keep
console logs, pid files, and bridge specs after the run for inspection.

## Build Issues

### Workload kernel error is preceded by `SIGTERM`

On the first image-backed run, mvm may build the workload kernel through the
Stage 0 builder. You may see both of these messages:

```text
builder egress endpoint pid=... exited with status signal: 15 (SIGTERM)
resolved workload kernel ... carries no device-mapper/dm-verity support
```

The `SIGTERM` is normally expected cleanup, not the cause of the failure. The
Stage 0 build starts a host-side egress endpoint and terminates it when the
one-shot build exits. The actionable message is the dm-verity error: the
resolved kernel cannot provide `/dev/mapper/control`, so it cannot boot the
verity-sealed workload.

Rebuild or download the workload kernel explicitly:

```bash
# Use the release's hash-verified kernel
mvmctl build kernel build --which workload --source download

# Or compile the host-architecture kernel from a source checkout
mvmctl build kernel build --which workload --source compile
```

For a local compile, the cache also contains the resolved kernel config and
metrics under `~/.mvm/cache/builder-vm/<arch>/kernels/workload/`. An empty
config sidecar or a zero built-in-symbol count indicates that the generated
kernel artifact is incomplete and should not be used for a sealed workload.

### Nix build fails

```bash
# Re-run the normal host-orchestrated build; the error streams back
# from the builder VM the same way as the first attempt.
mvmctl build --flake . -vv
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

# Remove old build artifacts and run Nix garbage collection
# inside the builder VM (no shell needed):
mvmctl env cleanup
```

### Hash mismatch (fixed-output derivation)

```
error: hash mismatch in fixed-output derivation
  got: sha256-XXXX...
```

**Cause**: The `npmHash` or `outputHash` in your flake doesn't match the fetched content (e.g., upstream package changed).

**Fix**: Update the hash to the value shown after `got:` in the error message, or use `--update-hash`:

```bash
mvmctl machine build --flake ./my-service --update-hash
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

**Fix**: Check that the dev VM has internet access and that your service binds to the correct port. Use `mvmctl machine logs <name>` to inspect guest output.

## Machine Run Issues

### `machine run --image ... --allow-host ...` is refused on macOS before the image is pulled

`mvm` now checks the macOS HVF host-vsock-proxy path before any OCI pull,
kernel resolution, or VM boot work. If the detached HVF workload helper is not
launchable, the CLI fails closed instead of falling back to guest-NIC
networking.

Typical message:

```text
... require a NIC-less host-vsock-proxy backend; backend hvf is unavailable on this host
```

**Fix**:

- If you set `MVM_HVF_SUPERVISOR_PATH`, point it at a real `mvm-hvf-supervisor` binary.
- In a source checkout, ensure the workspace can build the helper binary.
- On release installs, make sure `mvm-hvf-supervisor` is present alongside `mvmctl`.

This path is intentionally fail-closed: `--allow-host` on OCI images never
widens to broad `--net` behavior and never falls back to a guest NIC.

When the helper path is available and you want a live runtime proof, run:

```bash
just hvf-oci-allow-host-smoke
```

The script captures both the exact `machine run --image ... --allow-host ...`
command and a second admit/deny relay proof under `/tmp/`.

### `machine run --image X -- /bin/sh` exits immediately with no shell

This is **by design**, not a crash. A plain `machine run` is the one-shot
_transient_ runner: it streams the command's output back to the host but never
forwards host stdin or allocates a terminal, so an interactive shell sees EOF on
stdin and exits `0` right away.

To get an interactive shell, add `-it` (dev-only):

```bash
mvmctl machine run -it --image <dev-image> -- /bin/sh   # drops into a shell
```

The command after `--` is the same command argv as a non-interactive run; `-it`
only adds a PTY and forwards stdin. Omit the command to use the guest default
shell. `-it` requires DevOnly agent verbs and is refused for a sealed/production
image (claim 15: no interactive access to a sealed microVM), with no `--force`
override. A non-dev baked-entrypoint run may receive the restricted ProdSafe
grant, but it cannot be upgraded to a PTY by adding `-it`. The command is also
refused when stdin is not a terminal — both fail fast with a clear message
rather than hanging. To keep the machine after the shell exits, add `--name <N>`
or `-d`.

### `machine run --name X` recreated my machine

`machine run --name X` with a config that differs from the persisted spec
(image, CPU, memory, profile, volumes, …) **auto-recreates** the machine: it
stops the old instance, overwrites the spec, and reboots, printing
`machine 'X': config changed (…) — stopping the old instance and recreating it`
on stderr. This is intended — a machine is defined by its config, so a config
change converges to a fresh machine.

**If that wasn't what you wanted** (e.g. a typo'd `--image`): the machine's own
rootfs is ephemeral, so just re-run with the right config. Durable data should
live in a `--mount` host share, which lives on the host and survives the
recreate. To keep two configs side by side, give them different `--name`s.

**To reconnect without changing anything**, run `mvmctl machine run --name X`
with no other config flags — a matching config reuses the running machine.

### I detached a machine with `-d` — how do I get back in?

`machine run -d` prints the machine's name (auto-generated unless you passed
`--name`). Reconnect with that name:

```bash
mvmctl machine ls                 # list persisted machines
mvmctl machine shell <N>          # interactive shell (dev)
mvmctl machine exec  <N> -- <cmd>   # one-shot command
mvmctl machine stop  <N>          # tear it down (prompts; add --yes to skip)
```

## Network Issues

### MicroVM has no internet

There's no shell into the builder VM to inspect NAT/TAP state directly.
Start from the network policy the VM was launched with:

```bash
mvmctl doctor              # resolved network backend
mvmctl machine logs <name>  # guest-side boot + networking errors
```

Remember networking is deny-by-default: a transient `machine run` needs
`--net` or `--allow-host` before outbound traffic works at all.

### Can't access project files inside microVM

The Firecracker microVM has an **isolated filesystem** and there's no shell into the builder VM to bridge it. Pass host shares explicitly with `--mount HOST:GUEST[:rw]` (see [Sandboxed Exec](/guides/exec/)).

## Performance Issues

### Builder VM is slow

Persist a resource override, then re-provision it:

```bash
mvmctl ops config set dev_vm_cpus 8
mvmctl ops config set dev_vm_mem_gib 16
mvmctl cache repair
mvmctl bootstrap
```

### Wrong backend selected

Force a specific backend:

```bash
mvmctl machine run --flake . --hypervisor firecracker
mvmctl machine run --flake . --hypervisor hvf
mvmctl machine run --flake . --hypervisor libkrun
mvmctl machine run --flake . --hypervisor qemu    # dev/test, no /dev/kvm
mvmctl doctor   # check available backends
```

### macOS: first-run codesigning for `hvf` and `libkrun`

The macOS backends — `hvf` (the default) and `libkrun` — need ad-hoc codesigning before the macOS kernel will let the binary touch the hypervisor APIs:

- `com.apple.security.hypervisor` — required by direct `Hypervisor.framework` callers (the `hvf` and `libkrun` backends).

On the **first** run of either backend, `mvmctl` ad-hoc signs itself with the entitlement and re-spawns the current invocation. The same signed binary covers both backends, so swapping `--hypervisor` between `hvf` and `libkrun` does not re-sign.

What you'll see on the first run:

```
$ mvmctl machine run --flake . --hypervisor hvf
INFO Signing binary with hypervisor entitlement...
…starts the VM…
```

On macOS 14+ the ad-hoc signature is accepted by Gatekeeper without an extra prompt. If you had previously installed `mvmctl` from a Homebrew bottle signed against a different entitlement set, the re-spawn will trigger once on the next run after upgrade to lift the binary to the hypervisor entitlement; subsequent runs are silent.

To pre-sign in CI (skip the re-spawn entirely), set `MVM_SIGNED=1` once the binary on disk already carries the hypervisor entitlement — the wrapper trusts the env var and skips the codesign probe.

If the signing step itself fails, check that the Xcode command-line tools are installed:

```bash
xcode-select --install
codesign --version    # should report a build number
```

### No `/dev/kvm` available (cloud VMs without nested virt)

Hitting `KVM not available` on a cloud instance? Three options, in order of recommendation.

**Option 1 — Switch to a nested-virt instance type.** Most cloud providers added nested KVM in 2025–2026. After moving to one of these, Firecracker runs natively and you get full Tier 1 isolation:

| Provider | Nested-virt instance families                          |
| -------- | ------------------------------------------------------ |
| AWS      | C8i / M8i / R8i (Feb 2026 onward) — e.g. `c8i.4xlarge` |
| GCE      | n2 with `--enable-nested-virtualization`               |
| Azure    | Dasv5 / Easv5                                          |

**Option 2 — Use the QEMU dev/test backend.** On a Linux host without `/dev/kvm`, run the software-emulated QEMU/TCG backend. It's a real microVM but **Tier 2 dev/test** — slower, larger TCB, partial verified boot (see the [Matryoshka model](/security/matryoshka)) — so use it for local dev/test, not production or untrusted workloads.

```bash
mvmctl machine run --flake . --hypervisor qemu
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

## Builder Pack Signature Verification

The builder VM image ships as a release artifact (the "builder pack") under
the same cosign-signed-manifest + SHA-256 + revocation model that used to
also cover the now-removed dev-image fetch path.

### "Cosign verification failed for builder-vm-{arch}.manifest.json"

The cosign-signed manifest didn't validate against the project's release-workflow OIDC identity. Treat this as a supply-chain incident until proven otherwise.

Triage in this order:

1. **Clock skew** — `date -u`. Sigstore signatures carry a tight time window. A host clock more than ~10 minutes off can fail otherwise-valid signatures.
2. **Re-download the pair** — manifest and `.bundle` belong together. A partial download from a previous attempt may have left only one file fresh.
3. **Verify with the cosign CLI** to localize the failure:
   ```bash
   cosign verify-blob \
     --bundle builder-vm-aarch64.manifest.json.bundle \
     --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
     --certificate-identity-regexp "https://github.com/tinylabscom/mvm/.github/workflows/release.yml@refs/tags/v0.14.0" \
     builder-vm-aarch64.manifest.json
   ```
   Same identity wording mvmctl uses internally.
4. **Open a security issue** if the signature is genuinely invalid against the official identity. Don't ship a workaround locally.

Emergency rotation when Sigstore TUF/Rekor is unavailable: `MVM_SKIP_COSIGN_VERIFY=1` keeps SHA-256 verification active while bypassing the signature check. Loud warnings; not for routine use.

### "Manifest is for v0.14.1 but mvmctl is v0.14.0"

The manifest pins `manifest.version` to `mvmctl --version` exactly. Either:

- Upgrade `mvmctl` to match (`brew upgrade mvmctl` / `cargo install mvmctl`); or
- Use a manifest from the matching release (re-export from the v0.14.0 release page).

### "Integrity check failed for rootfs.ext4"

SHA-256 of the downloaded artifact doesn't match the manifest's recorded digest. Possible causes, in order:

1. Mid-flight corruption — retry with `mvmctl bootstrap` (or `mvmctl pack download --kind builder`) to re-download.
2. Mirror/CDN cache poisoning — rare but real; open a security issue with the SHA-256 you got vs what the manifest says.
3. The release was re-uploaded after the manifest was signed (publishing process bug) — wait for the next tag.

`MVM_SKIP_HASH_VERIFY=1` is the documented escape, but it disables the supply-chain check entirely. Investigate first.

### "Manifest is on the project's revocation list"

A `revocations` release entry has marked your mvmctl version unsafe. Read the recall reason in the failure message. Upgrade mvmctl to a non-revoked release.

### "Could not refresh revocation list … using cached copy"

Network failure during the 24-hour revocation-list refresh. mvmctl tolerates up to 7 days of cached staleness. After 7 days, revocation enforcement is silently skipped (with a warning) — refresh manually:

```bash
mkdir -p ~/.mvm/cache/revocations
curl -L -o ~/.mvm/cache/revocations/revoked-versions.json \
  https://github.com/tinylabscom/mvm/releases/download/revocations/revoked-versions.json
curl -L -o ~/.mvm/cache/revocations/revoked-versions.json.bundle \
  https://github.com/tinylabscom/mvm/releases/download/revocations/revoked-versions.json.bundle
```

For air-gapped hosts that can never reach github.com, see [Air-gapped Bootstrap](airgapped-bootstrap).

### "Pack revocation list failed verification"

The fetched builder-pack recall list did not verify against the project's
`revocations.yml` OIDC identity, so mvmctl ignored it and fell back to the
operator's local `pack-trust.json` revocations only. Refresh the cached pair
manually if you need the public recall channel immediately:

```bash
mkdir -p ~/.mvm/cache/pack-revocations
curl -L -o ~/.mvm/cache/pack-revocations/pack-revocations.json \
  https://github.com/tinylabscom/mvm/releases/download/revocations/pack-revocations.json
curl -L -o ~/.mvm/cache/pack-revocations/pack-revocations.json.bundle \
  https://github.com/tinylabscom/mvm/releases/download/revocations/pack-revocations.json.bundle
```

### "Could not refresh pack revocation list … using cached copy"

Network failure during the 24-hour builder-pack recall refresh. mvmctl tolerates
up to 7 days of cached staleness before it drops back to the on-disk
`pack-trust.json` revocations only. Refresh the cached pair with the same
commands above, or keep operating on the local trust policy until the public
channel is reachable again.
