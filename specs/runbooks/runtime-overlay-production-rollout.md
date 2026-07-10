# Runbook — runtime-overlay production rollout

**Audience:** the engineer cutting the release candidate and the operator
rolling it onto real hosts.

**Purpose:** turn the readonly guest-runtime overlay from a validated branch
feature into a safely shipped release with explicit rollout and rollback steps.

## Scope of the contract

The released runtime overlay is the shared guest-runtime artifact published with
each `mvmctl` release and cached locally under:

```text
~/.cache/mvm/runtime-overlay/<version>/<arch>/
```

Contents:

- `overlay.ext4`
- `overlay.verity`
- `overlay.roothash`
- `VERSION`

Rules:

- Only **guest-executed** runtime binaries belong here.
- The guest mounts this artifact **read-only** on admitted overlay-backed
  backends.
- The runtime is **version-matched** to the host `mvmctl` release, not "latest
  in cache".
- Running VMs do **not** hot-remount a new overlay.
- Stopped VMs adopt a new overlay on the next start or restart.
- Unsupported Linux rootfs-backed libkrun builder use fails closed with
  `BuilderVmError::LibkrunUnavailable(...)`.

## Pre-release candidate checklist

Before cutting or approving the RC tag:

1. Confirm the branch tip intended to ship is identified exactly by commit SHA.
2. Re-run:
   - `cargo check --workspace --offline`
   - `cargo clippy --workspace --all-targets --offline -- -D warnings`
   - `cargo test --workspace --offline`
3. Reconfirm Linux-native builder behavior on `88.99.197.234`:
   - `builder_backend_select::tests::auto_detect_default_for_linux_native_picks_qemu`
   - `libkrun_builder::tests::linux_native_rootfs_builder_support_guard_matches_platforms`
4. Confirm the admitted backend matrix still has readonly overlay proof on the
   exact ship candidate or on release assets built from it.
5. Confirm release docs still say:
   - readonly mount
   - version-matched, not latest
   - stopped VMs restart onto new runtime
   - running VMs do not hot-remount

## Release candidate checks

The release pipeline must publish the runtime overlay assets for each supported
architecture:

- `runtime-overlay-aarch64.ext4`
- `runtime-overlay-aarch64.verity`
- `runtime-overlay-aarch64.roothash`
- `runtime-overlay-aarch64.VERSION`
- `runtime-overlay-aarch64-checksums-sha256.txt`
- `runtime-overlay-x86_64.ext4`
- `runtime-overlay-x86_64.verity`
- `runtime-overlay-x86_64.roothash`
- `runtime-overlay-x86_64.VERSION`
- `runtime-overlay-x86_64-checksums-sha256.txt`

Verify:

1. The release tag version matches the workspace version.
2. The published `runtime-overlay-<arch>.VERSION` file matches that release.
3. `mvmctl build runtime-overlay build --source download` resolves the expected
   asset set into `~/.cache/mvm/runtime-overlay/<version>/<arch>/`.

## Rollout procedure

### Fresh hosts / fresh starts

1. Install or update `mvmctl` to the released version.
2. Optionally prefetch the runtime overlay:

```bash
mvmctl build runtime-overlay build --source download
```

3. Start the workload normally.
4. Confirm the guest sees `/mvm/runtime` mounted read-only on the selected
   admitted backend.

### Existing stopped VMs

1. Update the host to the new `mvmctl` release.
2. Ensure the matching runtime overlay is present or downloadable.
3. Start or restart the stopped VM.
4. Confirm it booted on the expected runtime-overlay version.

### Already-running VMs

1. Update the host to the new `mvmctl` release.
2. Do **not** expect the running VM to change immediately.
3. Restart the VM when you are ready for it to adopt the new runtime.

This is the intended update flow. There is no in-place remount or live rebinding
of the runtime overlay inside a live guest.

## Rollback procedure

If the new release must be reverted:

1. Downgrade `mvmctl` on the host to the previous known-good release.
2. Ensure that release's runtime-overlay assets are still available.
3. Restart affected VMs.

Expected result:

- running VMs continue on the runtime they already booted with until restart
- restarted VMs resolve the downgraded release's matching overlay

Do not try to "repair" a running VM by manually replacing files under
`~/.cache/mvm/runtime-overlay/...` and expecting a live guest remount. That is
outside the product contract.

## Release note template

When cutting the release candidate or final release, include a note equivalent
to the following:

> This release ships the readonly guest-runtime overlay as a first-class
> versioned artifact under `~/.cache/mvm/runtime-overlay/<version>/<arch>/`.
> Only guest-executed runtime binaries live in that overlay; host-side helpers
> remain in the host bundle. Admitted overlay-backed backends mount the runtime
> artifact read-only. Running VMs keep the runtime they booted with until
> restart; stopped VMs pick up the new version-matched runtime on the next
> start/restart. Linux rootfs-backed libkrun builder use remains fail-closed and
> is not silently admitted.

If the release must be rolled back, pair the binary downgrade with a VM restart
so restarted guests resolve the matching older runtime overlay.

## Backend expectations

| Surface | Production expectation |
|---|---|
| Firecracker workload | readonly overlay mounted and proven |
| qemu workload | readonly overlay mounted and proven |
| libkrun workload | readonly overlay mounted and proven |
| HVF workload | readonly overlay mounted and proven |
| qemu builder | readonly overlay mounted and proven |
| HVF builder | readonly overlay mounted and proven |
| Linux rootfs-backed libkrun builder | refused fail-closed |

## Ship / no-ship rule

Do not call the rollout shipped just because the branch tests are green.

It is shipped only when all of the following are true:

1. The code is merged through the normal review path.
2. The release tag is cut.
3. The runtime-overlay assets are published for that exact release.
4. The release docs and operator guidance match the runtime contract.
5. At least one real release-candidate verification pass has been recorded for
   the ship commit.
