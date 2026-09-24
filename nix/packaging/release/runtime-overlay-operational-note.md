## Operational note: readonly guest-runtime overlay

This release ships the shared readonly guest-runtime overlay as a versioned
artifact under `~/.cache/mvm/runtime-overlay/<version>/<arch>/`.

- Only **guest-executed** runtime binaries belong in that overlay; host-side
  helpers remain in the host bundle.
- Admitted overlay-backed backends mount the runtime artifact read-only.
- Fresh starts resolve the matching runtime overlay automatically.
- Running VMs keep the runtime they booted with until restart.
- Existing stopped VMs pick up the new version-matched runtime on the next
  start/restart.
- Already-running VMs do not hot-remount or live-swap the runtime overlay.
- Linux rootfs-backed libkrun builder use remains fail-closed and is not
  silently admitted.

If you roll this release back, pair the binary downgrade with a VM restart so
restarted guests resolve the matching older runtime overlay.

## Image support window

Boot images for this release come from the `mvm-images` image set pinned in
`crates/mvm-core/images.lock`. The image assets attached to this release are
byte-identical mirrors of that set, checked against its signed root before they
were signed here. Earlier releases and `boot-image/v*` releases remain
published; the legacy image producer's lock entry is kept until 2026-12-31.
See the [releases reference](https://github.com/tinylabscom/mvm/blob/main/public/src/content/docs/reference/releases.md#image-releases-and-the-support-window)
for which CLI versions read which URLs.
