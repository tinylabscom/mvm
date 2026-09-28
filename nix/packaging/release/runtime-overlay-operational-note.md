## Operational note: readonly guest-runtime overlay

The shared readonly guest-runtime overlay is a member of the image set this
release pins. It is cached under
`~/.mvm/cache/image-set/<root-sha256>/runtime-overlay/<member-version>/<arch>/`,
keyed by the pinned root rather than by this release's version, so a CLI
release that keeps the same pin reuses the cached overlay.

- Only **guest-executed** runtime binaries belong in that overlay; host-side
  helpers remain in the host bundle.
- Admitted overlay-backed backends mount the runtime artifact read-only.
- Fresh starts resolve the matching runtime overlay automatically.
- Running VMs keep the runtime they booted with until restart.
- Existing stopped VMs pick up the runtime this release resolves on the next
  start/restart.
- Already-running VMs do not hot-remount or live-swap the runtime overlay.
- Linux rootfs-backed libkrun builder use remains fail-closed and is not
  silently admitted.

If you roll this release back, pair the binary downgrade with a VM restart so
restarted guests resolve the runtime overlay the older release pins.

## Image support window

Boot images for this release come from the `mvm-images` image set pinned in
`crates/mvm-core/images.lock`, and are fetched from that set and verified
against its signed root; this release carries no image assets. Earlier
releases and `boot-image/v*` releases remain published; the legacy image
producer's lock entry is kept until 2026-12-31.
See the [releases reference](https://github.com/tinylabscom/mvm/blob/main/public/src/content/docs/reference/releases.md#image-releases-and-the-support-window)
for which CLI versions read which URLs.
