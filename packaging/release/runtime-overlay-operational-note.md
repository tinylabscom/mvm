## Operational note: readonly guest-runtime overlay

This release ships the shared readonly guest-runtime overlay as a versioned
artifact under `~/.cache/mvm/runtime-overlay/<version>/<arch>/`.

- Only **guest-executed** runtime binaries belong in that overlay; host-side
  helpers remain in the host bundle.
- Admitted overlay-backed backends mount the runtime artifact read-only.
- Running VMs keep the runtime they booted with until restart.
- Stopped VMs pick up the new version-matched runtime on the next
  start/restart.
- Linux rootfs-backed libkrun builder use remains fail-closed and is not
  silently admitted.

If you roll this release back, pair the binary downgrade with a VM restart so
restarted guests resolve the matching older runtime overlay.
