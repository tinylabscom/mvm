# Aarch64 vsock permission and merge-queue download retry

The aarch64 QEMU lane grants its runner user access to `/dev/vhost-vsock`
before the live TCG witness. That correction is already present on `main`, so
the branch contributes no duplicate permission change.

The first merge-queue attempt exposed a separate workflow reliability defect:
the pinned, checksum-verified actionlint download failed on a connection reset
and `curl --retry 3` did not retry that error class. The download now uses
`--retry-all-errors` with a bounded two-second delay while preserving the
existing three-attempt limit, pinned version, and checksum verification.

Validation covers actionlint over every workflow, workflow-path policy,
formatting, sprint append, plan names, and the CI workflow's exact bounded
retry arguments.

The next scheduled Security run exposed a separate claim-18 witness gap in
backend capability negotiation. Its mutation shard could delete the WebLinux
transport arm because the wildcard silently substituted the UDS route. Both
backend matches are now exhaustive, so a new or missing backend is a compile
failure, and a focused WebLinux test pins the browser-channel alternative.

The merge-group AArch64 witness then reached the before-build lifecycle hook
and exposed an image-path mismatch: the hook runner invoked bare `mount`, so
the inherited PATH selected BusyBox instead of the installed util-linux
binary. BusyBox passed `loop` through as an ext4 option, the hook failed after
the expensive build, and no `rootfs.ext4` was returned. The runner now invokes
the image contract's explicit `/sbin/mount`; a focused constant regression
pins that selection so PATH ordering cannot silently restore the broken path.
The AArch64 live lane also opts out of the embedded-host-binary cache while it
builds `mvmctl`, ensuring source changes to the builder guest are cross-compiled
and injected rather than hidden by a restored stale binary.
