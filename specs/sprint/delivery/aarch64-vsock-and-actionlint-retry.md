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
