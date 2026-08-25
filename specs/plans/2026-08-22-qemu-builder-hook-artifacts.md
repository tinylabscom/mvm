# QEMU builder hook artifact preservation

Backing: shipped-source
Validation: focused shell-rendering, loop-device parsing, CI aggregate, and
workflow-structure tests plus the merge-group AArch64 QEMU TCG witness.

**Status:** IN PROGRESS
**Date:** 2026-08-22
**Owner:** mvm

## Failure

The AArch64 no-KVM bundle smoke completed its builder VM job with exit code 0
but produced no `rootfs.ext4`. The console contained the earlier causal error:
ext4 rejected `loop` as an unknown filesystem parameter while the
`before_build` hook runner tried to mount the file-backed image.

After artifact preservation was repaired, the live witness reached the
workload launch and exposed a separate architecture gap: the workload driver
selected `qemu-system-aarch64` without the mandatory `virt` machine and still
used the x86 serial-console default. QEMU exited before daemonizing, and
transient cleanup removed its log before the workflow diagnostic step could
read it.

After that launch gap was repaired, QEMU booted but the first authenticated
agent handshake saw `ConnectionReset` while the TCG guest was still coming up.
Activation already retries transport-level peer hangups for 30 seconds, but
the host handshake had flattened `SessionError::Io` into message text, hiding
the typed cause from the retry classifier and turning an ordinary readiness
race into an immediate failed launch.

After readiness was repaired, the merge-group witness reached guest workload
activation and exposed an ext4 journal that still required recovery. The
workload rootfs is intentionally attached read-only, so the guest could not
replay the journal and correctly refused to mount it. The writable builder
mount must therefore be torn down and the journal sealed before publication.

Manual workflow run 32763211862 proved that sealing only inside the builder
image's hook-runner binary is insufficient for the release-bootstrap witness:
that lane deliberately boots the last published builder VM while exercising
job scripts rendered by the source checkout. The old hook runner returned
success without replaying the journal, and the exact read-only mount failure
recurred. The source-rendered one-shot and persistent job scripts must
therefore run the same fail-closed offline check before copying the artifact.

Two independent defects turned that mount failure into a merged regression:

- the generated job shell used `if ! command; then hook_rc=$?`, so `hook_rc`
  captured the successful result of `!` instead of the hook's non-zero status;
  it removed the staged rootfs and exited 0;
- the no-KVM smoke was not a dependency of the required `Test` aggregate, so
  its eventual failure did not hold the merge group.

## Work

- [x] Reproduce the missing-artifact sequence from the merge-group log and
      trace it to the hook status inversion and `mount -o loop` path.
- [x] Capture the hook command's real status before branching, and prove the
      generated shell no longer uses the status-losing negation form.
- [x] Allocate a validated `/dev/loopN` device explicitly with util-linux,
      mount that block device through the existing syscall wrapper, and use
      RAII to unmount bind mounts/rootfs and detach the loop device on every
      return path.
- [x] Make the AArch64 no-KVM job a dependency of `Test`, while preserving its
      merge-group/manual-only execution contract for ordinary pull requests.
- [x] Share the existing QEMU host-architecture machine and serial-console
      mapping between builder and workload launches, and prove the AArch64
      workload argv selects `-machine virt` plus `console=ttyAMA0`.
- [x] Include a bounded tail of `qemu.log` in pre-daemonization launch errors
      so transient cleanup cannot erase the causal diagnostic.
- [x] Preserve typed host-handshake session errors, retry peer hangups while
      the guest agent becomes ready, keep authenticated rejections fail-closed,
      and emit the redacted guest-console tail before failed transient cleanup.
- [x] Run an offline ext4 journal repair/check after every writable hook mount,
      fail closed on mounted or damaged images, retain `e2fsck` across builder
      GC, and flush every exported rootfs before reporting completion.
- [x] Seal the writable temp image again in the source-rendered one-shot and
      persistent job scripts so a source checkout remains correct when the
      release-bootstrap path intentionally uses an older published builder
      binary; accept only `e2fsck` exit 0/1 before copying the artifact.
- [ ] Pass focused tests, formatting, workspace check/test, all-target Clippy,
      Linux-gated checks, and the live merge-group witness.
- [ ] Record delivery and refactor status, then merge the repair.
