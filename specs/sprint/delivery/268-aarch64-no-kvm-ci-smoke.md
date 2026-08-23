# Aarch64 no-KVM bundle smoke test on `ubuntu-24.04-arm`

Added the `aarch64-no-kvm-smoke` job to `.github/workflows/ci.yml`. It runs
only on `merge_group` and `workflow_dispatch` (not per-PR), on a native
`ubuntu-24.04-arm` runner that exposes no nested KVM.

The lane:

1. Builds `mvmctl` with the `release-artifact-bootstrap` feature so it can
   download published builder VM / workload artifacts.
2. Hides the in-repo `nix/images/builder-vm` flake for the duration of the
   test, so `mvmctl` treats the binary as installed and downloads the published
   builder VM image instead of rebuilding it from scratch inside Stage 0 under
   TCG.
3. Boots the sealed `examples/exit_code` workload with
   `mvmctl machine run --builder qemu --hypervisor qemu`, which falls back to
   TCG because `/dev/kvm` is absent. The guest is expected to exit 7.
4. Exports the built slot to a signed `.mvmpkg`.
5. Installs the bundle against the CI-generated host-signer trust anchor.
6. Re-runs the installed bundle with `mvmctl machine run --manifest <sha>
   --hypervisor qemu`, again expecting exit 7.

This is the closest CI approximation to the Raspberry Pi no-KVM path: the
workload rootfs is built through the Stage 0 QEMU builder and the guest boots
via QEMU TCG on a real aarch64 host.

The hosted runner exposes `/dev/vhost-vsock` but leaves it inaccessible to the
runner user. The job transfers that one ephemeral device node to the current
user with mode `0600` before QEMU starts; an `xtask` workflow-structure test
keeps the grant ordered before the first boot.

Diagnostics (`console.log`, `firecracker.log`, `qemu.log`, and the captured
mvmctl output) are dumped on failure, including builder VM state under
`$MVM_HOME/cache/builder-vm/vms`.

The merge-queue witness also caught a QEMU-only drive-layout bug: the QEMU
builder had reused the one-shot libkrun runtime-overlay attachment, whose
kernel command line enables raw-disk job transport. QEMU supplies `/job` and
`/out` through virtio-fs instead, so the guest interpreted the runtime and
identity disks as nonexistent job input/output and never returned a result.
QEMU now shares the virtio-fs runtime-overlay contract used by persistent
builders: `/dev/vdc` is only the read-only runtime overlay, no disk-transport
tokens are present, and the writable job/output shares remain authoritative.
Unit tests pin both the shared attachment and the QEMU call-site contract.

The corrected drive layout then exposed a release-skew compatibility case:
an older published builder init copied the signing key and host anchor but not
the newer empty ingress-target projection from the identity drive. The current
egress client used the signing key alone as its "already provisioned" marker,
so it skipped its own idempotent drive copy and failed closed on the missing
projection. Egress startup now treats all three files as one identity contract
and reprovisions whenever any member is absent. A regression test covers the
two-file legacy state and the complete three-file state.

With identity provisioning repaired, the live lane progressed into the real
Nix workload build and was killed only by the generic 1,800-second builder
deadline while QEMU TCG was still compiling successfully. The no-KVM smoke
now gives that inner builder run 7,200 seconds, within the job's existing
five-hour ceiling; normal accelerated builder runs keep their stricter
30-minute default. The workflow policy test pins the TCG-specific override.

The live witness then exposed two workload-launch gaps hidden by the earlier
builder failures. Builder and workload QEMU launches now share one
architecture mapping, so AArch64 selects the mandatory `virt` machine and the
PL011 `ttyAMA0` console. Once QEMU booted, the first host handshake could race
the slowly starting TCG guest and receive a peer reset. Host handshake context
now preserves the typed session error, allowing the existing bounded
activation retry to treat only peer hangups as readiness races while identity,
signature, and protocol failures remain fail-closed. Failed transient starts
also print a bounded, redacted guest-console tail before deleting their state.
