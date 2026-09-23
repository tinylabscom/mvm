# GitHub Actions open-issue repair

Backing: shipped-source
Validation: check-sprint-append

**Issues:** [#3601](https://github.com/tinylabscom/mvm/issues/3601),
[#3598](https://github.com/tinylabscom/mvm/issues/3598),
[#3495](https://github.com/tinylabscom/mvm/issues/3495), and
[#3428](https://github.com/tinylabscom/mvm/issues/3428)

## Outcome

Restore the scheduled Security and Extended CI lanes, restore current
claim-bearing evidence, and move both kernel consumers to the latest Linux
6.12 LTS point release reported by the freshness watcher.

## Checklist

- [x] Reproduce every current scheduled-lane failure and separate deterministic
      defects from secondary freshness symptoms.
- [x] Make the mutation harness retain Git metadata and remove the retired
      `mvm-build/pure-mkfs` feature from its package invocation.
- [x] Incorporate the runtime and backend mutation witnesses merged by #3610
      while this repair was in progress.
- [x] Keep the privileged warm-claim run off the hosted runner user's session
      bus and gate the workflow shape.
- [x] Preserve the complete Firecracker warm-restore error chain and carry the
      standby parent's FlowMux identity drive through checkpoint capture and
      child materialization.
- [x] Keep the sealed agent-workload example on its baked per-call input path
      and persist the runtime state directory in named-machine registration.
- [x] Verify and synchronize the Linux 6.12.111 source pin for the Nix kernels
      and libkrun firmware.
- [x] Pass focused mutation, workspace, gated-target, Linux Clippy, Nix kernel,
      formatting, and repository-policy validation.
- [ ] Pass the scheduled Security and Extended CI workflows from the repaired
      branch.
- [ ] Merge the issue-linked pull request and close all four issues.

## Kernel source verification

The Linux 6.12.111 archive SHA-256 is
`9e59dc67624188fa12a6601f9598499cd6662a9066be572b59f935e3d7849810`,
which converts to the Nix SRI hash
`sha256-nlncZ2JBiPoSpmAflZhJnNZmKpBmvlcrWfk149eEmBA=`.

The archive matches kernel.org's checksum manifest. Its detached signature
over the uncompressed archive verifies against Greg Kroah-Hartman's stable
release key fingerprint
`647F 2865 4894 E3BD 4571 99BE 38DB BDC8 6092 693E`, the fingerprint published
by kernel.org.

## Rollout

The kernel pin changes newly built workload, builder, and libkrun firmware
artifacts only. It does not modify running VMs. Locally managed VMs move with
`mvmctl vm rekernel`; fleet rollout remains owned by mvmd.
