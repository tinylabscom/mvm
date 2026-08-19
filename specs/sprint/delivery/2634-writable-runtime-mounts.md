# 2634 — writable runtime mounts on a sealed guest root

## Outcome

The universal-initramfs guest now carries dedicated writable `/run` and `/tmp`
tmpfs mounts across the pivot into the verified workload root. The root image
remains read-only; runtime state and scratch files no longer depend on mutating
it.

This completes the issue together with the earlier closeout increments:

- PR #2690 made a missing `eth0` an expected NIC-less topology instead of a
  netinit failure.
- PR #2709 consolidated unavoidable optional read-only setup skips into one
  diagnostic.
- PR #2720 cached the root mount-table decision so optional setup did not
  repeatedly parse `/proc/mounts`.

## Runtime contract

- PID 1 mounts `/run` and `/tmp` as `tmpfs` before activating the workload.
- Both mounts use `nosuid,nodev`; `/tmp` is mode `1777` and `/run` is mode
  `0755`.
- The mounts move into the workload root beside `/proc`, `/sys`, and `/dev`.
- OCI image materialization already creates the sealed mountpoints and folds
  their layout into the image digest.
- Mediated tools can use `/run/mvm/overlay` for their writable overlay, making
  the existing absolute `/bin/ping` workflow functional without changing the
  verified lower layer.
- Optional home and passwd edits are skipped on a read-only root rather than
  issuing syscalls known to fail. Workloads retain writable `/tmp` scratch
  space.

## Verification

- Focused unit tests pin both tmpfs mounts, their pivot participation, and the
  read-only image-write decision.
- The live lifecycle suite now writes a unique file with `mktemp` under `/tmp`
  in an Alpine OCI workload.
- The existing live mediated-tool scenario executes `/bin/ping` and covers the
  `/run` overlay path.
- Repository-wide format, compile, clippy, gated-target, and test commands are
  recorded in the pull request.

The live microVM scenarios remain builder-VM/merge-queue evidence: host-side
runtime commands are intentionally not used for Linux microVM work.
