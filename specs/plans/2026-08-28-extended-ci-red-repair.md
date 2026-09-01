# Extended CI red repair

Backing: shipped-source
Validation: check-sprint-append

**Issues:** [#2979](https://github.com/tinylabscom/mvm/issues/2979),
[#3007](https://github.com/tinylabscom/mvm/issues/3007),
[#3051](https://github.com/tinylabscom/mvm/issues/3051),
[#3052](https://github.com/tinylabscom/mvm/issues/3052)

## Outcome

The scheduled Extended CI witnesses use platform-correct prerequisites and a
launchable macOS runner, and an installed portable bundle can be launched by
the SHA-256 address printed by `mvmctl bundle install`. The repair preserves
the bundle protocol's existing SHA-256 content address; it does not introduce
a competing BLAKE3 address or re-hash the archive.

## Failure boundaries

- Linux invoked a combined helper recipe that enabled `libkrun-sys`, even
  though the Linux job neither uses libkrun nor installs its headers.
- Both documented-surface jobs invoked the SDK codegen witness through `uvx`
  without installing `uv`, and neither warmed the source-matched SDK sidecar.
- `bundle install` printed a launch command using the installed bundle's
  64-character SHA-256, but `resolve_manifest_arg` treated every such value as
  a manifest-path slot and never reached the existing slot-or-bundle runtime
  dispatcher.
- `macos-latest` selected an arm64 hosted VM whose Hypervisor.framework call
  returned `HV_UNSUPPORTED`. The live witness now uses the current Intel runner
  label rather than pretending a skipped arm64 boot is evidence.
- The first repaired rerun exposed two follow-on portability gates: repository
  policy rejected an unpinned `setup-uv`, and the Intel runner could not install
  the arm64-only libkrun firmware. The workflow now pins the shared uv action and
  tool version, while Intel builds the HVF path without the libkrun feature or
  supervisor. Apple Silicon retains the existing libkrun-backed builder path.
- The next Linux documented-surface rerun reached the source SDK sidecar build,
  then QEMU could not read the hosted runner's protected `/boot` kernel. The
  workflow now grants unprivileged QEMU read access to the exact running kernel
  and initramfs before Stage 0 starts.
- With those files readable, the same rerun reached QEMU device creation and
  exposed that `/dev/vhost-vsock` was still root-owned. The job now transfers
  that single device to the runner user with mode `0600` before Stage 0 starts.
- The next rerun completed the SDK-sidecar guest build, then the host extractor
  tried to preserve root ownership with `debugfs rdump` and ignored the three
  SDK-sidecar outputs. QEMU Stage 0 now dumps only the allow-listed artifacts
  without ownership preservation, including the image, version, and checksums.
- The first full rerun proved the Intel HVF witness still auto-selected
  libkrun for Stage 0 even though libkrun is ARM-only on macOS. The job now
  installs QEMU and explicitly selects it for Stage 0 artifact construction;
  workload scenarios remain on HVF, with a bounded 90-minute cold-run deadline.
- The next scheduled Linux rerun reached the documented service-plane witness
  and exposed three clean-run prerequisites: the hosted runner lacked
  `virtiofsd`, unprivileged ICMP sockets excluded the runner group, and
  transient `--mount` treated a pre-materialized ext4 fixture as a live
  directory share. The workflow now installs the missing daemon and grants the
  runner group ICMP sockets. Transient launch resolution preserves disk-image
  mounts as backend-agnostic block volumes while continuing to capability-gate
  live directory shares.
- The first rerun on the fully merged queue exposed a cross-checkout artifact
  hole: the warm-up treated an existing initramfs file as current without
  invoking the source-fingerprint gate. The lane therefore tested the latest
  host binary against an older guest agent, producing dm-verity, FlowMux,
  stop-drain, and warm-readiness failures that disagreed with the checked-in
  guest code. The warm-up now always enters launch resolution so stale guest
  binaries are evicted and rebuilt. The same run exposed Firecracker's u8
  machine-config boundary and two stale BDD assertions; the backend now
  declares that vCPU ceiling, while the witnesses preserve child exit status
  and stderr ownership.
- The next complete Linux witness exposed two residual boundaries: persistent
  machine launches bypassed the backend vCPU clamp, and authenticated frame
  reads erased the I/O source needed to recognize `EAGAIN`. The persistent path
  now clamps before admission, and frame errors preserve their typed source.

## Delivery checklist

- [x] Reproduce all three failed jobs from Extended CI run 33192385988.
- [x] Add structural regressions for platform-scoped helper builds, `uv`, the
      source-matched SDK sidecar, and the live macOS runner selection.
- [x] Add a resolver regression proving an installed bundle SHA-256 reaches
      the bundle registry while materialized slots retain identity checking.
- [x] Build the portable host helpers on every host, require a detected header
      for the optional libkrun helper, and keep the Intel witness free of the
      libkrun FFI feature and arm64-only firmware installation.
- [x] Install a repository-pinned `uv` in both documented-surface jobs and build
      the checkout's SDK sidecar once before the live scenarios.
- [x] Reuse `template_load_dispatched` for ambiguous 64-character slot or
      bundle addresses.
- [x] Pin the live HVF witness to `macos-15-intel` instead of the unsupported
      arm64 hosted VM selected by `macos-latest`.
- [x] Pass focused Extended CI contracts, all shared resolver tests, formatting,
      and zero-warning `mvm-cli` Clippy.
- [x] Rebase onto the latest merged `main` and pass full workspace and repository
      gates.
- [x] Repair the fresh rerun's action-pin invariant and Intel/arm64 libkrun
      mismatch with structural regressions.
- [x] Repair the Linux hosted-kernel permissions with a structural regression
      covering both Stage 0 boot files.
- [x] Repair the Linux Stage 0 vhost-vsock permissions with a structural
      regression covering ownership, mode, and read/write access.
- [x] Make QEMU Stage 0 extraction ownership-neutral and include the complete
      SDK-sidecar artifact contract in its allow-list.
- [x] Route Intel-hosted Stage 0 builds through an installed QEMU without
      changing the workload backend from HVF.
- [x] Install `virtiofsd` and grant unprivileged ICMP sockets on the hosted
      Linux witness, with structural workflow regressions.
- [x] Carry read-only disk-image `--mount` values through transient launch
      resolution without weakening directory-share backend refusal.
- [x] Pass the focused mount, receipt/preflight, workspace, gated, formatting,
      and zero-warning Clippy checks for the follow-on repair.
- [x] Revalidate the universal initramfs source fingerprint on every live
      warm-up, with a structural regression forbidding file-existence shortcuts.
- [x] Declare Firecracker's u8 vCPU wire ceiling and cover the advertised
      capability so oversized portable requests clamp before serialization.
- [x] Reconcile the live refusal witnesses with the child process exit code,
      stderr channel, and fail-closed timeout-admission contracts.
- [x] Clamp persistent-machine vCPU requests before admission and Firecracker
      machine-config serialization.
- [x] Preserve `WouldBlock` through authenticated control-frame context so the
      existing bounded liveness loop can retry sustained transfers.
- [ ] Pass focused formatting, Clippy, workspace, gated, and policy checks for
      the residual repair.
- [ ] Pass a fresh Extended CI run containing all repaired witness lanes.
- [ ] Merge the corrective pull request and close #3007 through its linkage.
