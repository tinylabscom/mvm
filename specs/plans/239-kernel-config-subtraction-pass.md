# Plan 239 - Next kernel-config subtraction pass

**Status:** COMPLETE
**Created:** 2026-07-09
**Goal:** make the shared microVM kernel materially smaller by removing unused
kernel features from the generated config in a measured, boot-safe way.

## Why this plan exists

`mvm` already generates its guest kernels from an upstream `defconfig` plus a
scripted delta in `nix/images/kernel/base.nix`, then resolves the final config
with `make olddefconfig`. That gives the project one reproducible kernel recipe,
but it also means every default that survives the current `scripts/config`
subtractions still ships unless it is explicitly cut.

Plan 209 established the long-term slim-kernel direction and the config-budget
idea. This plan is the next concrete subtraction pass: audit the generated
config, remove whole dead subsystems where the workload and builder paths do not
need them, and record the measured result.

## Non-goals

- Do not change the rootfs model, dm-verity posture, or backend contract.
- Do not merge builder-only and workload-only kernel requirements back together.
- Do not introduce hand-edited committed `.config` files as the source of truth.
  The source of truth remains the generated recipe under `nix/images/kernel/`.
- Do not land speculative removals. Every cut needs a direct usage audit and a
  boot or runtime witness.

## Current state

- `nix/images/kernel/base.nix` runs `make defconfig`, applies
  `scripts/config --enable/--disable`, then runs `make olddefconfig`.
- `nix/images/kernel/builder.nix` adds the builder-only delta.
- `nix/images/kernel/workload.nix` adds the workload-only delta.
- Plan 209 already calls for a config-budget gate and audit-driven subtraction,
  but it does not spell out the next concrete candidate list or the exact proof
  sequence for the next reduction pass.

## Kernel-config generation contract

The generated final config is authoritative.

For each kernel variant, the recipe is:

1. unpack the pinned Linux source,
2. run `make defconfig`,
3. apply explicit `scripts/config` enables and disables,
4. run `make olddefconfig`,
5. use the resolved `.config` for the actual build.

Any subtraction in this plan must be judged against the resolved `.config`, not
only against the source enable/disable lists.

## Phase 0 - Make the resolved config easy to inspect

**Goal:** ensure every subtraction pass starts from the actual resolved config.

- [x] Confirm there is a first-class way to build and inspect the resolved
      configfile for both builder and workload kernels.
- [x] If needed, add or document dedicated outputs or commands so a reviewer can
      diff the resolved config before and after a subtraction pass.
- [x] Record the current baseline for:
      `vmlinux` size,
      compressed kernel size,
      `=y` symbol count.

**Validation**

- `nix build ./nix/images/kernel#metrics`
- `cargo run -p xtask -- check-kernel-config-budget` if already wired

## Phase 1 - Workload-first candidate audit

**Goal:** cut obvious dead weight from the workload kernel before touching the
shared base.

Audit these candidates first, because they are common distro defaults but may be
unnecessary in a sealed workload guest:

- [x] `BPF`
- [x] `BPF_SYSCALL`
- [x] `PERF_EVENTS`
- [x] `PROFILING`
- [x] `IKCONFIG`
- [x] `IKCONFIG_PROC`
- [x] `CHECKPOINT_RESTORE`
- [x] `POSIX_MQUEUE`

For each candidate:

- [x] Trace whether the workload boot path, guest agent, runtime helpers, or
      admitted workload behavior actually uses it.
- [x] If workload-only dead, disable it in `workload.nix`; only move a cut into
      `base.nix` if the builder kernel also provably does not need it.
- [x] Keep a short rationale next to the disable in the Nix file explaining the
      invariant, not any plan reference.

**Validation**

- workload-kernel build still succeeds
- workload boot smoke still succeeds
- any relevant guest-agent or runtime smoke still succeeds

## Phase 2 - Compression and initramfs surface audit

**Goal:** keep only the compression and initramfs support the project actually
ships.

- [x] Audit the enabled kernel compression formats and keep only the ones the
      built artifacts use.
- [x] Audit the `RD_*` decompressor symbols and keep only the formats the boot
      path actually accepts.
- [x] Audit initramfs compression choices in the same way.
- [x] Land cuts one class at a time so failures are attributable.

**Validation**

- kernel build still succeeds for both variants
- boot smoke still succeeds for the backends that consume the kernel artifact
- measured kernel-size deltas are recorded after each accepted cut

## Phase 3 - Workload size-mode experiment

**Goal:** test whether the workload kernel should optimize for size instead of
performance.

- [x] Build the workload kernel with `CONFIG_CC_OPTIMIZE_FOR_SIZE`.
- [x] Compare against the current workload kernel on:
      `vmlinux` bytes,
      compressed image bytes,
      boot success,
      any obvious runtime regressions.
- [x] Keep the size-oriented mode only if the measured win is meaningful and the
      operational behavior remains acceptable.

**Validation**

- before/after kernel metrics
- workload boot smoke
- targeted runtime smoke using the workload kernel

## Phase 4 - Shared-base subtraction pass

**Goal:** after the workload-only cuts are exhausted, reduce the common kernel
surface safely.

- [x] Re-read the resolved builder and workload configs after Phases 1 to 3.
- [x] Enumerate surviving `=y` subsystems that are still unjustified in
      `base.nix`.
- [x] For each candidate, prove neither the builder path nor the workload path
      needs it before moving the cut into `base.nix`.
- [x] Prefer disabling whole dead subsystem menus over individual leaf drivers.
- [x] Keep builder-specific needs in `builder.nix` and workload-specific needs in
      `workload.nix`; use `base.nix` only for truly shared removals.

**Validation**

- builder kernel still boots its dev/build path
- workload kernel still boots its runtime path
- kernel metrics improve or the candidate is reverted

## Phase 5 - Budget and regression gate refresh

**Goal:** make successful shrinkage sticky.

- [x] Update the recorded kernel budget after accepted cuts.
- [x] Ensure the config-budget gate reflects the new baseline instead of the old
      larger one.
- [x] If the current metrics output is too weak to justify future reviews, expand
      it enough to capture the kernel-size shape that this plan changes.

**Validation**

- `cargo run -p xtask -- check-kernel-config-budget`
- any CI lane that already enforces the gate stays green

## Sequencing

1. Expose and record the resolved config baseline.
2. Audit workload-only candidates first.
3. Audit compression and initramfs support.
4. Run the workload size-optimization experiment.
5. Do a shared-base subtraction pass only after the earlier cuts are proven.
6. Refresh the budget gate.

## Completion criteria

- The resolved config for builder and workload kernels is easy to inspect and
  diff.
- At least one measured subtraction pass lands with a smaller kernel and green
  boot witnesses.
- The accepted cuts are recorded in the kernel recipe, not in an ad hoc local
  config file.
- The config-budget gate is updated so the smaller shape becomes the new floor.

## Current measured state

- Builder kernel (`aarch64`): `16,998,408` bytes raw, `7,562,916` bytes gzip,
  `1364` built-in symbols.
- Workload kernel (`aarch64`): `15,796,232` bytes raw, `7,010,163` bytes gzip,
  `1320` built-in symbols.
- Workload sizeopt experiment (`aarch64`): `13,881,352` bytes raw,
  `5,951,074` bytes gzip, `1320` built-in symbols.
- The sizeopt config diff is currently limited to
  `CONFIG_CC_OPTIMIZE_FOR_PERFORMANCE` vs
  `CONFIG_CC_OPTIMIZE_FOR_SIZE`; it materially shrinks the image but does not
  reduce the built-in symbol count.
- Decision: keep `workload-sizeopt` as an explicit comparison output, not the
  default workload kernel. The size win is real, but this pass does not flip
  the default workload mode while the current default kernel remains the
  better-proven production path.
- The `mvmctl build kernel build --boot-check` helper now boots the pinned
  workload kernel through the OCI `--image` path and polls the guest agent
  directly instead of relying on full `machine wait` readiness.
- Live witness: `./target/debug/mvmctl machine run --image
  docker.io/library/alpine:3.20 --hypervisor hvf --kernel-pin workload --
  /bin/true` exits `0` on this host, proving the pinned workload kernel still
  boots the sealed OCI workload path after the accepted cuts. The stronger
  current-tree witness is now green too: `cargo run -- --builder libkrun build
  kernel build --which workload --source compile --boot-check` rebuilds on the
  synced tree and confirms the guest agent over vsock.
- The resolved builder and workload configs both carry `CONFIG_INITRAMFS_SOURCE=""`
  and `CONFIG_RD_GZIP=y` with every other `CONFIG_RD_*` decompressor disabled;
  the shipped verity path in the repo is consistently `cpio.gz`, so the shared
  kernel keeps gzip support only.
- Shared-base follow-up: `CONFIG_AUDIT` is now force-dropped in `base.nix`.
  Linux 6.12's `AUDITSYSCALL` rides `AUDIT && HAVE_ARCH_AUDITSYSCALL`, and the
  sealed workload boot/runtime path, guest agent, seccomp path, dm-verity
  path, and admitted workload behavior do not consume kernel audit or
  `NETLINK_AUDIT`. The shipped audit posture is the userspace, chain-signed
  `host.audit.v1` flow (`mvm-hostd`, signer, verifier), so dropping the kernel
  audit subsystem is safe for both workload and builder kernels. The refreshed
  builder/workload metrics above include that cut.
- Shared-base follow-up: `CONFIG_BPF_JIT` is now force-dropped in `base.nix`.
  Linux 6.12's `kernel/bpf/Kconfig` describes the JIT as an optional speedup
  for loaded BPF programs; the interpreter remains present with `CONFIG_BPF=y`.
  Seccomp's cBPF filters still run through the in-kernel interpreter path, and
  neither the sealed workload nor the builder path ships a BPF loader, touches
  `/proc/sys/net/core/bpf_jit_*`, or uses xt_bpf/classifier programs. Result:
  keeping core `CONFIG_BPF=y` while dropping the native-code JIT surface is
  safe for both kernels, and the refreshed metrics above include that cut.
- `CONFIG_BPF` remains `=y` in the resolved workload config because Linux
  6.12's `menuconfig NET` unconditionally `select BPF`. The workload cannot
  drop `NET`: `VSOCKETS` / `VIRTIO_VSOCKETS` live under the networking menu and
  the guest agent, exit reporter, console forwarding, and addon bridges all use
  `AF_VSOCK`; admitted `--net` / `--allow-host` workloads also depend on the
  in-guest loopback TCP helpers (`mvm-egress-client`, addon DNS/bridges) and
  `mvm-guest-netinit`'s `AF_NETLINK` route installs. `SECCOMP`,
  `SECCOMP_FILTER`, and `DM_VERITY` do not keep BPF on. Result: keeping
  `BPF_SYSCALL` off is safe and landed, but a full workload-side `CONFIG_BPF`
  removal is not safe without dropping the current workload networking/runtime
  contract.
- The post-sync `mvm-kernel-config` `make defconfig` regression is fixed in the
  kernel recipe now: Linux Kconfig's `$(shell,...)` helper goes through
  `popen()` and therefore requires a real `/bin/sh` inside the Nix sandbox. The
  config builder now provides it explicitly before `make defconfig`, so fresh
  compile + boot-check witnesses are green again on the synced tree.
