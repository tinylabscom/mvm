# A guest kernel without device-mapper now says so

`mvmctl machine run --entrypoint --flake examples/exit_code` fails during
guest activation:

```
1: activate workload after boot
2: guest activation failed: syscall failed: open /dev/mapper/control: No such file or directory
```

Reproduced on the x86_64 KVM box against current main, so this is a product
defect rather than CI state. It is one of the two failures that had kept the
nightly documented-surface lane red.

## What the error was actually about

The guest kernel has no device-mapper, so nothing ever registers the control
node that dm-verity opens. devtmpfs *was* mounted and the mount path was
entirely correct — the message pointed at the one part of the system that was
working.

The session VM boots a flake-built kernel out of the template:

```
kernel_image_path: ~/.mvm/templates/<hash>/artifacts/revisions/.../vmlinux.elf
```

| kernel | "device-mapper" strings | `dm_ioctl` / `dm_table` |
| --- | --- | --- |
| shared workload kernel (`nix/images/kernel/`) | 149 | present |
| flake-built template kernel | **0** | **absent** |

`vm::template::lifecycle::artifacts::slot_kernel_source` returns a flake-built
`vmlinux` unconditionally when one exists, and `nix/lib/mk-guest.nix` does not
reference the shared kernel definition at all — only `default-tenant` and
`builder-vm` do. So a user flake gets a stock kernel where device-mapper is a
module rather than built in. That function's own comment concedes the
dependency ("AArch64 guests need the workload kernel's platform and dm-verity
support"), but the built-kernel branch runs ahead of that reasoning on every
arch.

## What this change does, and does not

It does **not** change which kernel boots. Making user-flake images boot a
dm-capable kernel is a decision about what a user flake produces — either
`mkGuest` builds from the shared kernel definition, or `slot_kernel_source`
refuses a built kernel that lacks device-mapper — and neither belongs in a
diagnosability fix. The root cause is filed with the evidence above.

What it changes is that the next person to hit this is told what happened.

**The error names the cause.** A missing control node is now reported as "this
guest kernel has no device-mapper", naming `CONFIG_BLK_DEV_DM` and explicitly
ruling out the mount reading. The bare `No such file or directory` sent this
investigation through the guest's early-mount ordering, the in-tree kernel
config, and the published kernel artifact — three wrong answers, each of which
had to be measured to be discarded — before reaching the kernel that had
actually booted.

Only `NotFound` is classified. A permission or busy failure keeps the plain
syscall shape, because a confident wrong answer is worse than the unhelpful one
it replaces, and there is a test for that.

**The e2e warm-up stops reporting failure as success.** It printed
`warm-up done (10s)` for a step that cannot build a universal initramfs in ten
seconds: the command's output went to `/dev/null`, so a warm-up that failed in
seconds was indistinguishable from one that succeeded in seconds, and the suite
then ran every scenario against whatever happened to be cached. It now reports
the exit code and the last twenty lines, and stays non-fatal — the scenarios
still fail on their own terms.

## A test that was rewritten before it landed

The first version of the error test asserted against a copy of the message it
had built itself, so it would have passed with the production path deleted.
`dm_control_open_error` is split out so the test calls the real function.
Both are `cfg(target_os = "linux")` and therefore invisible to a macOS `cargo
test`; they were run on the Linux box to confirm they execute rather than
silently compile out.

## Validation

67 gates clean · `cargo nextest run --workspace` 12979 passed · doctests clean ·
`clippy --all-targets -D warnings` clean · `fmt --all --check` clean ·
`check-gated` clean with `RUSTFLAGS=-D warnings` · both new tests confirmed
passing on Linux · `bash -n` clean on the harness change.
