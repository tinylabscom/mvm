# A workload guest needs the workload kernel, on every arch

`mvmctl machine run --entrypoint --flake examples/exit_code` died in guest
activation:

```
guest activation failed: syscall failed: open /dev/mapper/control: No such file or directory
```

This was the last failure keeping the nightly documented-surface lane red
(`features/suites/s29_doc_examples/documented_build_live.feature:27`), present
in both recent runs and reproducible on the x86_64 KVM box.

## The kernel it booted had no device-mapper, deliberately

The flake build produces no kernel, so `slot_kernel_source` falls through to its
arch branch — and on x86_64 that branch preferred the **builder** kernel:

```
template revision vmlinux              sha256: abd7ed4d1faeae03…
~/.mvm/cache/builder-vm/x86_64/vmlinux sha256: abd7ed4d1faeae03…
```

Byte-identical, and matching the revision's own `vmlinux.elf.src` sidecar.

`nix/images/kernel/builder.nix` force-drops `MD`, `BLK_DEV_DM` and `DM_VERITY`,
and states the reason: the builder VM boots `ro` with no roothash and never
opens a dm device, so *"verified boot is a workload-kernel concern."* A sealed
workload booted on that kernel reaches for a device its kernel was built
without.

## The fix is the rule aarch64 already followed

`slot_kernel_source` preferred the workload kernel on aarch64 and gave
dm-verity as the reason. x86_64 preferred the builder kernel to avoid
disturbing "a previously working boot path" — but that path cannot mount a
sealed rootfs. What the preference preserved was the failure.

x86_64 now prefers the workload kernel too. The builder kernel stays as the
fallback: a host with no workload kernel cached is better served booting an
unsealed guest, which never opens a dm device, than refusing outright. The
ordering is a preference, not a requirement.

Nothing about `mkGuest` or what user flakes produce changes.

## The test pinned the bug

`slot_kernel_source_prefers_builder_kernel_for_x86_64` asserted the broken
preference, which is why no test caught this. It is rewritten to state the rule
with its reason, and joined by one asserting the builder kernel remains the
fallback when no workload kernel is cached — the behaviour that keeps the
change from turning a working unsealed boot into a refusal.

## An analysis that was wrong first

The first diagnosis held that a user flake built its own stock kernel via
`mkGuest`, and proposed either rewiring `mkGuest` to the shared kernel
definition or having the host reject a dm-less built kernel. Both rested on a
misreading: the `MD`/`BLK_DEV_DM`/`DM_VERITY` line in `builder.nix` is in its
*disables* list, not its enables, and the template kernel was not built by the
flake at all — the matching sha256 above is what settled it. Recorded because
the wrong version was plausible enough to survive a first pass, and the thing
that refuted it was a hash comparison rather than more reading.

## Live verification

Same command, same host, on the scenario that was failing:

```
before: EXIT=1   guest activation failed: open /dev/mapper/control: No such file or directory
after:  EXIT=7   the sealed workload's own exit code, which is what the scenario asserts
```

## Validation

68 gates clean · `cargo nextest run --workspace` · `clippy --all-targets
-D warnings` clean · `fmt --all --check` clean · `check-gated` clean with
`RUSTFLAGS=-D warnings` · live witness above.
