# VMM-agnostic Stage 0

Stage 0 — the bootstrap that builds the builder VM from nothing — was the last
builder path that reached for a VMM directly instead of going through the
`VmmDriver` seam. It had a hand-written body for libkrun and another for QEMU,
and none for HVF, which is the auto-detected builder on macOS 26+ Apple Silicon.
`stage0_backend_choice` therefore lowered every `Hvf` selection onto `Libkrun`,
and that single lowering was the whole reason a macOS user had to
`brew install slp/krun/libkrun libkrunfw`.

It now runs through `BuilderRunner<D: VmmDriver>` like every other builder job.

## The seam already existed

This turned out to need much less new machinery than expected.
`BuilderRunner<D: VmmDriver>` already packs the input disk, creates the output
disk, mints the FlowMux identity, spawns the host-side egress endpoint, boots,
waits for power-off and reads the artifacts back — with `self.driver.boot(&spec)`
as its only backend-specific line. Four production drivers already sit behind
that seam. `HvfBuilderVm::run_build` was already using it. The Stage 0 arm of the
very same struct returned `VmmUnavailable`.

So the change is mostly deletion of a special case: a `stage0_spec` beside
`builder_spec`, a `BuilderRunner::stage0` beside `build`, and a `BootTransport`
factoring out the per-boot setup the two share. Stage 0 differs from an ordinary
builder job in four ways and no more — a writable seed root, the seed's own
`/init`, a `conf` input tree instead of a rendered `cmd.sh`, and a kernel that
cannot have been built locally.

## Three things worth knowing

**The console tokens now come from the driver.** `BUILDER_CMDLINE` hardcodes
`earlycon=pl011 console=ttyAMA0`, which is correct only because it is only ever
used with HVF. The console device is backend-specific — libkrun exposes `hvc0` —
and Stage 0's console is its *result channel*, since the guest powers off on
success and failure alike. A hardcoded pair would boot one VMM and leave another
with nothing to parse, so `stage0_spec` takes the base from
`VmmDriver::workload_base_bootargs`.

**A latent bug went with it.** The libkrun Stage 0 cmdline omits the
`mvm.hostepoch=` token that both the steady-state builder and the QEMU Stage 0
carry, so `stage0-init`'s clock sync there is a no-op. HVF has no RTC, so a guest
booting without it starts near the epoch and every HTTPS substituter fetch fails
certificate validation. The shared spec appends it unconditionally.

**The guest needed no changes at all.** `stage0-init`'s backend detection is
`is_qemu()` — a sniff for `mvm.backend=qemu`. Everything else takes the same arm,
which wants `mvm.builder_transport=disk` plus vsock egress and finds its Nix
store and identity drive by ext4 label rather than device letter. HVF already
satisfies all of it.

## The bootstrap kernel is a seed, not a build output

The one genuinely hard part. Stage 0 needs a kernel at the moment no builder VM
exists to compile one, and `resolve_kernel` answers a source checkout with
`NeedsBuild` — correct for every other kernel, unsatisfiable for this one.
libkrun escaped via libkrunfw's dylib; QEMU escapes via
`/boot/vmlinuz-$(uname -r)`. Neither generalizes.

`mvm_build::stage0_kernel` classifies it the way Stage 0 already classifies its
root filesystem: as a **seed**. The Nix release tarball is a hash-pinned
published artifact fetched and verified on a contributor checkout, because it is
a means of building rather than the artifact under construction. The bootstrap
kernel is the same kind of thing, so `resolve_bootstrap_kernel_with` passes
`source_checkout: false` unconditionally — that argument *is* the
classification.

The scope is narrow on purpose: it covers that one kernel. The builder image and
the workload kernel keep the local-build invariant, so editing
`nix/images/builder-vm/flake.nix` still shows up on the next boot. And the trust
surface shrinks rather than grows — the bootstrap kernel stops arriving inside a
third-party Homebrew dylib and starts arriving as our own release artifact, held
to a SHA-256 pinned in source — see `stage0-bootstrap-kernel-source-pin.md` for
why it is a source pin rather than the signed manifest this note first
described.

## What is not proven

**No live HVF Stage 0 boot has run.** The workspace suite is green and the boot
contract is checked against all four shipped drivers, but that proves the spec is
well-formed per backend, not that a bootstrap completes. A real run needs a
published `builder-vm-vmlinux-<arch>` to fetch. Treat W3 as wired and
typechecked.

The libkrun body is untouched and remains the fallback whenever the HVF Stage 0
type is not registered, so a failure in the new path costs a `--builder libkrun`
rather than a broken bootstrap.

**Firecracker is not wired**, deliberately. `FcDriver` implements `VmmDriver` and
the boot contract composes onto it, so what remains is a
`BuilderBackendChoice::Firecracker` variant plus a spec-level opt-out for
`FcDriver::boot`'s `mvm-agentd` handshake — which a `stage0-init` guest will
never answer. That is the real blocker, and it is small and specific.

## Stale facts corrected along the way

`CLAUDE.md` claimed libkrun was the auto-detect default on Linux and macOS 13–25,
described an `hvf → libkrun` auto-fallback, said the builder VM has a NIC, and
pointed at a `legacy::{libkrun,qemu,hvf}` module path. None of those were true:
auto-detect is `Apple Silicon macOS → hvf; everything else → qemu` with libkrun
nowhere in it, `builder_attempt_order` returns a single element in every branch,
the libkrun and HVF builders are NIC-less with vsock egress (QEMU's slirp NIC is
the outlier), and there is no `legacy` directory.

One of those is a live hole rather than a doc bug: on **macOS 13–25 Apple
Silicon**, auto-detect answers hvf, hvf reports the macOS 26 floor as
unavailable, and with no fallback the user is stuck unless they pass
`--builder libkrun` by hand. Documented, not fixed.
