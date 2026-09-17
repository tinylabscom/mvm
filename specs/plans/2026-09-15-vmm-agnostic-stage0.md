# VMM-agnostic Stage 0

Backing: shipped-source
Validation: check-declared-backing

**Status: W1–W7 COMPLETE** (HVF Stage 0 and x86_64 Firecracker Stage 0 + builds live-proven — see Validation).

Stage 0 — the bootstrap that builds the builder-VM image from nothing — was the
last builder path that talked to a VMM directly instead of through the
`VmmDriver` seam. It had two hand-written bodies
(`libkrun_builder::run_stage0_impl` and `qemu_builder::run_stage0_qemu`) and
none on HVF, which is the auto-detected builder on macOS 26+ Apple Silicon, so
`stage0_backend_choice` lowered `Hvf` to `Libkrun` — and that single lowering
was the entire reason a macOS user had to
`brew install slp/krun/libkrun libkrunfw`.

This plan lowers Stage 0 onto `BuilderRunner<D: VmmDriver>`, which already does
Stage 0's exact job generically for ordinary builder jobs, and gives the
bootstrap kernel a provenance that does not come from a third-party dylib.

## Why this shape

`BuilderRunner<D: VmmDriver>` (`crates/mvm-runtime/src/builder_runner/runner.rs`)
already packs an input disk, creates an output disk, mints a FlowMux identity,
spawns the host-side vsock egress endpoint, boots, waits, and reads the output
disk back. The only backend-specific line in it is `self.driver.boot(&spec)`.
Four production drivers implement that seam — `HvfDriver`, `FcDriver`,
`QemuDriver`, `LibkrunDriver` — plus `MockDriver` for tests.

Stage 0 differs from an ordinary builder job in four ways and no more:

| | ordinary builder job | Stage 0 |
|---|---|---|
| root disk | built builder rootfs, `ro` | nix-seed `root.ext4`, `rw` |
| `init=` | `/sbin/mvm-host-vm-init` | `/init` (`stage0-init`) |
| input trees | `job`, `work`, `mvm-bins` | `work`, `mvm-bins`, `conf` |
| kernel | the builder kernel it built earlier | a bootstrap kernel — see below |

Everything else is already identical: same `vda`–`vdd` slot order, same raw-tar
disk transport, same vsock egress with no guest NIC, same console capture.

## The bootstrap kernel

Stage 0 needs a kernel before any builder VM exists, so it can neither build one
nor resolve one through `kernel_fetch::resolve_kernel`, which returns
`NeedsBuild` on a source checkout by design.

libkrun answers this by extracting libkrunfw's kernel from the dylib's
`.rodata`. QEMU answers it with the host distro's `/boot/vmlinuz-$(uname -r)`.
Neither generalizes: the first requires Homebrew, the second requires a Linux
host with `initramfs-tools`.

**The bootstrap kernel is classified as a bootstrap seed**, exactly like the Nix
release tarball Stage 0 already fetches (`NIX_SEED_AARCH64` /
`NIX_SEED_X86_64`): a hash-pinned published artifact that is fetched and
verified even on a contributor checkout, because it is a *means of building*
rather than the artifact under construction. It is pinned the same way, too:
`mvm_build::stage0_kernel` carries a source-pinned URL and SHA-256 per arch
(`BOOTSTRAP_KERNEL_AARCH64` / `BOOTSTRAP_KERNEL_X86_64`) for the
`builder-vm-vmlinux-<arch>` assets of `boot-image/v0.1.5`, copied out of that
release's checksum manifests after their cosign signatures verified against the
boot-image release workflow's identity.

The first shape fetched through `update::download_kernel` instead, holding the
bytes to the signed manifest at run time. That needs the `manifest-verify`
feature, which an ordinary `just embed` build does not carry, so the first live
run refused before booting anything: every contributor HVF bootstrap was
broken. A source pin needs no feature and no run-time trust decision. The
transport is still injected from `mvm-cli` and is still curl, because the pinned
URL is a GitHub release asset that redirects and `mvm-http` follows no
redirects.

This narrows rather than widens the trust surface: the bootstrap kernel stops
coming from a third-party Homebrew dylib and starts coming from our own
release, held to a digest reviewed in source. It is a documented, narrowly scoped exception to the
source-checkout-never-fetches rule, and it does not extend to the builder image
or the workload kernel, which keep the local-build invariant unchanged.

## Guest impact: none

`stage0-init`'s backend detection is `is_qemu()` — a sniff for
`mvm.backend=qemu` on the kernel cmdline. Every other backend takes the same
arm, which requires `mvm.builder_transport=disk` plus vsock egress and finds its
Nix store and identity drive by ext4 label rather than by device letter. HVF
satisfies all of that already, so the guest needs no change.

One latent bug is fixed in passing. The libkrun Stage 0 cmdline omits the
`mvm.hostepoch=` token that the steady-state builder and the QEMU Stage 0 both
carry, so `stage0-init`'s clock sync is a no-op there. HVF is RTC-less, so a
Stage 0 booting on it without that token would fail HTTPS certificate
validation against a ~1970 clock. Routing through the shared spec builder, which
appends the token unconditionally, fixes it for every backend.

## Workstreams

- [x] **W1 — bootstrap kernel resolution.** `mvm_build::stage0_kernel`: resolve a
  cached+digest-verified bootstrap kernel, else fetch the published
  `builder-vm-vmlinux-<arch>` and record its digest. Fail closed on an
  unverifiable artifact. Unit tests for cache hit, missing sidecar, digest
  mismatch, and the fetch-on-source-checkout classification.
- [x] **W2 — generic Stage 0 on the driver seam.** `stage0_spec()` beside
  `builder_spec()`, and a `BuilderRunner::stage0()` that packs the
  `work`/`mvm-bins`/`conf` trees, boots over `D: VmmDriver`, and derives its
  result from the console markers. Driver-parametric tests over `MockDriver`.
- [x] **W3 — HVF wiring.** A separate `HvfStage0Vm` rather than a method on
  `HvfBuilderVm`, because that type is constructed *from* a builder image and
  Stage 0 runs when none exists; folding both in would mean kernel and rootfs
  fields meaningless for half its lifetime. Registered by the CLI alongside the
  builder ctor, which is what makes `stage0_backend_choice` stop lowering
  `Hvf` onto `Libkrun`. `declared_capabilities` answers for the live process so
  `doctor` reports what it can actually do.
- [x] **W4 — docs + stale-fact sweep.** CLAUDE.md is stale on the builder
  defaults, the auto-fallback, the builder NIC, and the `legacy::` backend
  paths; correct those. Record delivery under `specs/sprint/delivery/`.

- [x] **W5 — Firecracker, and a Linux builder VM.** `Stage0Vm<D>` and
  `DriverBuilderVm<D>` generic over `VmmDriver` instead of HVF-only;
  `BuilderBackendChoice::Firecracker`, auto-detected on Linux-with-KVM.
  `FcDriver::boot`'s agent-ready wait is gated on `VmmSpec::serves_guest_agent`,
  so a `stage0-init` guest is not waited on. `HvfVmmFailed` → `VmmFailed`.
- [x] **W6 — no builder path requires libkrun.** The Stage 0 lowering onto
  libkrun is deleted (an unregistered backend refuses and names itself);
  `run_shell_script` moves onto the `BuilderVm` trait so the ext4 materializer
  and verity sealer stop mapping `Hvf` onto `LibkrunBuilderVm`; the shell-job
  records move out of `libkrun_builder` so `libkrun` leaves the HVF builder's
  public signature.
- [x] **W7 — Firecracker serves builds (issue #3324).**
  `fc_builder_image::resolve_fc_builder_image` hands `DriverBuilderVm<FcDriver>`
  the Stage 0 image as-is: the builder-vm flake already installs
  `mvm-host-vm-init`, so there is no patcher VM. Getting there fixed two things
  that were wrong on every driver-backed builder and only mattered on
  Firecracker: the builder's egress port said `HostDials` (the guest dials;
  HVF ignores the direction, Firecracker bridges only `GuestDials`), and its
  console tokens were an HVF-shaped constant. The one-shot builder also stopped
  declaring an agent port its guest never serves. Builder shell jobs on
  Firecracker admit the current source image first, as libkrun's do. The
  persistent builder still refuses Firecracker by name. The live run added two
  more: the runner stops a guest whose kernel halts instead of powering off
  (Firecracker does not exit on a halt), and `FcRunningVm::kill` no longer
  requires a guest agent to flush through.

## Deliberately out of scope
- **Deleting the libkrun Stage 0 body.** It stays as the second working
  implementation until the generic path has live mileage. Removing it is a
  follow-up, not a precondition.
- **`MVM_LINUX_BUILDER_VM`.** Orphaned scaffolding: a predicate, a readiness
  check and two doctor lines with no dispatch consumer, citing a plan file that
  was deleted from the tree. Its written end state (a libkrun host VM with
  nested Firecracker) is now clearly the wrong topology — W5 makes Firecracker
  the Linux builder directly — so this should be deleted rather than finished.
- **A Firecracker persistent builder.** One-shot builds and shell jobs run on
  Firecracker (W7); `mvmctl persistent-builder start` still refuses it by name.
- **The rest of the libkrun module residue.** `BuilderVmImage`, the Stage 0
  store chain, the transport helpers and the image-cache readers are all
  VMM-neutral but still live in `libkrun_builder`, so the module cannot yet be
  feature-gated. No path *reaches* libkrun; the imports simply still name it.
- **Making `builder-vm` unconditional.** It cannot be turned off
  (`mvm-runtime` pins it) and costs zero crates in the closure, so ~120 of its
  cfg sites are dead configuration.

## Validation

**HVF is live-proven.** On macOS 26.6.2 arm64, a plain `just embed` build (no
`user` feature, libkrun installed but never touched) ran
`mvmctl __builder-vm-bootstrap` against a cold `MVM_HOME` and exited 0 after
about 11 minutes. The guest's console shows every leg the unit tests cannot:
`wall clock set from host epoch` (the clock-seed fix), the Nix store found by
label, substituter traffic through the host egress endpoint, and
`stage0-init: done; halting`. The cache then held a 760 MiB `rootfs.ext4`, a
`vmlinux`, `manifest.json`, `cmdline.txt` and provenance.

**Firecracker is live-proven on x86_64** (W7). On an Ubuntu 24.04 KVM host with
Firecracker v1.14.1, a cold `MVM_HOME` and nothing selected or killed by hand,
auto-detect chose Firecracker, Stage 0 exited 0 after 17 minutes, and a builder
shell job exited 0 with its `/out` intact — including a `curl` of
cache.nixos.org through the guest's egress channel. The first attempt hung at
Stage 0's halt; that is the W7 halt fix. aarch64 Firecracker is untested.
`specs/sprint/delivery/3324-firecracker-builder-image.md` carries the evidence.

The libkrun Stage 0 body is
untouched and reachable by name, but it is no longer a fallback — nothing lowers
onto it.

## Follow-ups

- **Live-boot the hvf Stage 0.** The one thing standing between this and
  "libkrun is optional on macOS".
- **Move the console-marker tests.** `stage0_console_halt_outcome`,
  `Stage0HaltOutcome` and `stage0_root_mount_nodes` moved to `stage0_host`, but
  their tests stayed in `libkrun_builder`'s test module and reach them through a
  `#[cfg(test)]` import. They should follow the code.
- **Untangle the persistent-store helpers.** `prepopulate_stage0_nix_store_image`
  and `stage0_nix_store_image_name` are re-exported from `stage0_host` rather
  than moved, because their implementation pulls in a chain of host-mkfs
  helpers.
- **A Firecracker Stage 0.** `FcDriver` already implements `VmmDriver` and the
  boot contract composes onto it, so what remains is a
  `BuilderBackendChoice::Firecracker` variant (~8 exhaustive-match sites plus an
  env-parser arm) and a spec-level opt-out for `FcDriver::boot`'s `mvm-agentd`
  handshake, which a `stage0-init` guest never answers.
- **Decide `MVM_LINUX_BUILDER_VM`'s fate.** Orphaned scaffolding whose written
  end state is the opposite topology from a first-class Firecracker builder.
