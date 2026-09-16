# VMM-agnostic Stage 0

Backing: shipped-source
Validation: check-declared-backing

**Status: IN PROGRESS.**

Stage 0 — the bootstrap that builds the builder-VM image from nothing — is the
last builder path that talks to a VMM directly instead of through the
`VmmDriver` seam. It has two concrete bodies (`libkrun_builder::run_stage0_impl`
and `qemu_builder::run_stage0_qemu`) and no implementation on HVF, which is the
auto-detected builder on macOS 26+ Apple Silicon. `stage0_backend_choice`
therefore lowers `Hvf` to `Libkrun`, and that single lowering is the entire
reason a macOS user must `brew install slp/krun/libkrun libkrunfw`.

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
rather than the artifact under construction. The artifact already exists —
`release.yml` publishes `builder-vm-vmlinux-<arch>`, covered by the signed
checksum manifests under claim 20, reachable through
`update::download_kernel(arch, "builder", dest)`.

This narrows rather than widens the trust surface: the bootstrap kernel stops
coming from a third-party Homebrew dylib and starts coming from our own
signature-gated release. It is a documented, narrowly scoped exception to the
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

- [ ] **W1 — bootstrap kernel resolution.** `mvm_build::stage0_kernel`: resolve a
  cached+digest-verified bootstrap kernel, else fetch the published
  `builder-vm-vmlinux-<arch>` and record its digest. Fail closed on an
  unverifiable artifact. Unit tests for cache hit, missing sidecar, digest
  mismatch, and the fetch-on-source-checkout classification.
- [ ] **W2 — generic Stage 0 on the driver seam.** `stage0_spec()` beside
  `builder_spec()`, and a `BuilderRunner::stage0()` that packs the
  `work`/`mvm-bins`/`conf` trees, boots over `D: VmmDriver`, and derives its
  result from the console markers. Driver-parametric tests over `MockDriver`.
- [ ] **W3 — HVF wiring.** `HvfBuilderVm::run_stage0` through W2;
  `capabilities().stage0_bootstrap = true`; drop the `Hvf => Libkrun` lowering
  in `stage0_backend_choice`.
- [ ] **W4 — docs + stale-fact sweep.** CLAUDE.md is stale on the builder
  defaults, the auto-fallback, the builder NIC, and the `legacy::` backend
  paths; correct those. Record delivery under `specs/sprint/delivery/`.

## Deliberately out of scope

- **A Firecracker `BuilderBackendChoice`.** `FcDriver` already implements
  `VmmDriver`, so W2 makes a Firecracker Stage 0 a wiring change rather than a
  rewrite — but `FcDriver::boot` blocks on an `mvm-agentd` handshake that a
  `stage0-init` guest will never answer, so it needs a spec-level opt-out first.
  Tracked, not built here.
- **Deleting the libkrun Stage 0 body.** It stays as the second working
  implementation until the generic path has live mileage. Removing it is a
  follow-up, not a precondition.
- **`MVM_LINUX_BUILDER_VM`.** Orphaned scaffolding: a predicate, a readiness
  check and two doctor lines with no dispatch consumer, citing a plan file that
  was deleted from the tree. Its written end state (a libkrun host VM with
  nested Firecracker) is the opposite topology from a first-class Firecracker
  builder. Needs a decision before anything is built on it.
