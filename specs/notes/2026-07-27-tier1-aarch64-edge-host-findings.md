# Tier-1 aarch64 edge host (Raspberry Pi 4/5) — verification findings

Date: 2026-07-27
Status: G1 CONFIRMED a non-bug via a live aarch64 Firecracker boot (ttyS0);
BDD `@firecracker` capability gate + local aarch64 nested-KVM env landed; G2
arch gate DEFERRED — reverted after code review found a placement regression
(see the Slice A note below).

## Question

Can a runtime-only `mvmctl` on a KVM-capable aarch64 board (Pi 4/5, RK3588)
admit and run an already-signed, content-addressed bundle end-to-end, with no
local build?

## Verified

1. **The workspace cross-compiles for `aarch64-unknown-linux-gnu`** — full
   `cargo zigbuild --workspace --lib --all-features`, exit 0 (3m48s, from a
   macOS host via zig). No aarch64-specific compile failures at the lib level.

2. **The runtime-only admit-and-run path exists and is hardware-independent.**
   `bundle install <src>` extracts a verified `.mvmpkg` to `~/.mvm/bundles/<sha>/`;
   `up --manifest <sha>` resolves artifacts straight from that registry dir
   (`vm/template/lifecycle/artifacts.rs::bundle_artifacts_for_sha`) with no nix
   and no builder VM. Admission itself (`mvm_hostd::plan_admission::admit_for_run`
   → verify plan → validity window → nonce replay → `verify_plan_bundle` →
   chain-signed audit emit) touches only filesystem + Ed25519/SHA-256; it drives
   the in-memory mock backend in tests, so it needs no `/dev/kvm` and no builder.
   The first and only hardware gate is `backend.start()`.

3. **Firecracker is the default Linux/KVM backend; libkrun is opt-in.**
   `AnyBackend::auto_select` picks Firecracker on native KVM. `mvm-cli` default
   features do not enable the `libkrun-sys` FFI, so a stock Pi binary links no
   `libkrun.so`. Guest arch resolves correctly (`GuestArch::host()` maps
   non-x86_64 → Aarch64).

## Gaps to close for a real Pi boot

### G1 — console device (CORRECTED: mostly a non-bug for Firecracker)

**Correction (verified against Firecracker docs):** Firecracker emulates a legacy
16550A UART on *aarch64 too*, so `console=ttyS0` is CORRECT for the Firecracker
path on aarch64. The PL011/`ttyAMA0` expectation applies to QEMU's `virt` machine
and the in-house HVF path, NOT to Firecracker. The sweeping arch→console change
described below is therefore NOT needed; the only plausible aarch64 delta is
adding `keep_bootcon` if the boot log comes up silent. **CONFIRMED 2026-07-27 on
real aarch64 Firecracker v1.10.1 in the Lima nested-KVM guest:** a stock
Firecracker-CI aarch64 `vmlinux-6.1.102` boots and emits a full kernel console
log on `console=ttyS0` (`Booting Linux on physical CPU ... aarch64`), no change
needed and `keep_bootcon` not required for boot output. Using a QEMU-`virt` boot as a proxy (PL011→ttyAMA0) would have
mis-led us into breaking a correct cmdline — hence the original "don't change the
contract blind" caution.

Original finding, retained for context — console device is x86-named across the
Firecracker path:

`console=ttyS0` is baked into the FC production path, not just tests:
- `crates/mvm-runtime/src/driver/fc.rs:74` (+ the rationale comment at :67)
- `crates/mvm-runtime/src/compat.rs:102,145` — a compat *contract* requiring it
- `crates/mvm-runtime/src/artifacts/builders/nix.rs:148`
- `crates/mvm-runtime/src/vm/template/lifecycle/build.rs:87,89`
- `crates/mvm-runtime/src/qemu.rs:85` (dev/test backend, same issue)

aarch64 has no 8250 ISA serial; a PL011 (`ttyAMA0`) is expected, which the
in-house HVF path already uses (`hvf_bootargs.rs:14`). This is cross-cutting —
it touches a validation contract and its tests — so it is its own slice, and the
exact correct console device for *Firecracker on aarch64* must be confirmed on
real aarch64 KVM before changing the contract. Do not change blind.

### G2 — no host-arch gate at bundle admit (hermetic, no hardware needed)

`BundleManifest.arch` is only displayed by `bundle fetch`; neither
`admit_for_run` nor `bundle_artifacts_for_sha` compares it to
`GuestArch::host()`. An `x86_64` `.mvmpkg` installed on a Pi is admitted and
fails only at boot, with a confusing error. Fix: fail closed at admit/resolve
when `manifest.arch != GuestArch::host()`. Fully unit-testable against the
existing hermetic admission tests (`plan_admission.rs` tests,
`up/admission.rs::admit_plan_tests`). Recommended next slice — no hardware.

## Blocker for true end-to-end

The boot half (`backend.start()` → Firecracker on `/dev/kvm`) needs an aarch64
KVM host. The available cloud KVM box is x86_64, which validates the
arch-independent admit/verify/audit logic but not an aarch64 boot. A Pi 4/5 or
an aarch64 KVM instance is required to validate G1 and the full
`bundle install` → `up --manifest <sha>` boot.

## Proposed sequencing

- Slice A: DEFERRED — the G2 arch gate was reverted after code review. Placing
  it in `bundle_artifacts_for_sha` also blocked non-boot callers that legitimately
  resolve foreign-arch bundle artifacts without booting (`bundle export`,
  `manifest export-oci` both reach it via `template_artifacts_dispatched`). Redo:
  gate at the actual boot sites (`exec.rs` `resolve_image_artifacts` /
  `boot_session_vm`) and cover the plan-admission path
  (`plan_admission::admit_for_run`, which re-verifies a pinned bundle but not its
  arch); add a regression test asserting cross-arch `bundle export` still works.
- Slice B (needs aarch64 KVM): validate the correct Firecracker aarch64 console
  device, then thread target arch → console selection through the compat contract
  + cmdline builders (G1), with the full signed-bundle boot as the witness.
- Packaging (later): a runtime-only aarch64 `mvmctl` binary build (backend =
  Firecracker, no libkrun feature, embedded host bins cross-built for the Pi).
