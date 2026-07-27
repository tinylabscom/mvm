# mvm-protocol on bare-metal embedded targets — verifier-at-the-edge track

Date: 2026-07-27
Status: slice 1 landed (bare-metal build proven + CI-gated); follow-ups open

## Goal

Extend the trust/attestation surface to microcontroller-class edge devices
without moving any workload execution there. Two device tiers:

- **Tier 1 — workload host.** A KVM-capable aarch64 board (Raspberry Pi 4/5,
  RK3588-class SBCs) runs real microVM workloads. This is the existing
  Linux/KVM/Firecracker path on aarch64; the work there is packaging +
  runtime-only admission of signed, content-addressed bundles, not a new
  backend. Tracked separately.
- **Tier 2 — verifying client.** A microcontroller (ESP32-class) cannot host
  a microVM (no MMU, no virtualization, single-digit MB RAM) but can *verify*:
  check a chain-signed audit log and Merkle inclusion proofs, hold a device
  identity, and act as a policy-enforcing client that submits work to a Tier 1
  host and cryptographically confirms the signed result. Execution stays on the
  MMU/EL2 device; verification pushes down to the smallest one. This mirrors the
  execute-vs-verify split the whole security model already draws (signed
  `ExecutionPlan`s, content-addressed signed bundles, the no_std/wasm protocol
  crate, the Merkle transparency log).

`mvm-protocol` is the crate that runs on Tier 2. It is already `#![no_std]` +
`alloc`, `forbid(unsafe_code)`, and hosts the audit-log verifier, the Workload
IR, the wire/policy DTOs, and the RFC 6962 Merkle inclusion-proof module.

## Result (slice 1)

`mvm-protocol` compiles for `riscv32imac-unknown-none-elf` — a true bare-metal
`*-none-*` target with no operating system and no `std` — with **zero code
changes**. The full dependency graph is already bare-metal-clean:
`ed25519-dalek` (verify path), `curve25519-dalek`, `sha2`, `serde` /
`serde_json` (alloc), `chrono` (no clock), `base64`. This is a stricter proof
than the existing wasm32 gate: `wasm32-unknown-unknown` still ships a partial
`std`, so a stray `std::` path can slip through there, whereas a `-none-elf`
target exposes only `core` + `alloc`.

Landed here:

- CI gate `baremetal-no-std-boundary` in `.github/workflows/ci.yml` — builds
  the crate lib for `riscv32imac-unknown-none-elf` on every PR, so a `std` leak
  can never regress the embedding surface.
- `just check-embedded [TARGET]` recipe for the same check locally.

`riscv32imac` is the mainline stand-in for the RISC-V microcontrollers this
targets and needs no out-of-tree toolchain, so both the gate and the recipe
stay hermetic. A lib-only build is an rlib with no final link, so no
cross-linker is required.

### Local toolchain gotcha

On a macOS host with Homebrew's Rust installed, `/opt/homebrew/bin/rustc`
shadows the rustup proxy in PATH, and Homebrew's rustc has no rustup-managed
bare-metal `core`. The target itself is present on the pinned toolchain — the
build fails with a misleading "can't find crate for `core`". Fix: pin
`RUSTC=$HOME/.cargo/bin/rustc` and put `$HOME/.cargo/bin` first in PATH. CI is
unaffected (clean rustup toolchain, no Homebrew Rust).

## Open follow-ups

- **Footprint measurement (the "how small" question).** An rlib doesn't link,
  so it carries no measurable code size on its own. Build a real `#![no_std]`
  `#![no_main]` binary (global allocator + panic handler + target linker
  script) that exercises the verify + Merkle path against a fixture, then
  measure `.text`/`.rodata`. That number is the actual on-device budget and the
  input to any flash/RAM sizing for the target part.
- **riscv32imc (ESP32-C3) has no atomics.** The `imac` proof target has the `a`
  extension; the C3 is `imc` (no hardware atomics). Any transitive
  `core::sync::atomic` use needs `portable-atomic` + `critical-section` shims.
  Add a second (allowed-to-be-harder) build against `riscv32imc-unknown-none-elf`
  to surface this before real hardware.
- **Xtensa (ESP32 / ESP32-S3) needs the esp-rs rustc fork.** Out-of-tree
  toolchain, so it cannot gate in mainline CI. Keep the mainline RISC-V gate as
  the portable proof; validate Xtensa out-of-band on hardware.
- **Verify-only means no entropy source.** Signature *verification* and Merkle
  proof checking need no RNG, so no `getrandom` backend is required on-device —
  a real simplification. Signing would need entropy; the edge device never
  signs, it verifies.
- **Transport.** vsock is a hypervisor construct and is absent off a VMM. The
  ESP32↔Pi link speaks the same protocol framing over a device-appropriate
  transport (TCP/serial/BLE). The DTOs and verifier are transport-agnostic
  already; the transport seam is the next design question for Tier 2.

## Related architecture decisions

- Tier matrix and per-backend claim coverage: ADR-001.
- Target-architecture posture: ADR-022.
- Minimal-memory profile for Tier 1 hosts (a resource profile, orthogonal to
  ADR-001's trust tiers, gated on an empirical boot-floor measurement) is a
  separate open decision — light path is a plan + a validated `MIN_MEM_MIB`;
  the heavy path (a distinct size-optimized guest kernel) would amend ADR-001.
