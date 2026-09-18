# Delete the unused x86_64 KVM VMM

Issue #3306; `specs/plans/2026-09-15-the-big-cleanup.md` B1.1 and G1.

`crates/mvm-runtime/src/kvm/` was a second in-house VMM for KVM on x86_64:
1,125 lines across `mod.rs`, `vm.rs`, `x86_boot.rs` and `serial.rs`. It
implemented no `VmmDriver`, was not a backend variant, held no claim witness,
and its only callers were two examples (`kvm-boot`, `kvm-relay-egress`). Its
docs cited a `spikes/` directory that does not exist. The Linux workload path
is Firecracker, which is unaffected.

Removed: the module, both examples, the `pub mod kvm` declaration, and the
Linux-only `kvm-ioctls` / `kvm-bindings` dependencies, which had no other
consumer. The two hand-rolled pieces that duplicated rust-vmm crates only in
that tree (`setup_boot` vs `linux-loader`, `Serial16550` vs `vm-superio`) go
with it.

Knock-on effects:

- `vmm-sys-util` 0.12.1 entered only through `kvm-bindings`, so the crate now
  resolves at 0.15 alone. Its exception is removed from `deny.toml`
  `[bans].skip` and from `check-duplicate-majors`' allowlist; ADR-033 carries
  a dated resolution note beside the paragraph that recorded the residual.
- The Linux default closure drops from 238 to 235 crates and the budget is
  ratcheted to match. The macOS budget is unchanged (229); its comment no
  longer lists `kvm-*` and `vmm-sys-util` as Linux-only.
- The main lockfile and the detached `mvm-runtime/fuzz-backend` lockfile are
  refreshed. The other two fuzz lockfiles were already clean.

No security claim, ADR-001 witness or backend behavior changes.
