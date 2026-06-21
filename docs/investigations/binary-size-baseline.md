# mvmctl binary-size baseline

The size counterpart to `dep-baseline.md`. `mvmctl` is the artifact users
download; the cross-compiled musl host-vm binaries (`mvm-host-vm-init` +
`mvm-egress-proxy`) are baked into it as data, so their weight already counts
toward it. This file records the **measured** baseline (no asserted numbers) and
backs the `xtask check-binary-size` ratchet.

## Method (Plan 156 A1)

Measured under the release profile (`opt-level=3`, `lto=true`,
`codegen-units=1`, `strip=true` — the current `[profile.release]`):

```sh
cargo build --release -p mvmctl --bin mvmctl
ls -l target/release/mvmctl          # file size (bytes) — the headline
size  target/release/mvmctl          # section breakdown
cargo bloat --release --bin mvmctl --crates   # crate attribution
cargo bloat --release --bin mvmctl -n 50      # function-level
```

The size is **platform-sensitive** (macOS pulls libkrun/objc2; Linux pulls
firecracker/passt), so a baseline names its host/target. The release lane
measures the per-target distributed artifact; this file's headline is the host
that took the measurement.

## Baseline

| Target | Date | `mvmctl` size | Budget (`check-binary-size`) |
|---|---|---|---|
| macOS arm64 (aarch64-apple-darwin) | 2026-06-21 | 25,324,512 B (24.15 MiB) | 26,600,000 B (25.37 MiB) — baseline + 5.0% |

The budget is `BINARY_SIZE_BUDGET_BYTES` in `xtask/src/check_binary_size.rs`.
`check-binary-size` measures `target/release/mvmctl` (or `MVM_BINARY_SIZE_PATH`)
and fails if it exceeds the budget — a regression must be a deliberate, reviewed
bump. Lower the budget as the binary shrinks (the A–C tuning tasks).

## Notes

- Per-platform / CI-target budgets (the Linux release artifact) are enforced by
  pointing `check-binary-size` at the built artifact via `MVM_BINARY_SIZE_PATH`
  in the release lane — a follow-up to wire (Plan 156 D1 Step 2).
- The single largest future drop is the Plan 126 `sigstore` relocation; record
  it here as a 126-attributed delta when it lands.
