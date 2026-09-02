# Binary size baseline

Measured for the current `mvmctl` release path and tracked as the companion to
[`dep-baseline.md`](dep-baseline.md). Dependency count is the no-build supply
chain proxy; this file records the shipped artifact weight where we have a real
target measurement and calls out provisional local-only builds honestly.

## Method

Canonical commands for a measured release binary:

```sh
# Headline file size
ls -l target/<triple>/release/mvmctl

# Section breakdown
size target/<triple>/release/mvmctl

# Budget check
cargo run --package xtask -- check-binary-size \
  --path target/<triple>/release/mvmctl \
  --budget-bytes <bytes>
```

Some July 2026 entries below were measured with a retired zero-byte helper-stub
mode. They remain labeled as historical provisional measurements. Current
builds always produce the builder/bootstrap helper payloads, so only a current
release-path measurement may drive the release budget.

## Current measured baseline

### Release-gated target

Measured 2026-08-20 for `aarch64-apple-darwin` with the new
`[profile.release-min]` in [`.github/workflows/release.yml`](../../.github/workflows/release.yml):

| Target                 |        Measured size |                        Budget |
| ---------------------- | -------------------: | ----------------------------: |
| `aarch64-apple-darwin` | **19,206,160 bytes** | **25,165,824 bytes** (24 MiB) |

The `release-min` profile inherits the existing `release` settings
(`lto = true`, `codegen-units = 1`, `strip = true`, `overflow-checks = true`)
and adds `opt-level = "z"` and `panic = "abort"` to minimize the shipped
artifact. This is the current real binary-size ratchet: the release workflow
runs `xtask check-binary-size` against that budget for the measured target
only.

### Release-bundled secondary binaries

Measured 2026-07-08 on the macOS release-bundle set that
[`.github/workflows/release.yml`](../../.github/workflows/release.yml) currently
ships. This replaces the stale historical binary list in Plan 156: today's
bundle is the Linux-shared pair `mvm-bridge` + `mvm-substitution-endpoint`,
plus the macOS-only supervisors `mvm-hvf-supervisor` and
`mvm-libkrun-supervisor`.

Commands:

```sh
CARGO_TARGET_DIR=/tmp/mvm-size-target \
  cargo build --release --locked --offline -p mvm-vm-host \
    --bin mvm-bridge --bin mvm-hvf-supervisor

CARGO_TARGET_DIR=/tmp/mvm-size-target \
  cargo build --release --locked --offline -p mvm-vm-host \
    --bin mvm-libkrun-supervisor --features libkrun-sys

CARGO_TARGET_DIR=/tmp/mvm-size-target \
  cargo build --release --locked --offline -p mvm-hostd \
    --bin mvm-substitution-endpoint

cargo bloat --release -p <package> --bin <name> --crates \
  --locked --target-dir /tmp/mvm-size-target -n 8
```

Measured file sizes:

| Binary | Bundle scope | File size |
|---|---|---:|
| `mvm-bridge` | shipped on Linux + macOS | **4,091,160 bytes** |
| `mvm-substitution-endpoint` | shipped on Linux + macOS | **8,052,440 bytes** |
| `mvm-hvf-supervisor` | shipped on macOS only | **755,952 bytes** |
| `mvm-libkrun-supervisor` | shipped on macOS only | **4,448,008 bytes** |

Top crate-attribution snapshot (`cargo bloat --crates -n 8`):

| Binary | Largest crates |
|---|---|
| `mvm-bridge` | `std` 868.9 KiB; `regex_automata` 313.3 KiB; `mvm_hostd` 221.7 KiB; `regex_syntax` 145.1 KiB |
| `mvm-substitution-endpoint` | `std` 875.6 KiB; `aws_lc_sys` 675.5 KiB; `[Unknown]` 547.6 KiB; `rustls` 412.7 KiB |
| `mvm-hvf-supervisor` | `std` 279.3 KiB; `mvm_backend` 75.8 KiB; `serde_json` 35.7 KiB; `mvm_hvf_supervisor` 19.8 KiB |
| `mvm-libkrun-supervisor` | `std` 1.0 MiB; `regex_automata` 311.4 KiB; `mvm_hostd` 230.3 KiB; `serde_json` 153.6 KiB |

Two useful follow-on observations from the sidecar baseline:

- The Linux-shared `mvm-substitution-endpoint` is the largest shipped sidecar
  by a wide margin, with `aws_lc_sys` + `rustls` visible in its top contributors.
- The regex stack (`regex_automata`, `regex_syntax`, `aho_corasick`) is a
  repeated top contributor in the bridge and both heavier macOS supervisors,
  which makes the upcoming feature-audit slice worth measuring there too.

### Local provisional branch measurement

Measured 2026-07-08 on this branch with:

```sh
CARGO_TARGET_DIR=/tmp/mvm-size-target \
  cargo build --release --bin mvmctl --locked --offline

ls -l /tmp/mvm-size-target/release/mvmctl
size /tmp/mvm-size-target/release/mvmctl
```

Results:

| Target | Build mode | File size |
|---|---|---:|
| host-local `mvmctl` | release, **stubbed embedded helpers** | **21,158,544 bytes** |

Section breakdown:

| `__TEXT` | `__DATA` | `__OBJC` | `others` | `dec` |
|---:|---:|---:|---:|---:|
| 20,201,472 | 32,768 | 0 | 4,295,901,184 | 4,316,135,424 |

Important caveat: this host did not have the pinned zig `0.13.0` toolchain that
`crates/mvm-cli/build.rs` required for real builder/bootstrap helpers, so the
historical build used the now-retired zero-byte stub mode. The recorded size is
useful only for comparing the contemporaneous Rust-side CLI payload; the
normalized command above now builds real helpers and will not reproduce it.

### Local provisional follow-up: Tokio feature-union trim

Measured 2026-07-08 after narrowing the workspace-wide Tokio union so `fs`,
`process`, and `signal` are requested only by the crates that actually use
them (`mvm-storage`, `mvm-hostd`, and the signal-aware guest/helper bins).

Validation/measurement commands:

```sh
CARGO_TARGET_DIR=/tmp/mvm-tokio-audit-target \
  cargo check --workspace --all-targets --offline

CARGO_TARGET_DIR=/tmp/mvm-tokio-audit-target \
  cargo clippy -p mvm-hostd -p mvm-storage -p mvm-guest-helpers \
    --all-targets --offline -- -D warnings

CARGO_TARGET_DIR=/tmp/mvm-size-target \
  cargo build --release --bin mvmctl --locked --offline

stat -f '%N %z' /tmp/mvm-size-target/release/mvmctl
```

Result:

| Measurement | Before | After | Delta |
|---|---:|---:|---:|
| host-local `mvmctl` provisional file size | 21,158,544 | **21,158,560** | **+16 bytes** |

The meaningful win here is feature-surface tightening, not artifact shrink:
`cargo tree -p mvmctl -e features` no longer shows `tokio feature "signal"` on
the default path, while `fs` and `process` remain only because `mvm-storage`
and `mvm-hostd` genuinely use them.

### Local provisional follow-up: direct `regex` feature trim

Measured 2026-07-08 after narrowing the workspace-wide direct `regex`
dependency to `default-features = false` with only `perf`, `std`, and
`unicode-perl`, then aligning `mvm-core` to consume the workspace dependency
instead of re-enabling `regex` defaults locally.

Validation commands:

```sh
CARGO_TARGET_DIR=/tmp/mvm-regex-audit-target \
  cargo check -p mvm-core -p mvm-hostd --all-targets --offline

CARGO_TARGET_DIR=/tmp/mvm-regex-audit-target \
  cargo clippy -p mvm-core -p mvm-hostd --all-targets --offline -- -D warnings

CARGO_TARGET_DIR=/tmp/mvm-regex-audit-target \
  cargo test -p mvm-hostd 'secrets_scanner::tests::' --lib --offline

CARGO_TARGET_DIR=/tmp/mvm-regex-audit-target \
  cargo test -p mvm-hostd 'injection_guard::tests::' --lib --offline

CARGO_TARGET_DIR=/tmp/mvm-regex-audit-target \
  cargo test -p mvm-hostd 'pii_redactor::tests::' --lib --offline

CARGO_TARGET_DIR=/tmp/mvm-size-target \
  cargo build --release --bin mvmctl --locked --offline

stat -f '%N %z' /tmp/mvm-size-target/release/mvmctl

cargo tree -p mvmctl -e no-dev -e features -i regex \
  --offline --target x86_64-unknown-linux-gnu
```

Result:

| Measurement | Before | After | Delta |
|---|---:|---:|---:|
| host-local `mvmctl` provisional file size | 21,158,560 | **21,158,544** | **-16 bytes** |

This tightened the direct dependency surface used by `mvm-core`/`mvm-hostd`,
but it did not shrink the default `mvmctl` path yet: `cargo tree` still shows
full regex Unicode features pulled in transitively through `tree-sitter`
(`mvm-sdk`), so the Unicode tables remain present in the binary. In practical
terms, this only clawed back the earlier provisional `+16` byte drift from the
Tokio feature-union slice; the branch is now back at the original local
provisional baseline of 21,158,544 bytes rather than materially below it.

### Local provisional follow-up: `clap` default-feature trim

Measured 2026-07-08 after narrowing the workspace `clap` dependency from the
default feature set to `default-features = false` with only `derive`, `help`,
`std`, and `usage`.

Validation commands:

```sh
CARGO_TARGET_DIR=/tmp/mvm-clap-audit-target \
  cargo check -p mvm-cli --all-targets --offline

CARGO_TARGET_DIR=/tmp/mvm-clap-audit-target \
  cargo test -p mvm-cli --lib commands::tests::top_level_help_hides_infra --offline

CARGO_TARGET_DIR=/tmp/mvm-clap-audit-target \
  cargo test -p mvm-cli --lib commands::tests::machine_help_lists_run_first --offline

CARGO_TARGET_DIR=/tmp/mvm-clap-audit-target \
  cargo test -p mvm-cli --lib commands::tests::builder_flag_appears_in_help --offline

CARGO_TARGET_DIR=/tmp/mvm-clap-audit-target \
  cargo clippy -p mvm-cli --all-targets --offline -- -D warnings

CARGO_TARGET_DIR=/tmp/mvm-size-target \
  cargo build --release --bin mvmctl --offline

stat -f '%N %z' /tmp/mvm-size-target/release/mvmctl

cargo tree -p mvmctl -e no-dev -e features -i clap \
  --offline --target x86_64-unknown-linux-gnu
```

Result:

| Measurement | Before | After | Delta |
|---|---:|---:|---:|
| host-local `mvmctl` provisional file size | 21,158,544 | **21,108,960** | **-49,584 bytes** |

The default `mvmctl` path now carries only `clap`'s `derive`, `help`, `std`,
and `usage` features. The removed default features (`color`, `error-context`,
and `suggestions`) were not needed for the current help/parse surface, and this
is the first Plan 156 C2 slice on this branch that produced a material binary
reduction.

### Local provisional follow-up: explicit direct `serde` / `serde_json` features

Measured 2026-07-08 after changing the workspace direct dependencies to:

- `serde = { default-features = false, features = ["derive", "std"] }`
- `serde_json = { default-features = false, features = ["std"] }`

Validation commands:

```sh
CARGO_TARGET_DIR=/tmp/mvm-serde-audit-target \
  cargo check --workspace --all-targets --offline

CARGO_TARGET_DIR=/tmp/mvm-serde-audit-target \
  cargo test -p mvm-core protocol::protocol::tests:: --lib --offline

CARGO_TARGET_DIR=/tmp/mvm-serde-audit-target \
  cargo test -p mvm-cli json_out::tests::to_json_string_is_pretty --lib --offline

CARGO_TARGET_DIR=/tmp/mvm-serde-audit-target \
  cargo test -p mvm-hostd framing::tests:: --lib --offline

CARGO_TARGET_DIR=/tmp/mvm-serde-audit-target \
  cargo clippy --workspace --all-targets --offline -- -D warnings

CARGO_TARGET_DIR=/tmp/mvm-size-target \
  cargo build --release --bin mvmctl --offline

stat -f '%N %z' /tmp/mvm-size-target/release/mvmctl

cargo tree -p mvmctl -e no-dev -e features -i serde_json \
  --offline --target x86_64-unknown-linux-gnu

cargo tree -p mvmctl -e no-dev -e features -i serde \
  --offline --target x86_64-unknown-linux-gnu
```

Result:

| Measurement | Before | After | Delta |
|---|---:|---:|---:|
| host-local `mvmctl` provisional file size | 21,108,960 | **21,108,960** | **0 bytes** |

This keeps the direct workspace dependency declarations honest, but it does not
reduce the current default `mvmctl` path further. `cargo tree` still shows
transitive default-feature users for the serde stack, notably `reqwest`,
`schemars`, and build-time `tree-sitter`, so the next meaningful work is to
audit those callers rather than the workspace direct declarations themselves.

### Local provisional follow-up: `mvm-sdk` `schemars` / `tree-sitter` trims

Measured 2026-07-08 after narrowing:

- `mvm-sdk` `schemars` to `default-features = false, features = ["derive"]`
- workspace `tree-sitter` to `default-features = false, features = ["std"]`

Validation commands:

```sh
CARGO_TARGET_DIR=/tmp/mvm-sdk-audit-target \
  cargo check -p mvm-sdk -p mvm-cli --all-targets --offline

CARGO_TARGET_DIR=/tmp/mvm-sdk-audit-target \
  cargo test -p mvm-sdk --lib --offline

CARGO_TARGET_DIR=/tmp/mvm-sdk-audit-target \
  cargo clippy -p mvm-sdk -p mvm-cli --all-targets --offline -- -D warnings

CARGO_TARGET_DIR=/tmp/mvm-size-target \
  cargo build --release --bin mvmctl --offline

stat -f '%N %z' /tmp/mvm-size-target/release/mvmctl

cargo tree -p mvmctl -e no-dev -e features -i schemars \
  --offline --target x86_64-unknown-linux-gnu

cargo tree -p mvmctl -e no-dev -e features -i tree-sitter \
  --offline --target x86_64-unknown-linux-gnu

cargo tree -p mvmctl -e no-dev -e features -i regex \
  --offline --target x86_64-unknown-linux-gnu
```

Result:

| Measurement | Before | After | Delta |
|---|---:|---:|---:|
| host-local `mvmctl` provisional file size | 21,108,960 | **21,108,960** | **0 bytes** |

The default-path feature graph is cleaner: `schemars` now enters via its derive
path only, and `tree-sitter` no longer carries its broader default feature set.
But `tree-sitter`'s remaining `std` path still pulls regex Unicode support, so
this slice is another honest dependency-surface trim rather than an additional
binary-size win.
