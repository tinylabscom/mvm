# Windows API dependency range patches

These two temporary Cargo patches admit the already-locked
`windows-sys 0.61.2` without replacing `notify 8.2.0`, migrating sysinfo,
changing runtime behavior, or weakening dependency policy.

## Immutable published sources

| Package | Archive SHA-256 | Upstream revision |
| --- | --- | --- |
| `notify 8.2.0` | `4d3d07927151ff8575b7087f245456e549fea62edf0ec4e565a5ee50c8402bc3` | `a1d7c2d8f80786679d58ec6d5986a1d4278bc8cf` |
| `io-extras 0.19.0` | `20fd6de4ccfcc187e38bc21cfa543cb5a302cb86a8b114eb7f0bf0dc9f8ac00f` | `943084024810db2d674050af664a1e10c81b58a0` |

- `notify`: https://github.com/notify-rs/notify.git, package path `notify`;
  https://static.crates.io/crates/notify/notify-8.2.0.crate.
  CC0-1.0, original `LICENSE-CC0` retained; Rust 1.77 MSRV.
- `io-extras`: https://github.com/sunfishcode/io-extras, repository root;
  https://static.crates.io/crates/io-extras/io-extras-0.19.0.crate.
  `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT`; original
  `COPYRIGHT`, `LICENSE-APACHE`, `LICENSE-Apache-2.0_WITH_LLVM-exception`
  and `LICENSE-MIT` retained; Rust 1.70 MSRV.

The import verified cached archive SHA-256 values against the original
registry entries in `Cargo.lock`, rejected archive links and escaping paths,
and copied only these exact published packages. `notify` contains 15 files,
162,241 uncompressed bytes; `io-extras` contains 25 files, 184,071 bytes.
No dependency trees or upstream workspace checkout are imported.

## Complete delta

Only four imported files differ from the published archives:

- `notify-8.2.0/Cargo.toml`: Windows dependency `windows-sys` changes
  from `0.60.1` to `>=0.60.1, <0.62`.
- `notify-8.2.0/Cargo.toml.orig`: the corresponding Windows dependency
  replaces `workspace = true` with `version = ">=0.60.1, <0.62"`.
  This records the effective standalone patch; an upstream submission
  should widen the source workspace dependency instead.
- `io-extras-0.19.0/Cargo.toml` and `Cargo.toml.orig`: Windows dependency
  `windows-sys` changes from `>=0.52, <=0.60` to `>=0.52, <0.62`.

Existing lower bounds, features, other dependencies, and all Rust source
remain unchanged. Every other imported file, including licenses, is
byte-identical to its published archive.

## Source-level Windows compatibility evidence

All Windows API imports in both packages were compared against cached
`windows-sys 0.60.2` and `0.61.2`: 35 imports in `notify/src/windows.rs`,
13 in `io-extras/src/os/windows/{stdio,types}.rs`, 48 total.
Every imported function signature, constant declaration, and type declaration
matches byte-for-byte after normalizing only the generated linker macro name
from `windows_targets::link!` to `windows_link::link!`.
Complete struct bodies for `FILE_NOTIFY_INFORMATION`, `OVERLAPPED`, and
`CONSOLE_READCONSOLE_CONTROL` also match.

This is source compatibility evidence, not a Windows compilation or runtime
test. Parent-coordinated Windows cross-checks remain required.

## Why these two ranges

The existing lock has six direct parents of `windows-sys 0.60.2`:

| Parent | Published Windows dependency range |
| --- | --- |
| `anstyle-query 1.1.5` | `>=0.60.2, <0.62` |
| `anstyle-wincon 3.0.11` | `>=0.60.2, <0.62` |
| `cap-primitives 4.0.3` | `>=0.60, <0.62` |
| `socket2 0.6.4` | `>=0.60, <0.62` |
| `notify 8.2.0` | `0.60.1` |
| `io-extras 0.19.0` | `>=0.52, <=0.60` |

After these two patches, all six permit `0.61.2`. `io-lifetimes 2.0.4`
and `3.0.1` have optional Windows dependencies, but neither has a
`windows-sys` dependency edge in the reviewed lock; `3.0.1` enables that
edge only through its non-default `close` feature.

Retaining the legacy `windows-sys 0.52`/`0.59` users keeps their required
single `windows-targets 0.52` family. Removing `windows-sys 0.60.2`
removes the extra `windows-targets 0.53` family. Migrating sysinfo alone
cannot achieve that because other dependencies still require the legacy
family.

## Coordinated lock reconciliation and validation

```sh
cargo update --offline -p notify@8.2.0 -p io-extras@0.19.0
cargo update --offline -p windows-sys@0.60.2 --precise 0.61.2
cargo metadata --offline --locked --format-version 1
cargo deny --locked check
```

Review the lock diff to confirm only intended package-source changes and
dependency consolidation. Preserve `mvm-macho-sign`, all its direct
dependencies, and unrelated work. Do not modify `deny.toml`.

Compilation, focused behavior tests, and Windows cross-checks are coordinated
by the parent task. Remove these patches when published upstream versions
provide compatible ranges.
