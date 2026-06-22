# Task 11 — Single-VM rekernel primitive

## Status

COMPLETE. All verify steps green.

## What was implemented

### `up --kernel-pin`

- Added `kernel_pin: Option<String>` to `up::Args` (with `#[arg(long = "kernel-pin")]` and a doc comment explaining its purpose).
- Added `kernel_pin: Option<&'a str>` to `RunParams` and threaded it through `run() → cmd_run()`.
- In `cmd_run`, at the kernel-resolution site (~line 2611), branched: if `kernel_pin.is_some()`, call `resolve_pinned_kernel(cache_dir, arch, source_checkout)` instead of the existing `resolve_workload_kernel`.
- Added a public helper `find_builder_vm_flake_is_source_checkout() -> bool` to `dev_vz.rs` (wraps the private `find_builder_vm_flake().is_ok()`).
- Added `resolve_pinned_kernel(cache_dir, arch, source_checkout) -> anyhow::Result<String>` helper in `up.rs`, which delegates to `mvm_build::kernel_fetch::resolve_kernel` (Task 10's `KernelResolution` type) and maps outcomes:
  - `Cached(p)` → Ok(path string)
  - `NeedsBuild(p)` → Err with "run `mvmctl build kernel build --which workload`" hint
  - `NeedsFetch(_)` → Err with "not yet supported; build from source" message
- `None` (`--kernel-pin` absent) → original `resolve_workload_kernel` path unchanged.

### `vm rekernel`

- New module `crates/mvm-cli/src/commands/vm/rekernel.rs`.
- `Args { name: String, flake: Option<String>, kernel_pin: Option<String>, hypervisor: String (default="libkrun") }`.
- `run()` calls `down::run(name)` (non-fatal on "not found"/"not running" errors; real stop errors propagate), then `up::run(cli, up::Args { name=Some(name), flake, kernel_pin, hypervisor, ...all-defaults }, cfg)`.
- Registered in `group.rs` (`Rekernel(rekernel::Args)` variant, `verb_name = "rekernel"`, dispatch arm), imported in `mod.rs`.

## How `resolve_kernel` was reused

`resolve_pinned_kernel` calls `mvm_build::kernel_fetch::resolve_kernel(cache_dir, arch, "workload", source_checkout)` directly — no reimplementation of the cache-presence check or the source-checkout / installed-binary policy split. The `KernelResolution` enum drives the three-way error/success mapping. `cached_kernel_path` (also from `kernel_fetch`) is used in the test to stage the cache.

## Verify outputs

```
cargo build -p mvm-cli 2>&1 | tail -5
→ Finished `dev` profile [unoptimized + debuginfo] target(s) in 35.87s

cargo test -p mvm-cli --lib resolve_pinned_kernel 2>&1 | tail -8
→ running 3 tests
→ test ...cached_kernel_returns_its_path ... ok
→ test ...source_checkout_without_cache_returns_err_with_build_hint ... ok
→ test ...installed_binary_without_cache_returns_err_about_fetch_not_supported ... ok
→ test result: ok. 3 passed; 0 failed

cargo clippy -p mvm-cli -- -D warnings 2>&1 | tail -3
→ Finished `dev` profile [unoptimized + debuginfo] target(s) in 23.84s (zero warnings)

cargo fmt -p mvm-cli -- --check 2>&1
→ (no output — clean)

./target/debug/mvmctl vm rekernel --help 2>&1 | head
→ Relaunch a VM on a chosen/updated workload kernel
→ Usage: mvmctl vm rekernel [OPTIONS] <NAME>
→ ...shows --flake, --kernel-pin, --hypervisor

./target/debug/mvmctl up --help 2>&1 | grep -i kernel-pin
→ --kernel-pin <KERNEL_PIN>  (flag visible)
```

## Concerns / follow-ups

1. **`NeedsFetch` not implemented**: installed-binary path with absent kernel returns a clear "not yet supported" error. A future slice can wire `verify_fetched_kernel` + a real download URL here once the kernel publish pipeline (Task 9) stabilises the download endpoint.
2. **`rekernel` restores all `up` defaults**: volume mounts, env vars, ports, TTL, etc. are reset. This is intentional for the minimal CVE-remediation use case (just reboot on the new kernel). A caller that needs to carry those settings through should script `down` + `up` directly.
3. **Non-fatal stop detection heuristic**: `rekernel` treats "not found"/"not running"/"no such"/"No such" error substrings as non-fatal. This is the same pragmatic pattern used elsewhere in the codebase and is robust for the intended use case (re-kerning after a crash or manual down).
