# `#[allow(dead_code)]` sweep

Issue #3310; `specs/plans/2026-09-15-the-big-cleanup.md` A3.6 / D6.

57 of the 61 `#[allow(dead_code)]` attributes are gone (counted as attribute
lines, excluding `third_party/` and the doc-example code that
`mvm-conformance/build.rs` generates). Rather than judge each site by reading
it, every attribute was removed and the compiler asked what was dead in each
configuration CI builds: macOS, a Linux cross-check, and the `builder-vm`,
`bdd`, `libkrun-live` and `libkrun-sys` feature sets. Each hit then got one of
three fixes.

## Gated to the configuration that uses it

Code that runs only on Linux (or only under a feature) and is unit-tested
everywhere now says so with `cfg(any(target_os = "linux", test))` or the
feature equivalent. This is the pattern `parse_loop_device` already used.
Covered: `mvm-host-vm-init`'s `#[path]` modules and their Linux-only runners,
`mvm-builder-agent`'s helpers, `seccomp_audit`, `doctor::warm_start`,
`verity::parse_root_hash`, `stage0-init`'s seed helpers, `libkrun-sys`'
`validate_boot_config`, and the
macOS-only entitlement layouts in `tests/install_sh.rs`.

## Deleted

- `crates/mvm-runtime/src/backends/hvf/dax_mapper.rs`: 215 lines no `mod`
  declared, so it was never compiled. Its only purpose was implementing
  `mvm_vmm::dax::DaxMapper`, which had no other implementation or user and
  goes too.
- `mvm_runtime::handle_registry`: nothing has called `register_attached` since
  the old sandbox backend was removed in May, so the Ctrl-C handler's
  `stop_all_attached()` always walked an empty map. The module and the call
  are gone.
- Unused HVF FFI declarations and their non-Apple stubs (`hv_vm_unmap`, five
  GIC getters, `HV_REG_X1..3`, `HV_EXIT_REASON_UNKNOWN`).
- Placeholders: `EntryKind::Directory` ("reserved for future use", never
  emitted), `extract_libkrunfw_kernel` (both copies, no caller), the
  test-only `drain_endpoint_bytes` trait method, `perf`'s `Backend::budget`,
  `WorkloadVmm::name`, `simple_file_tar`, the mock storage backend's
  `block_size` and `origin` (the latter recorded the snapshot's own id, not its
  origin's), `RemoteIndex::schema_version`, the unread `spec = "mvm/1"` tag in
  `model/*.toml`, and `Value::Bool`'s payload.

## Made to mean something

Where a field existed to be checked, it is now checked instead of deleted:

- Every `authority` row in `model/authorities.toml` must state a non-empty
  `statement`, as claims already had to.
- Every `[[prose]]`, `[[planned]]`, `[[absent]]` and `[[nix_attribute]]` entry
  in the doc-examples tier manifest must state a reason. The type's own doc
  demanded one, and nothing checked it.
- The `.mvmev` vector sidecar's `negatives` list must match the four mutations
  `mvmev_archive_vectors.rs` exercises, so the cross-language contract and the
  Rust tests cannot drift apart.

## Left, each with an owner

- `mvm-host-vm-init`'s `mod proxy`: #3484. The unused `VsockProxyLifecycle` is
  the vsock egress path the design calls production. #1613 swapped it for a
  child proxy that dials upstreams directly. Deleting it would delete the
  intended path.
- `policy_resolver`: #3483. It builds five supervisor controls that never run,
  and the audit chain records them as `live`.
- `mvm-builderd`'s two `#[path]` modules: #3485. `builderd.rs` needs splitting
  so the daemon stops compiling the host-side half.

No security claim or ADR-001 witness changes. The deletions remove no
production caller, and the three new checks pass on today's data.
