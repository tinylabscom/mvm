# Backend papercuts found during the TypeScript core-demo E2E (2026-06-03)

Surfaced while bringing up the TS workload E2E (`feat/ts-core-demo`) on a
macOS 26 / Apple Silicon host. None block the TS feature — the demo runs on the
libkrun builder + libkrun workload backend — but all three bite anyone driving
the Vz or Apple Container paths. Filed here rather than the GitHub mirror since
the canonical remote is codeberg.

## 1. Vz builder VM refuses to boot — "storage device attachment is invalid"

`MVM_BUILDER_BACKEND=vz mvmctl dev up` builds the builder image fine, then the
Swift supervisor rejects the VM config before guest start:

```
mvm-vz-supervisor: VM failed to start: Error Domain=VZErrorDomain Code=2
  "The storage device attachment is invalid." ...
Error: vz builder VM: nix build failed inside builder sandbox:
  supervisor exited with non-zero status (3)
```

Console.log is empty (VM never booted). The cached image is well-formed:
`rootfs.ext4` (778 MiB) + `vmlinux` + the 68 GiB `nix-store-<arch>.img`, all
512-aligned. So it's a config-construction issue in the Vz attachment path
(`crates/mvm-vz-supervisor` + `crates/mvm-build/src/vz_builder.rs`), not a
corrupt artifact. Reproduced cold in an isolated temp cache, so it's not
cross-session contention.

- [ ] Reproduce with a minimal VZ disk-attachment harness; capture which
      attachment (rootfs vs `/nix-store` 68 GiB sparse) Vz rejects.
- [ ] Check the supervisor builds `VZDiskImageStorageDeviceAttachment` with a
      synchronization/cache mode macOS 26 accepts, and that the 68 GiB sparse
      `/nix-store` image is attached in a mode VZ allows.
- Refs: Plan 97 (Vz backend), Plan 98 (Vz builder VM), Plan 99 (Vz phase C).

## 2. Vz supervisor source-checkout discovery: `aarch64-` vs SwiftPM `arm64-`

`vz_builder.rs::resolve_supervisor_path` looks for the source-checkout binary at
`crates/mvm-vz-supervisor/.build/<arch>-apple-macosx/debug/mvm-vz-supervisor`
using the Rust arch tag (`aarch64`), but `tools/build.sh` / SwiftPM emit
`.build/arm64-apple-macosx/debug/...`. So a freshly-built supervisor is "not
found" and the only escape is `MVM_VZ_SUPERVISOR_PATH`.

- [ ] Map Rust `aarch64` → SwiftPM `arm64` in the source-checkout probe (or also
      check the `.build/debug/` symlink SwiftPM writes), so `dev up` works after
      `tools/build.sh` with no env override.
- Ref: `crates/mvm-build/src/vz_builder.rs` (`resolve_supervisor_path`), doctor's
  "Apple Virtualization.framework" line.

## 3. Apple Container workload backend — "Kernel not found: vmlinux"

On macOS 26 the workload runtime auto-selects `apple-container`, but a function
workload built by the dev-shell flake emits **only** `rootfs.ext4` (no
`vmlinux`) into the build artifact dir, so boot fails:

```
Error: Apple Container start failed: Kernel not found:
  <build>/vmlinux
```

libkrun is unaffected — it supplies its own libkrunfw kernel
(`mvm-libkrun::extract_bundled_kernel`). So either the function-workload build
must emit a kernel for the apple-container path, or the apple-container backend
must source one the way libkrun does.

- [ ] Decide kernel provenance for apple-container function workloads (emit
      `vmlinux` from the guest build vs. bundle one backend-side), then wire it.
- Ref: `crates/mvm-cli/src/commands/vm/up.rs` (apple-container dispatch),
  `crates/mvm-providers/src/apple_container`.
