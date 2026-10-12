# mvm-compiler

Shared workload compilation from `mvm_contract::ir::Workload` to deterministic
build artifacts. The compiler stages source, generates `flake.nix`,
`launch.json`, and `workload.json`, and can emit a gzipped tar archive.

## Boundaries

- `mvm-contract` owns the workload IR and its schema-level validation.
- This crate owns source copying, reachability, function/signature checks,
  framework stripping, lockfile checks, dependency-volume audit data, hook
  merging, launch/flake rendering, secret-reference stripping, and compilation
  orchestration.
- `mvm_sdk::compile` re-exports the same modules, functions, and error types
  when the SDK's opt-in `compiler` feature is enabled. SDK builders and
  language bridges remain in the base `mvm-sdk`.
- Concrete builds run through `mvm-build` in the builder VM. Runnable package
  assembly belongs to `mvm-bundler`; signing stays outside the compiler.
  Compiler tar archives are build inputs, not runnable `.mvmpkg` packages.

`compile` expects an already validated workload. `validate_lockfiles` is an
explicit on-disk check; it is not implicitly invoked by `compile`. Its existing
format-specific checks are heuristics, not full lockfile resolution or
cryptographic verification.

Use `compile_pinned` or `compile_archive_pinned` with `PinnedMvmRevision` for
an explicit immutable mvm flake input. Callers must still generate and verify
`flake.lock` inside the builder before publishing. Unpinned entrypoints retain
the existing `MVM_FLAKE_URL` override behavior.

## Packs

`pack` lowers a `PackSpec` to a command-entrypoint `Workload` and renders it
with `compile_pinned`; it has no renderer of its own. `lock_pack` snapshots the
source tree (refusing a root or symlink that escapes it) and returns a
`PackLock` binding the pack identity, target, canonical spec digest, snapshot
digest over file paths, modes and contents, lowered workload digest, compiler
version and mvm revision. `compile_frozen` recomputes that lock, names every
stale field, and compiles from the verified snapshot only when nothing differs.

Lowering refuses build-scoped packages, exact package versions, language
dependency files and copy operations, because the IR and Nix factories cannot
honor them yet. A successful frozen compile resolves no packages, installs no
dependencies and runs no build.

## Validation

```sh
cargo test -p mvm-compiler
cargo test -p mvm-sdk --no-default-features
cargo test -p mvm-sdk --features compiler,deploy-remote
cargo clippy -p mvm-compiler -p mvm-sdk --features mvm-sdk/compiler,mvm-sdk/deploy-remote --all-targets -- -D warnings
```

The compiler dependency-boundary test rejects SDK, execution, and packaging
dependencies, including development dependencies. SDK compatibility tests
exercise both API paths, compare generated files and archives for Python and
TypeScript workloads, and verify error-type compatibility.
