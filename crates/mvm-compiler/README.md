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

Copy operations run in authored order against the verified snapshot and
assemble the application tree the guest sees at `/app`; without any, the whole
source tree lands there. Destinations outside `/app`, symlinks anywhere a copy
reads, and a file replacing a directory (or the reverse) are refused. An npm
`package.json` + `package-lock.json` at the source root lowers to the IR's Node
dependency declaration: the lockfile must carry an integrity hash for every
entry, and the generated flake builds `node_modules` from it in the builder VM,
so nothing installs at boot.

A uv `pyproject.toml` + `uv.lock` at the source root lowers to the IR's Python
dependency declaration. The spec must name exactly one runtime package
`python3NN` (for example `python312`); that is the interpreter, and the lock's
`requires-python` must hold for every patch release of it. `lock_pack` reads
the lockfile from the snapshot and resolves it for the pack's target with
`pack::python::resolve`: starting at the project (`source = { virtual = "." }`
or `{ editable = "." }`, which is not installed), it follows runtime
dependencies and the optional-dependency sets their edges name, never
development dependencies, and evaluates each edge marker for the target
(Linux, the target's architecture, CPython 3.NN). Each reached package must
come from a registry and gets one wheel, chosen in pip's CPython tag order from
glibc `manylinux` platforms no newer than the glibc of mvm's pinned nixpkgs
(`MAX_GLIBC_MINOR`); the wheel must be an https URL with a sha256. The resolved
set is recorded in the workload's `mvm.pack` extension, so the lock's workload
digest binds every wheel, and `compile_frozen` writes it beside `flake.nix` as
`pack-build.json`. The flake fetches each wheel as a fixed-output derivation,
installs them with pypa's `installer` into one store path patched against the
image closure, and puts it on the command's `PYTHONPATH`; nothing installs at
boot and the guest needs no network.

Build-scoped packages are not in the image. They are recorded in the same
extension (`build_packages`, so the lock binds them), written to
`pack-build.json`, and the flake adds them to the dependency-install
derivations only. A pack spec has no field for a Nix module or build script,
so the only code that runs at build time is the generated flake.

Resolution refuses, by name, what it cannot decide exactly for one target: git,
URL, path and directory sources; a marker over a variable the target does not
fix (`platform_release`, `extra`, ...) or whose outcome depends on the
interpreter's patch release; a dependency edge that matches several locked
versions; and a package with no compatible wheel, since nothing is built from
an sdist.

Lowering still refuses exact package versions, Python
dependency files other than a uv lockfile at the source root, other Node
lockfiles and more than one dependency declaration, because the IR and Nix
factories cannot honor them for a command workload yet. A successful frozen compile runs no build; `mvmctl pack lock` and
`mvmctl pack compile` are the command-line surface over `lock_pack` and
`compile_frozen`. A `pack.lock.json` at the source root is the lock itself and
is left out of the snapshot it digests.

## Validation

```sh
cargo test -p mvm-compiler
cargo test -p mvm-sdk --no-default-features
cargo test -p mvm-sdk --features compiler,deploy-remote
cargo clippy -p mvm-compiler -p mvm-sdk --features mvm-sdk/compiler,mvm-sdk/deploy-remote --all-targets -- -D warnings
```

The compiler dependency-boundary test rejects SDK, execution, and packaging
dependencies, including development dependencies. It also rejects key-custody
and TLS crates and any signing-key type named in compiler source, so no
publisher or host signing key can enter compilation or the builder input it
produces. SDK compatibility tests
exercise both API paths, compare generated files and archives for Python and
TypeScript workloads, and verify error-type compatibility.
