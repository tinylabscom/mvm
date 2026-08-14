# Builders for every input-parameter struct

CLAUDE.md and AGENTS.md both call for the builder pattern on types carrying
more than a couple of fields, but the convention was applied by hand and had
drifted: of the 58 `*Params` / `*Input` / `*Options` / `*Opts` / `*Args`
parameter-bundle structs in the workspace, exactly three had a builder
(`KernelBootUntilParams`, `FsWriteOptions`, `StreamOpts`). Everything else was
constructed positionally through a struct literal — including
`SynthesisInput` (34 fields), `VmStartParams` (18) and
`BuildRuntimePackParams` (16), where two adjacent `&str` or `PathBuf` fields
transpose silently.

## Delivered

- `mvm_contract::builder::BuilderError` — the one error a builder returns, so a
  required field left unset is reported by type and field name instead of being
  defaulted into an empty value. `no_std`, one struct, two fields.
- Builders on **29 input structs** across `mvm-core`, `mvm-fs`, `mvm-build`,
  `mvm-vmm`, `mvm-runtime`, `mvm-hostd` and `mvm-cli`. Two shapes, chosen per
  struct by whether the type already has a `Default`:
  - **Defaulted** (`Mke2fsOptions`, `UnpackOptions`, `VeritysetupOptions`,
    `LayerFetchOptions`, `MaterializeOptions`, `MaterializeExt4Options`,
    `PoolBuildOpts`) — the builder starts from `T::default()`, every setter
    overrides, `build()` is infallible. An unset field keeps the value the type
    itself declares, which is the existing contract those types already have.
  - **Checked** (the other 22) — the builder starts empty and `build()`
    returns `Result<T, BuilderError>` naming the first required field left
    unset. These types have no `Default`, so defaulting a required `PathBuf` or
    `&str` would substitute an empty path for a missing one; the struct literal
    they replace could not do that, and neither can the builder.
- `Option<T>` setters take `impl Into<Option<T>>`, so a call site passes either
  the bare value or the `Option` it already holds — the OCI persist path threads
  `initrd_path` / `verity_path` / `roothash` straight through.
- Fields stay `pub`: the builder is additive, so the ~200 existing struct
  literals keep compiling. Migrating them is a separate, mechanical change.
- Production call sites migrated where the builder would otherwise be dead in a
  binary crate's lib build: `VmStartParams` in the persistent-OCI start path and
  `StandbySpecParams` in `warm_to_target`'s spawn loop.
- One test per builder: the defaulted ones assert an untouched builder agrees
  with `T::default()`; the checked ones assert an empty builder refuses and
  names its first missing field. `VmStartParams` and `StandbySpecParams` also
  get round-trip tests covering every optional setter.

## Deliberately not covered

- **Structs with one or two fields** (`ConvergeOpts`, `WalkOptions`,
  `RestoreParams`, `SecretValueInput`, …). CLAUDE.md's rule is "more than a
  couple of fields", and its YAGNI clause is explicit; a builder over two
  fields is more code to read, not less risk.
- **serde-deserialized wire DTOs** — `Sigv4Params`, `UploadParams`,
  `WebSearchParams`, `DownloadParams`, `WebFetchParams`, `TimeNowParams`. These
  are produced by `serde` from a tool-call JSON envelope, never by Rust code.
- **clap-derived `Args`** — `StartArgs`, `SubmitArgs`, `StopArgs` and the two
  `Args` command roots. clap constructs them from argv.
- **`WarmParams`** (`mvm-cli`'s `pool.rs`). `warm_to_target` has no production
  caller in this crate — only tests construct it — so a builder there is dead
  code in the lib build, and `#[allow(dead_code)]` is not an option we take.
  Worth revisiting when the warm path grows a production caller.
