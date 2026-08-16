# Aux helper binaries drift from `mvmctl`, and two resolvers disagree about which one to run

Backing: shipped-source
Validation: none

Every path below was read on `main` at `0c9ef804d`. The two-divergent-binaries
observation is from a developer machine and reproduces by building two branches
through one shared `CARGO_TARGET_DIR`. Nothing here is gated yet — the checkboxes
are the work, not a record of it.

Deferred out of the builder-egress handshake fix. Neither item caused that
failure — the handshake timeout did — but both were found while diagnosing it,
and both make a future occurrence harder to diagnose than it needs to be.

## 1. Two resolvers for `mvm-network-endpoint`, with opposite precedence

`mvm_vmm::host::aux_bin::resolve` (`crates/mvm-vmm/src/host/aux_bin.rs`) is the
canonical resolver. Its order is `$<ENV_VAR>` → `$MVM_AUX_BIN_DIR` → next to
`current_exe` → workspace `target/{release,debug}`, and its doc comment says why
the build script's dir must come first: so a freshly built helper there is not
shadowed by a stale copy sitting next to a dev `cargo run` exe.

`resolve_network_endpoint_path` in `crates/mvm-build/src/libkrun_builder.rs`
reimplements that search and **omits `$MVM_AUX_BIN_DIR`**, so the builder path
picks exactly the copy the canonical resolver exists to avoid. `mvm-build`
already depends on `mvm-vmm` (`crates/mvm-build/Cargo.toml`), so it can call
`aux_bin::resolve` directly.

- [ ] Delete `resolve_network_endpoint_path` and call `aux_bin::resolve`.
- [ ] Note that this also drops the run-time `cargo build -p mvm-hostd`
      fallback, which is the intended behaviour: `aux_bin::resolve`
      deliberately never builds and errors with a `just build-supervisors` hint.
- [ ] Test: the builder path prefers `$MVM_AUX_BIN_DIR` over a decoy copy
      beside the exe.

## 2. The build script's watch list has two holes

`build_native_aux_helpers` in `crates/mvm-cli/build.rs` watches
`crates/mvm-hostd/src` and `crates/mvm-core/src` with a bare directory-level
`rerun-if-changed`. The same file's own comment on `emit_rerun_for_tree` states
that cargo does not reliably re-trigger a directory watch on a content edit to
an existing file, which is why `crates/mvm-runtime/src` and
`crates/mvm-build/src` get the file-by-file walk instead.

`crates/mvm-vmm/src` is not watched at all, though `mvm-network-endpoint` links
it (`cargo tree -p mvm-hostd --depth 1`).

Observed consequence: two `mvm-network-endpoint` binaries coexisting under one
shared target dir, built from different commits — one linking `rand 0.10` and
`crates/mvm-http/src/proxy.rs`, the other `rand 0.8` with no `proxy.rs`.

- [ ] Switch the `mvm-hostd/src` and `mvm-core/src` entries to
      `emit_rerun_for_tree`.
- [ ] Add `crates/mvm-vmm/src`.
- [ ] Extend the existing freshness guard rather than adding a second one:
      `supervisor_needs_rebuild` / `LIBKRUN_SUPERVISOR_INPUT_ROOTS` in
      `crates/mvm-build/src/libkrun_builder.rs` today covers only
      `mvm-libkrun-supervisor`. Add `crates/mvm-vmm/{Cargo.toml,src}` to its
      roots and apply it to `mvm-network-endpoint` too.

## 3. The deeper cause behind the handshake timeout

The handshake fix raises and bounds the budget and makes the failure legible. It
does not remove what made the budget tight: `pack_stage0_work_disk`
(`crates/mvm-build/src/libkrun_builder.rs`) writes a multi-gigabyte, non-sparse
`work.ext4` immediately before `BuilderVsockEgressEndpoint::spawn`, so the
endpoint's first exec competes with that flush.

- [ ] Consider spawning the egress endpoint *before* packing the work disk. The
      endpoint would then be alive across a long pack, which the parent-death
      watchdog and the RAII reaper already cover — confirm that before moving it.
