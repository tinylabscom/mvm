# One `mvmctl`, one command: the Linux host payload without a second binary

Backing: shipped-source
Validation: none

**Status: COMPLETE**
**Opened:** 2026-09-24

## Why

A contributor ran `cargo build --release --locked` and then
`mvmctl machine run --image alpine -- ls`. Nothing appeared for minutes, and no
microVM started.

The release `mvmctl` carried no embedded Linux host payload. `embed-host-bins`
is opt-in, and the content-store restore missed. With the builder image stale
(`fingerprint_mismatch`), the run went to rebuild it, found no payload, and ran
`cargo build -q --bin mvmctl --features embed-host-bins` into
`target/mvm-builder-vm-bootstrap/debug/`. That compile produced a *second*
`mvmctl` and printed nothing (`-q`, no message before it), even under `-vvv`.
Measured: 2.5 minutes of blank terminal before the builder work started.

The documented fix was a second command (`just embed --release`), and the
fallback was a second binary. We want neither: running a microVM from a source
checkout takes one command and one `mvmctl`.

## What stays out of scope

The per-VM host processes (`mvm-hvf-supervisor`, `mvm-network-endpoint`, the
broker, the signers) remain separate executables. They are built by the same
`cargo build`, ship beside `mvmctl` in the release archive, and their process
separation and the HVF supervisor's own code signature are load-bearing for the
security claims. Folding them into a multicall `mvmctl` buys no ease of use.

Rebuilding the builder image in the VM after a builder-image source change
also stays (ADR-030's contributor invariant). It happens inside the one command.

## Decision

1. **Release builds embed by default.** `crates/mvm-cli/build.rs` embeds when
   `embed-host-bins` is on *or* the profile is `release` (cargo's `PROFILE`,
   which also covers profiles inheriting from `release`). `MVM_EMBED=0` opts a
   release build out. When the embed was implied by the profile (not
   requested by the feature) and the pinned toolchain is missing, the build
   does not fail: it emits a `cargo:warning=` naming the fix and writes the
   unembedded table, and item 2 covers the binary at run time. An explicit
   `embed-host-bins` keeps today's hard failure.
2. **A payload-less `mvmctl` builds its payload in-process.** When the running
   `mvmctl` has an empty embedded table and runs from a source checkout, it
   computes the same content-store key the build script uses, restores the set
   from `~/.cache/mvm/embed` or cross-compiles it into the store (the same
   `cargo zigbuild` invocation), and extracts from the store. The store is the
   one the build script already restores from, so the *next* plain
   `cargo build` bakes the same bytes into the binary with no compile.
3. **No second `mvmctl`.** The bootstrap-helper compile
   (`builder_vm_bootstrap_helper_build_command`, the `.features` stamp, the
   source-mtime staleness walk, `target/mvm-builder-vm-bootstrap/`) is
   deleted. Where a builder helper subprocess is still spawned, it is the
   current executable.
4. **Never silent.** Before any payload compile, `mvmctl` prints one line
   saying what it is building, why, and roughly how long it takes; cargo's
   progress streams through under `-v`.

## Workstreams

- [x] **W1 — share the payload build between build script and runtime.** Move
      the key computation, manifest parsing and `cargo zigbuild` invocation out
      of `crates/mvm-cli/build.rs` into one file both the build script
      (`#[path]`, as `embed_toolchain.rs` already is) and runtime code compile.
      Build-script behaviour is unchanged by this step alone.
- [x] **W2 — release profile embeds by default** (Decision 1), with the
      embed decision a pure function of (feature, profile, `MVM_EMBED`,
      toolchain readiness) and unit-tested per case.
- [x] **W3 — store-backed payload at run time** (Decision 2). Extraction reads
      from a payload source abstraction with two impls (compiled-in table;
      content store). Tests: store hit extracts without a compile; store miss
      invokes the build; a tampered store entry is refused by the existing
      sha256 check; a library embedder is refused as today.
- [x] **W4 — delete the second-`mvmctl` helper** (Decision 3) and its tests,
      keeping the library-embedder refusals and the bootstrap-active marker.
- [x] **W5 — progress output** (Decision 4), with a test that the message is
      emitted before the compile starts.
- [x] **W6 — CI and docs.** Release-profile CI builds that neither boot a VM
      nor carry zig set `MVM_EMBED=0` or rely on the warning path; `CLAUDE.md`,
      the `embed-host-bins` comments in both `Cargo.toml`s, the Justfile
      `embed` recipes and `public/src/content/docs/contributing/development.md`
      describe the new default.
