# One `mvmctl`, one command: the host payload without a second binary

Plan: `specs/plans/2026-09-24-single-binary-payload.md`.

A contributor ran `cargo build --release` and then `mvmctl machine run --image
alpine -- ls`, and saw nothing for minutes. The release binary carried no
embedded Linux host payload, so the run compiled a second, embedding `mvmctl`
into `target/mvm-builder-vm-bootstrap/` with `cargo build -q` — no output, even
under `-vvv`. The documented fix was a second command, `just embed --release`,
and a later plain release build undid it.

## What changed

- **Release builds embed by default.** `crates/mvm-cli/build.rs` embeds when
  `embed-host-bins` is on or cargo's `PROFILE` is `release`. `MVM_EMBED=0` opts
  a release build out. A profile-implied embed whose toolchain probe fails
  prints a `cargo:warning=` naming the fix and ships the unembedded table; the
  explicit feature still fails hard. The decision is a pure function in
  `build_support.rs`, unit-tested per case. Debug builds — `cargo check`,
  clippy, nextest — still compile nothing.
- **A payload-less `mvmctl` builds its payload in-process.** The payload now
  comes through `host_binaries::source`: either the compiled-in table or the
  content store at `~/.cache/mvm/embed`, filled from the checkout the binary
  was built from with the build script's own keys and `cargo zigbuild` (shared
  through `src/host_binaries/payload_build.rs`). Extraction and the builder
  image fingerprint read the payload through it, so stored and compiled-in bytes
  fold identically, and the next plain `cargo build` embeds the stored bytes
  without compiling them. Only `mvmctl` may do this; test binaries and other
  consumers keep the refusal, and a library embedder is refused as before.
- **The store records digests.** Each published artifact carries the SHA-256 it
  was built with; an entry whose bytes changed is refused at run time and not
  restored at build time. Entries published before this adopt a digest on first
  read.
- **Never silent.** Before any runtime compile `mvmctl` prints one `[mvm]` line
  on stderr saying what it is building, why, and roughly how long it takes;
  `-v` streams cargo's output.
- **No second `mvmctl`.** The bootstrap-helper compile is gone: the feature
  mirror and its `.features` stamp, the source-mtime staleness walk, the helper
  target directory, and the root build script's feature recording that only fed
  it. The helper is the named override or the current executable.
- **Toolchain.** `just toolchain-embed` also installs the pinned
  cargo-zigbuild, so it provisions everything the compile needs.
- **CI.** The reproducibility lane and the pack-signing image-set step set
  `MVM_EMBED=0`: neither boots a VM, and the reproducibility comparison would
  otherwise restore Build B's payload from the store Build A filled.

## Measured

On an Apple Silicon host under load (1-minute load average 17–21):

- A debug `cargo build --bin mvmctl` after editing `mvm-cli` sources ran no
  `zigbuild` (0 matches in the `-vv` log).
- A debug `mvmctl machine run --image alpine -- ls` with an empty table and a
  fresh store printed the status line 7 s in, ran `cargo-zigbuild` as its own
  child (no second `mvmctl` under `target/`), and filled the store with the
  five binaries in 8 m 24 s from a cold nested target.
- The next debug `cargo build` restored all five from that store and embedded
  them (binary grew by 4.9 MB) in 7.7 s, confirming the runtime and the build
  script compute the same keys.
