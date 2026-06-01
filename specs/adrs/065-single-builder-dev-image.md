# ADR-065 — Single builder/dev image with mvmctl-embedded Linux binaries

**Status:** Proposed (2026-05-29). Refactored 2026-05-29 to embed the
Linux binaries in `mvmctl` itself (`build.rs` + `include_bytes!`)
rather than invoking cargo at `dev up` runtime. See §Decision.
**Supersedes:** the dev-image-vs-builder-VM-image split established by
ADR-046 §"Two artifact layers, two acquisition paths" — see §Migration.
**Related (do not change in this ADR):** the SDK end-user transparency
story (`crates/mvm-sdk/src/compile/flake.rs`, ADR-0007), and ADR-046's
source-checkout invariant (preserved unchanged here).
**Concurrent work to track:** Plan 107 A1a/A1b — `mvm-builder-init` is
being renamed to `mvm-host-vm-init` (commit `58c737dd` merged, PR
#506 open for the crate rename). ADR-065 names match whichever lands
first; the implementation plan should adopt the final name.

## Context

`mvmctl dev up` from a source checkout today drives this chain:

1. mvmctl spawns Stage 0 (libkrun + libkrunfw kernel + Alpine + nix).
2. Stage 0 runs `nix build path:/work/nix/images/builder-vm#packages.<system>.default`.
3. The flake calls `rustPlatform.buildRustPackage` for `mvm-builder-init`,
   `mvm-egress-proxy`, and (via the dev-image flake) a second copy of
   `mvm-builder-init`.
4. Nixpkgs translates `Cargo.lock` into ~290 per-crate `fetchCrate`
   derivations.
5. Each `fetchCrate` curls `https://crates.io/api/v1/crates/<name>/<v>/download`
   with no User-Agent and gets HTTP 403 under crates.io's data-access
   policy. The build collapses.

Two further smells were uncovered while debugging this:

- **Two flakes producing nearly the same artifact.** `nix/images/builder-vm/`
  produces the headless builder VM; `nix/images/builder/` produces the
  "dev shell" image. The only structural reason the dev image existed
  separately was a circular Stage-0 bootstrap: when the builder-VM cache
  was empty, mvmctl could boot the dev image as PID 1 (`mvm-builder-init`)
  and ask it to build the builder VM. The dev image carries its own
  copy of `mvm-builder-init` solely for that fallback.
- **mvm is rebuilding its own product on every contributor's `dev up`.**
  `mvm-builder-init`, `mvm-egress-proxy`, and (out of scope here)
  `mvm-guest-agent`, `mvm-runner` are mvm's binaries — not user code.
  They should be *inputs* to the builder-VM image build, the same way
  the Linux kernel and busybox are inputs. Today they are translated
  through nixpkgs's curl-based crate fetcher every time, which is both
  the wrong tool (cargo handles this trivially with a proper UA) and
  the wrong responsibility (the builder VM exists to build microVMs,
  not to recompile mvm's source code).

The crates.io 403 problem will be fixed upstream in days (PR
NixOS/nixpkgs#525067 merged 2026-05-28; backport PR #525491 open). A
nixpkgs overlay would unblock today's `dev up`. But shipping that
overlay would entrench both smells above. We have a chance to address
the underlying shape instead.

## Decision

1. **Collapse the dev image and the builder VM image into a single flake
   with two attributes.** `nix/images/builder/flake.nix` is deleted.
   `nix/images/builder-vm/flake.nix` becomes the only flake, producing:
   - `packages.<system>.default` — the headless builder VM. Boots
     for `mvmctl build`, `mvmctl run`, and every other command that
     needs an internal builder. Exits when its job completes.
   - `packages.<system>.dev` — the same base image plus the
     interactive layer: `bashInteractive`, `cargo`, the Rust toolchain
     matching the workspace, an editor, motd, and PTY-over-vsock
     console plumbing. Boots only for `mvmctl dev up`, which always
     attaches a shell — there is no headless `dev` variant by design.

   The Stage 0 chicken-and-egg dance (`bootstrap_builder_vm_image_via_
   dev_image_stage0`) dissolves because there is no longer a separate
   dev image to bootstrap from. Only the Alpine + libkrunfw Stage 0
   path remains.

2. **mvm's Linux binaries are embedded in `mvmctl` at *its own build
   time*, not at `dev up` runtime.** A new contract, all compile-time:

   - **`crates/mvm-cli/build.rs` cross-compiles the Linux binaries
     during `cargo build` of mvm-cli.** For each entry in a Rust
     manifest constant (`crates/mvm-cli/src/host_binaries/
     manifest.rs`), the build script invokes `cargo zigbuild --target
     aarch64-unknown-linux-musl --release -p <cargo_package>` (or
     plain `cargo build` when the build host *is* aarch64-linux) and
     writes the binary to `$OUT_DIR/mvm-host-bins/<name>`. The paths
     are baked into mvmctl as `include_bytes!` byte arrays plus a
     precomputed SHA-256 content hash.

   - **Runtime is just extraction, never compilation.** On the first
     use per mvmctl process, mvmctl extracts each embedded binary to
     `~/.cache/mvm/host-bins/<content-hash>/<name>` (idempotent: a
     fresh mvmctl process with the same binary content hits the
     existing dir; a different mvmctl version writes a different dir).
     mvmctl sets `MVM_HOST_BIN_DIR` to that dir before invoking the
     in-VM nix build. **No runtime cargo invocation. No runtime
     manifest parsing. No `target/` lookup.** mvmctl is a true
     single-binary unit of distribution.

   - **The flake-side view: `nix/lib/mvm-host-binaries.nix`.** A small
     Nix attrset, parallel to `workspace-filter.nix`. Same set of
     entries as the Rust manifest, declaring each binary's
     `install_path` and `mode`:
     ```nix
     {
       mvm-builder-init = {
         install_path = "/sbin/mvm-builder-init";
         mode = "0755";
       };
       mvm-egress-proxy = {
         install_path = "/sbin/mvm-egress-proxy";
         mode = "0755";
       };
     }
     ```
     The flake reads this attrset natively, iterates entries under
     `--impure` using `MVM_HOST_BIN_DIR` to locate the extracted
     binaries, and generates `extraFiles` mechanically — no
     hand-written per-binary entries.

   - **CI invariant: the Rust manifest and the Nix attrset stay in
     sync.** A small xtask (`xtask check-mvm-host-binaries-sync`)
     parses both and asserts the entries match by name and
     `install_path`. Cheap because the manifest is small and changes
     rarely.

   - **No `rustPlatform.buildRustPackage` for mvm's binaries** in the
     builder-VM flake (or in the deleted dev-image flake). The
     `fetchCrate` path stops being on `dev up`'s critical path
     entirely, regardless of what crates.io's data-access policy does.

   - **Contributor toolchain delta:** `brew install zig` plus
     `cargo install cargo-zigbuild` — needed at `cargo build`-of-
     mvmctl time, not at `dev up` runtime. Probed by `mvmctl doctor`
     with install hints, same surface as the existing libkrun trio.
     Native Linux contributors require nothing new.

3. **The dev VM is the builder VM with interactivity.** Both attrs build
   from the same kernel, base userland, networking, mvm binaries,
   security posture, audit chain. The `dev` attr adds packages and
   wires a TTY; nothing about the underlying VM model changes. There
   is no headless dev VM and no interactive builder VM.

## Why cargo zigbuild

Three reasons, in order of how much each actually matters. (These
apply whether zigbuild runs at mvmctl-build-time or at runtime; the
embedding choice in §Decision doesn't change the tool.)

1. **Crates with C in `build.rs` actually compile.** `ring`,
   `aws-lc-rs`, `openssl-sys`, etc. typically fail under Homebrew's
   `aarch64-elf-gcc` because there is no glibc sysroot. Zig ships its
   own multi-arch C toolchain with a real glibc sysroot.
2. **Single Homebrew install (`brew install zig`), no Docker.** Uses
   cargo's native `target/` directory, so incremental compile shares
   state with the contributor's normal `cargo build`. Editing
   `mvm-builder-init` source triggers an incremental cross-compile
   inside `build.rs`, not a full rebuild.
3. **Static musl, so no rootfs loader needed.** The pinned target is
   `aarch64-unknown-linux-musl` (static; see
   `[workspace.metadata.mvm.toolchain]`). The builder VM's minimal
   NixOS-derived rootfs ships no FHS dynamic loader
   (`/lib/ld-linux-aarch64.so.1`), so a glibc-dynamic init binary
   panics the guest with `Requested init … failed (error -2)` (ENOENT
   on the interpreter). A static binary has no interpreter dependency —
   it runs as PID 1 in any rootfs, the same reason mkGuest static-links
   its own `/init`. This supersedes the earlier glibc-version-pinning
   approach (`gnu.2.17`), which only worked if the rootfs carried a
   matching loader. Both host binaries are libc-only (no `ring` /
   `openssl-sys` / TLS), so the musl build is unencumbered.

Alternatives considered:

- **`cross`** (Docker-based) — slower startup, separate target dir
  from cargo's, Docker dependency on macOS contributors.
- **Hand-rolled Homebrew cross-toolchain** — high per-contributor
  setup tax, breaks on C-in-`build.rs` crates, no glibc sysroot.
- **Cargo at `dev up` runtime instead of `mvm-cli`'s `build.rs`** —
  the rejected earlier draft. Conflates mvmctl's orchestration
  responsibility with build-system orchestration; introduces a
  runtime dependency on cargo + zigbuild even after mvmctl is built;
  makes mvmctl-the-binary not a self-contained unit.
- **Build inside a Linux container/VM** — slower inner loop, runs
  against the responsibility split established here (the dev/builder
  VM's job is *building microVMs*, not recompiling mvm).
- **Cargo inside the builder VM, bootstrap-staged** — recreates the
  Stage 0 chicken-and-egg shape in a new place.

## Architecture / data flow

### Layers (with sharp boundaries)

- **mvmctl build time (`cargo build` of mvm-cli)** — `build.rs`
  cross-compiles each entry in the host-binaries manifest via
  `cargo zigbuild`. Outputs land in `$OUT_DIR/mvm-host-bins/<name>`
  and are baked into the mvmctl binary via `include_bytes!` plus a
  precomputed SHA-256. From the artifact perspective: the mvmctl
  binary now contains everything it needs to run a builder/dev VM.
- **mvmctl runtime (host)** — On first use per process, extracts the
  embedded binaries to `~/.cache/mvm/host-bins/<content-hash>/`
  (idempotent). Sets `MVM_HOST_BIN_DIR` for downstream use. **No
  cargo invocation. No `target/` lookup. No manifest parsing.**
- **Stage 0 (libkrun + libkrunfw kernel + Alpine + nix)** —
  unchanged in role. New inputs: the extracted binary dir mounted at
  `/mvm-bins` via virtio-fs, and `MVM_HOST_BIN_DIR=/mvm-bins` in env.
  Output: builder-VM image artifacts (`vmlinux` + `rootfs.ext4` +
  cmdline.txt + manifest.json). The flake never compiles Rust.
  Rootfs assembly uses `mkfs.ext4 -d <staged-dir>` (a populate-at-
  format pattern) so the final image is built from a populated
  directory tree in one step.
- **Builder VM (the produced image)** — one image, two attrs as
  defined in §Decision.

### `mvmctl dev up` end-to-end

Steps in **bold** are new or substantially changed; the rest match
today's shape.

1. User runs `mvmctl dev up` (always interactive).
2. mvmctl detects source-checkout mode (workspace + flake present).
3. **mvmctl extracts the embedded Linux binaries to
   `~/.cache/mvm/host-bins/<content-hash>/`** if not already there.
   The hash is part of the mvmctl binary; identical mvmctl binaries
   produce identical extractions and reuse the same dir.
4. mvmctl boots Stage 0 with two virtio-fs shares: `/work`
   (workspace) and **`/mvm-bins`** (the extracted dir from step 3).
5. Stage 0 runs `nix build path:/work/nix/images/builder-vm#packages.
   <system>.dev --impure` (`.default` for non-`dev` commands).
   `MVM_HOST_BIN_DIR=/mvm-bins` set in env.
6. **The flake reads `mvm-host-binaries.nix`, iterates entries, and
   generates `extraFiles` entries pointing at `/mvm-bins/<name>` with
   the declared `install_path` and `mode`.** No `rustPlatform`. No
   `fetchCrate`.
7. Nix produces `vmlinux` + `rootfs.ext4` (assembled via
   `mkfs.ext4 -d`); Stage 0 powers down.
8. mvmctl extracts to `~/.cache/mvm/builder-vm/<system>/`, keyed on
   (workspace SHA, mvmctl host-bin content hash, flake SHA).
9. mvmctl boots the dev VM via whichever backend the host selects
   (libkrun / Vz / Apple Container per the existing
   `MVM_BUILDER_BACKEND` rules).
10. mvmctl opens a PTY-over-vsock console into the running VM.

For `mvmctl build`, `mvmctl run`, and other non-`dev` commands: same
path, but step 5 targets `packages.<system>.default`, step 9 boots
headless, no step 10.

### Cache invalidation

- **mvmctl binary changes** (e.g., because `mvm-builder-init` source
  changed and `build.rs` re-cross-compiled) → embedded content hash
  changes → cache key changes → rebuild.
- `mvm-host-binaries.nix` changes → flake re-bakes → cache key
  changes → rebuild.
- Workspace SHA changes elsewhere → cache key changes → rebuild.
- Nothing changed → mvmctl boots straight from cache; extraction is
  a no-op (target dir already exists).

## Component-level diff

### New

- `nix/lib/mvm-host-binaries.nix` — flake-side attrset (the manifest's
  Nix view). Single purpose, pure data.
- `crates/mvm-cli/build.rs` — orchestrates the cross-compile during
  `cargo build` of mvm-cli. Invokes `cargo zigbuild` per manifest
  entry, computes SHA-256 of each output, writes both bytes and
  hashes into `$OUT_DIR/mvm-host-bins/`.
- `crates/mvm-cli/src/host_binaries/` — small module: `manifest.rs`
  declares the Rust-side manifest constant; `embedded.rs` exposes
  the `include_bytes!`'d binaries + their hashes; `extract.rs`
  handles the idempotent extraction to `~/.cache/mvm/host-bins/
  <hash>/`.
- `xtask check-mvm-host-binaries-sync` — CI lane asserting the Rust
  manifest and `nix/lib/mvm-host-binaries.nix` agree on name set and
  `install_path`.

### Modified

- `nix/images/builder-vm/flake.nix` — substantially rewritten:
  - Two attrs: `packages.<system>.default` and `packages.<system>.dev`.
  - No `rustPlatform.buildRustPackage` for mvm binaries.
  - Reads `mvm-host-binaries.nix` and `MVM_HOST_BIN_DIR` under
    `--impure`; generates `extraFiles` mechanically.
  - The `dev` attr adds `bashInteractive`, `cargo`, Rust toolchain,
    editor, motd, PTY-over-vsock console wiring.
  - Rootfs assembly: explicit `mkfs.ext4 -d <staged-dir>` (or the
    nixpkgs equivalent if `mkGuest` already does this internally —
    confirm during implementation; either way the assembly step is
    legible in the flake, not buried).
- `nix/lib/workspace-filter.nix` — drops `nix/images/builder` from
  its list of consumers (3 → 2).
- `crates/mvm-cli/src/commands/env/apple_container.rs` — collapses
  the source-checkout dispatch: the `find_dev_image_flake` /
  `ensure_source_checkout_dev_image` /
  `resolve_source_checkout_dev_image` branches go away.
  `cmd_dev_libkrun` / `cmd_dev_vz` call into
  `host_binaries::ensure_extracted()` (cheap on warm runs) before
  invoking nix, and target the `dev` attr.
- `crates/mvm-build/src/pipeline/dev_build.rs` —
  `dev_build_with_builder_vm` mounts the host-bin dir from
  `host_binaries::ensure_extracted()` and passes `MVM_HOST_BIN_DIR`
  into the in-VM nix invocation.
- `crates/mvm-cli/src/doctor.rs` — adds a build-time probe report
  for `zig` and `cargo-zigbuild` on macOS contributors with install
  hints (these are needed for `cargo build` of mvm-cli, not for `dev
  up`). Native Linux contributors pass trivially. The doctor also
  reports the embedded-binary content hashes (one-line each) so
  contributors can sanity-check what their mvmctl carries.
- `CLAUDE.md` "Host dependencies (macOS)" — adds `zig` and
  `cargo-zigbuild` as build-time deps for source-checkout
  contributors. Clarifies these are not needed at `dev up` runtime.

### Deleted

- `nix/images/builder/flake.nix` — gone.
- The four `rustPlatform.buildRustPackage` call sites for
  `mvm-builder-init` / `mvm-egress-proxy` across the builder-vm and
  builder flakes.
- `find_dev_image_flake`, `ensure_source_checkout_dev_image`,
  `resolve_source_checkout_dev_image`,
  `bootstrap_builder_vm_image_via_dev_image_stage0` in
  `apple_container.rs`.
- The `mvmBuilderInitFor` helper duplicated between the two flakes —
  only one consumer survives, and it's not `rustPlatform`-based.

### Touched only mechanically

- Tests referencing the deleted flake or dispatch helpers — updated
  to the single-flake shape or removed if redundant.
- `nix/images/runtime-overlay/flake.nix` — left intact (out of scope;
  it still uses `rustPlatform` for `mvm-runner` and the guest agent).
  The mechanism defined here is reusable by a later spec that
  converts runtime-overlay to embed those binaries the same way;
  doing so is explicitly *not* required for this spec.

## Error handling

- **`zig` or `cargo-zigbuild` missing during `cargo build` of mvm-cli
  on macOS:** `build.rs` exits with a `cargo:warning=…` line that
  names the missing tool and the install command. Failing the build
  is correct — without zigbuild we cannot produce a working mvmctl.
- **Cargo build fails for any configured package at mvmctl-build
  time:** cargo's normal stderr appears; `build.rs` surfaces the
  failing package name in its own error context so the cause is
  locatable.
- **At runtime, extraction fails (filesystem error, perms):**
  mvmctl fails fast with the target dir path and the underlying I/O
  error. No fallback to "try cargo" — there is no runtime cargo path.
- **`MVM_HOST_BIN_DIR` not set when the flake is evaluated:** the
  flake errors loudly with the contract documented inline (a
  contributor running `nix build` directly without going through
  mvmctl gets a useful message, not a Nix evaluation failure 12
  layers deep).
- **A binary declared in `mvm-host-binaries.nix` not present in
  `MVM_HOST_BIN_DIR`:** the flake errors with the missing name +
  the dir path. The CI sync check makes this combination impossible
  in CI but it's still possible on a contributor's machine if
  someone manually rewrites the Nix attrset without rebuilding
  mvmctl.

## Testing

- **Unit tests (`crates/mvm-cli/src/host_binaries/`):** parse the
  manifest, assert the embedded SHA-256 matches the embedded bytes,
  assert extract is idempotent against an existing populated dir.
- **`build.rs` integration test:** a small fixture asserts `build.rs`
  produces non-empty binaries with valid ELF headers for
  aarch64-unknown-linux-gnu and embeds them under the expected names.
- **`xtask check-mvm-host-binaries-sync` test:** asserts the Rust
  manifest and `mvm-host-binaries.nix` agree on name set and
  install_path; deliberate divergence triggers a clear failure.
- **Flake-side fixture test:** feeds a hand-crafted
  `MVM_HOST_BIN_DIR` (with placeholder binaries) into `nix build`
  and asserts the produced rootfs.ext4 has files at the declared
  install paths with the declared modes.
- **End-to-end smoke (CI macOS lane):** runs the real `cargo build`
  of mvm-cli (triggering the embedded cross-compile), then runs
  `mvmctl dev up`, asserts the produced builder-VM image has
  `/sbin/mvm-builder-init` and `/sbin/mvm-egress-proxy` with
  SHA-256 matching the embedded hashes.
- **Tests touching the deleted dev-image dispatch helpers** —
  updated to reflect the collapse (most likely removed; the helpers
  are gone).

## Out of scope

- **Converting `nix/images/runtime-overlay/flake.nix` and the guest
  agent's build to use the embedded-binary contract.** The mechanism
  is reusable; doing the conversion is a follow-up spec. Keeps blast
  radius small.
- **The SDK's `mkGuest` adoption of the same contract** for end-user
  microVMs (so end-user `mvmctl compile` becomes
  `fetchCrate`-independent). Same reasoning — separate spec, separate
  PR. The mechanism here is designed to be adopted there later
  without changes.
- **Release pipeline changes.** Today's release workflow already
  cross-compiles to `aarch64-unknown-linux-gnu`; the embedded-binary
  pattern means the release pipeline only needs to ship the mvmctl
  binary (everything else rides inside it). No standalone Linux
  binary release artifacts to publish. Called out as a simplification
  this spec enables but does not enforce.
- **The `builder_vm_timeout()` value** and the partial-cache
  promotion bug observed during debugging this. Both are pre-existing,
  unrelated, and out of scope. Calling them out so future readers
  know they were noticed and parked.
- **Merging `mvm-builder-init` and `mvm-egress-proxy` into a single
  multi-call binary.** Considered (busybox-style would save ~5 MB on
  the embedded payload). Rejected because they have different uid
  policies and different threat-model exposure: builder-init is PID
  1, egress-proxy is uid 1801 and internet-facing. Merging conflates
  two things the security model treats separately. Future cleanup
  not blocked here.
- **Any change to `mvm.toml` shape or the SDK's end-user transparency
  story.** Reserved for the SDK's own specs.

## Future directions

(Not part of this spec — flagged so the implementation plan doesn't
paint future work into corners.)

- **OCI-base userland.** An external reference design pulls a Debian
  OCI image as the rootfs base, customises it in a chroot, and
  `mkfs.ext4 -d`'s the result. We already have `mvm-oci` in the
  repo (claim 10) for the end-user workload path. Using the same
  pattern for the *builder/dev VM rootfs* — Debian/Alpine base + mvm
  binaries on top, no nixpkgs busybox/iptables/etc. — would drain
  Nix from the rootfs userland side, complementing how ADR-065 drains
  it from the Rust-build side. Big architectural shift with its own
  threat-model implications (provenance of the OCI base, signature
  chain). Worth its own brainstorm later.
- **Apply the embedded-binary contract to runtime-overlay** so
  `mvm-runner` and `mvm-guest-agent` follow the same shape. Removes
  another `rustPlatform.buildRustPackage` site.
- **SDK's `mkGuest` adoption.** End-user `mvmctl compile` becomes
  `fetchCrate`-independent the moment `mkGuest` consumes the same
  contract.
- **Plan 107 A1b crate rename.** `mvm-builder-init` →
  `mvm-host-vm-init` is in flight (PR #506). ADR-065's implementation
  plan should adopt whichever name lands first and is expected to
  use the new name end-to-end if A1b merges before this work begins.

## Consequences

### Positive

- **`fetchCrate` exits mvm's hot path.** crates.io's User-Agent policy,
  rate limits, and future surprises stop being a `dev up` concern.
- **mvmctl is a true single-binary unit of distribution.** No
  runtime cargo dependency. No `target/` lookup. No separate Linux
  binary release artifacts. End-user downloads one file; that file
  contains everything it needs to build and run a builder/dev VM.
- **Single image, single source of truth.** The dev/builder split
  dissolves. The Stage-0 chicken-and-egg fallback (boot dev image to
  build builder VM) dissolves with it.
- **Cleaner responsibility split.** mvmctl is a VM orchestrator;
  cargo is a build system; nix assembles the rootfs. Each does
  exactly one job. The previous draft had mvmctl shelling out to
  cargo at runtime — this version eliminates that.
- **Less surface area in mvmctl.** Three dispatch helpers
  (`find_dev_image_flake`, `ensure_source_checkout_dev_image`,
  `resolve_source_checkout_dev_image`) go away. One bootstrap path
  remains, not two.
- **Aligns with existing release infrastructure.** `release.yml`
  already cross-compiles to `aarch64-unknown-linux-gnu`; the
  embedded path uses the same target triple and toolchain logic
  inside mvm-cli's `build.rs`.

### Negative

- **mvmctl binary grows by the embedded payload** (probably +5–15 MB
  for two static `-gnu` binaries; less if we eventually go `-musl`
  static). Cost is real but bounded.
- **`cargo build` of mvm-cli now does the cross-compile.** First
  build adds ~30–60s for the two Linux binaries. Subsequent builds
  are incremental — editing `mvm-builder-init` source rebuilds only
  that crate via cargo's normal incremental detection, then re-links
  mvmctl (the link step is what feels slow, not the cross-compile).
- **Iterating on `mvm-builder-init` source incurs a mvmctl re-link.**
  Not a full rebuild, but noticeable on a hot loop. Mitigation:
  contributors who are deep in `mvm-builder-init` work can run
  `cargo build -p mvm-builder-init --target aarch64-unknown-linux-gnu`
  directly and skip the mvmctl link; mvmctl's `MVM_HOST_BIN_DIR_OVERRIDE`
  env var (TBD during implementation) can point at the bare target/
  output for that workflow. Not required for normal use.
- **The Rust manifest and the Nix attrset are two-sided.** CI sync
  check enforces equivalence. Cost is small because the manifest is
  small and changes rarely.
- **New host build-time deps for macOS source-checkout contributors:**
  `zig` + `cargo-zigbuild`. One brew install + one cargo install,
  probed by doctor. Native Linux contributors are unaffected.

## Migration

The deletion of `nix/images/builder/flake.nix` is the high-blast
change. Specifically:

- Anything that called `find_dev_image_flake()` returns `Err` because
  the file is gone; the dispatch above it is removed in the same PR
  so the call no longer exists.
- The Stage 0 path `bootstrap_builder_vm_image_via_dev_image_stage0`
  is deleted. Only `bootstrap_builder_vm_image_via_root_dir_stage0`
  remains (the Alpine + libkrunfw path that's been the source-checkout
  default since Plan 92/95).
- `~/.mvm/dev/current/` (the cached dev image, separate from the
  builder-VM cache) becomes a stale concept. A best-effort cleanup
  on first `dev up` after the upgrade isn't required; the dir simply
  stops being read.
- **Existing mvmctl binaries that predate this change cannot use the
  new flake.** Cache invalidation is automatic (the content-hash key
  for the builder-VM cache will not match), but contributors must
  rebuild mvmctl once after the merge.

## Verification

- `mvmctl dev up` from a clean macOS source checkout, after a
  successful `cargo build` (with `zig` + `cargo-zigbuild` installed):
  no runtime cargo invocation; Stage 0 produces the builder-VM
  image from the embedded binaries; dev VM boots with a working
  interactive shell. No `crates.io` reachability required at any
  point during Stage 0's `nix build`.
- `mvmctl build` (or any non-`dev` command requiring the builder VM)
  from the same setup: same Stage 0 path, builder VM boots headless,
  job completes, VM exits.
- Edit a file in `mvm-builder-init/src/` and re-run `cargo build`
  followed by `mvmctl dev up`: `build.rs` incrementally re-cross-
  compiles `mvm-builder-init`; mvmctl re-links with the new embedded
  payload; new content hash; Stage 0 re-bakes the rootfs; the rest
  of the closure stays cached in the persistent `/nix-store`.
- Manually running `nix build path:.#packages.<system>.default --impure`
  without `MVM_HOST_BIN_DIR` set: clear, documented error pointing
  at the contract.
- Audit chain (claims 8 / 9 / 10): builder VM image's audit
  emission and verification are unaffected because the rootfs
  contents, paths, and binaries' SHA-256s are still deterministic
  given a fixed mvmctl binary + flake.

## References

- ADR-046 — Builder VM via libkrun. This ADR amends the "Two artifact
  layers" rule by collapsing the dev image into the builder VM image.
- Plan 72 — Builder VM via libkrun (the implementation of ADR-046).
- Plan 92, 95 — Alpine + libkrunfw Stage 0; the path this spec
  doubles down on as the only Stage 0 path going forward.
- Plan 107 A1a/A1b — Concurrent `mvm-builder-init` →
  `mvm-host-vm-init` crate rename (commit `58c737dd` merged; PR
  #506 open). ADR-065 implementation should adopt the final name.
- `crates/mvm-sdk/src/compile/flake.rs` and ADR-0007 — the end-user
  flake generation path, which adopts the same embedded-binary
  contract in a future spec.
- An external microVM reference project's build tooling — the
  `mkfs.ext4 -d <staged-dir>` rootfs assembly pattern we lift, and the
  direct-kernel-boot precedent we already follow.
- NixOS/nixpkgs PR #525067 — the upstream `fetchCrate` fix
  (static.crates.io) that motivated this redesign. The overlay was
  considered as a workaround and explicitly rejected in favor of
  removing the dependency on `fetchCrate` for mvm's own binaries.
