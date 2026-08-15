# The OCI rootfs cache is keyed on the runtime it actually contains

`oci_runtime_tag` decides whether an already-materialized OCI rootfs can be
booted as-is. It was `OCI_RUNTIME_EPOCH: u32 = 8` — a constant a human bumps —
folded with `guest_source_fingerprint`, a digest over `crates/mvm-agentd`'s
`Cargo.toml` and `src/`.

`inject_mvm_runtime` bakes in six artifacts. That fingerprint covers three of
them. `/init` (`mvm-oci-init`), `mvm-egress-client` and `mvm-verity-init` were
structurally invisible to it, so changing any of those invalidated nothing until
someone noticed. The constant's own doc comment is the record: epochs 3, 4, 5
and 8 are each a `/init`- or helper-shaped change that had to be caught by hand,
and epochs 4 and 5 were verity-handoff fixes — a stale rootfs there boots a
pre-fix agent inside a sealed image.

## Delivered

- `MvmRuntimeBinaries::content_digest` — a digest over the bytes of all six
  injected artifacts, plus the injection layout (`INJECT_DIRS` / `INJECT_DESTS`)
  that a byte digest cannot see and that decides which mountpoints a sealed
  image can create at boot. `MvmRuntimeBinaries::artifacts` is the one place the
  set is defined, so the digest and any caller that stats the same files cannot
  disagree about what "the injected runtime" is.
- `mvm_build::runtime_identity` — the digest recorded in a `runtime-id` sidecar
  beside the artifacts, with each artifact's length and mtime. The steady-state
  path reads the sidecar plus one `stat` per artifact; any disagreement discards
  it and recomputes. The sidecar is a cache, never an authority.
- `run_image::resolve_guest_runtime_identity` — the gate's entry point.
- `OCI_RUNTIME_EPOCH`, `source_runtime_fingerprint`, `oci_runtime_tag_with` and
  `oci_runtime_tag_with_epoch` deleted. `oci_runtime_tag` now takes a cache root.
- `mvm_build::guest_elf::validate_static_guest_elf`, called from
  `install_into_cache`: ELF64-LE, correct machine, no `PT_INTERP`, no
  `DT_NEEDED`. These are musl statics injected into a rootfs with no dynamic
  loader, where a wrong-architecture artifact boots to a silent PID 1 rather
  than failing. Fixed header offsets only, over our own build outputs under a
  mode-0700 cache — no section-table walk, no allocation driven by a field read
  out of the file.

## The constraint that shaped it

The tag gate runs before anything has decided a materialization is needed, and
`resolve_guest_binaries` **builds** on a cold cache. A naive digest-the-bytes
implementation turns an every-invocation question into a cross-compile;
`guest_agent_build.rs` records what that costs, at three `pull_core` tests that
"came to spend fifty-five seconds each building the guest agent".

Hence the sidecar. Measured **2.6ms per call** steady-state against a 200ms
dispatch budget, and a cold guest cache returns a marked `pending-` identity
rather than building. Both are asserted rather than asserted-about: one test
chmods every artifact to 0000 and still requires the tag to resolve, another
requires the cold path to answer without building, and a third pins the
per-call cost under a ceiling.

## On the tests

Mutation-checked, and it mattered — two rounds were rewritten because they
passed under mutation:

- The content tests perturbed artifacts by *appending*, so the length prefix
  satisfied them without the bytes ever being covered; digesting the path
  instead of the content still passed. They now mutate in place at constant
  length, and length has its own test that holds mtime constant.
- Two tests drove themselves from the function under test — one iterated
  `artifacts()`, one re-derived the whole encoding inline — so dropping an
  artifact or dropping the layout fold made the test stop looking too. They now
  enumerate the fields independently and compare real digests through a seam
  (`content_digest_with_shape`).

`guest_elf`'s corrupt-header test caught a real overflow panic in the reader on
an absurd `e_phoff`, fixed with checked arithmetic.

One line has **no killing mutation** and says so in a comment rather than being
defended by a test that would misrepresent it: with a fixed field set, nothing
can forge a neighbouring field's framing, so the per-artifact length prefix is
framing hygiene for a future variable-length set, not a live defence.

## Deferred

The launch-path restructuring that was scoped alongside this is tracked in
`specs/plans/2026-08-15-launch-path-as-declared-stages.md`. It is a separate
change against `crates/mvm-cli/src/exec.rs` with a security-relevant ordering
constraint, and shares no files with this one.

## Verification

`cargo nextest run --workspace` 11806 passed / 0 failed; `cargo clippy
--workspace --all-targets -- -D warnings` clean; `cargo test --workspace --doc`
clean; `just check-gated` clean; xtask gates clean including
`check-claim-catalog`, `check-guest-binary-lists`, `check-guest-init-parity`,
`check-vsock-only-egress`, `check-no-gateway-names`, `check-single-home` and
`check-honesty`.

No change to the egress seam, the vsock chokepoint, admission, the audit chain,
or any claim witness.
