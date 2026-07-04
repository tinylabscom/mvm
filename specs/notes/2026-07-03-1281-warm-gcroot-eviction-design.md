# Design: per-kind builder warm gcroot (fixes #1281)

**Status:** Approved (brainstorm) — ready for implementation
**Issue:** #1281 — single fixed-name warm gcroot (`mvm-warm-latest`) can evict the
workload kernel between alternating builds → unexpected cold recompile
**Scope:** one file (`crates/mvm-build/src/builder_vm_runtime.rs`) + one test

## Problem

The persistent builder VM's flake-build script pins each completed build's closure
under a **single fixed-name** indirect gcroot,
`/nix/var/nix/gcroots/mvm-warm-latest`, overwritten on every build
(`builder_vm_runtime.rs`, in `render_flake_cmd_sh`, ~line 448). The purpose is to
spare the just-built closure (kernel + runtime base) from the cap-triggered
`nix-collect-garbage --delete-older-than 14d` (~line 518), which fires once the
persistent `/nix` store grows past the cap (default 24 GiB) and deletes every
*unrooted* path.

Because the root name is fixed and shared, only the **latest** closure stays warm.
Two build kinds flow through this one root and carry **different** closures:

- **builder-VM image** — `dev up` / Stage 0 rebake (builder kernel).
- **workload image** — `machine run --flake` / `--image` (its own kernel/base).

Alternating them ping-pongs the single root, so the displaced kind goes unrooted and
is eventually GC'd → the next run recompiles from source (minutes):

```
machine run …   → mvm-warm-latest = workload closure   (workload warm)
dev up / stage0 → mvm-warm-latest = builder closure     (workload now UNROOTED)
… store exceeds cap → GC → workload closure evicted
next machine run → cold recompile
```

### Verified facts (against `main`)

- The single fixed root is still present at `builder_vm_runtime.rs:448`.
- Kernel builds (`mvmctl build kernel`) do **not** use this root — they go through
  Stage 0, which has its own GC. So `mvm-warm-latest` only ever pins **image**
  builds via `run_build`.
- Output shape is **not** a reliable kind discriminator: a Linux/Firecracker
  workload image also emits a directory with a `vmlinux`, same shape as a builder
  image. So `[ -f "$NIX_OUT" ]` would mis-bucket it.
- The builder-VM image derivation name is a stable in-repo convention
  (`nix/images/builder-vm/flake.nix:351`): `mvm-builder-vm-image-<system>` /
  `mvm-builder-vm-dev-<system>` — both share the `mvm-builder-vm-` prefix.

## Change

Replace the single overwritten root with a **two-root scheme keyed by build kind**,
classified at runtime from `$NIX_OUT`'s derivation name (platform-independent):

```sh
# Per-kind warm root so alternating builder-vm-image (dev up / stage0) and
# workload (machine run) builds don't evict each other. Bounded to 2 roots so the
# cap GC still works. Builder image name set in nix/images/builder-vm/flake.nix.
case "$(basename "$NIX_OUT")" in
  *-mvm-builder-vm-*) warm=builder ;;
  *)                  warm=workload ;;
esac
mkdir -p /nix/var/nix/gcroots 2>/dev/null || true
nix-store --add-root "/nix/var/nix/gcroots/mvm-warm-$warm" --indirect -r "$NIX_OUT" >/dev/null 2>&1 \
  || ln -sfn "$NIX_OUT" "/nix/var/nix/gcroots/mvm-warm-$warm" 2>/dev/null || true
# Retire the pre-fix single root so it stops protecting a stale closure.
rm -f /nix/var/nix/gcroots/mvm-warm-latest 2>/dev/null || true
```

~8 lines of shell replacing the current 3-line pin block.

### Why this shape

- **Bounded (2 roots)** → the cap-triggered GC still functions and the store stays
  bounded (avoids the unbounded per-closure failure mode where nothing is ever
  unrooted and GC frees nothing).
- **`dev up` (builder) and `machine run` (workload) no longer evict each other** —
  exactly the reported ping-pong. Within a kind, latest-wins is correct: an
  unchanged derivation is a store hit next build; a changed one supersedes.
- **Runtime derivation-name classification** is platform-independent and needs **no
  wire-protocol or host-API changes** — `BuilderJob::Flake` (a multi-callsite
  protocol type) is left untouched; the classification happens entirely inside the
  generated script from a value it already computes.

### Rejected alternatives

- **Output-shape kind (`[ -f "$NIX_OUT" ]`)** — platform-dependent; mis-buckets
  Linux/Firecracker workloads (directory output) as "builder".
- **Per-identity roots keyed by `FLAKE_REF#ATTR_PATH`, LRU-capped** — robust but
  needs new LRU eviction to stay bounded. Disproportionate: there are effectively
  two closure-families to keep warm, so two roots is exactly right (YAGNI).
- **Explicit `kind` field on `BuilderJob::Flake`** — cleaner typed signal, but that
  type is a host↔guest wire protocol with ~10 callsites + a guest-side parser;
  disproportionate blast radius for this fix.

## Error handling & migration

Unchanged: the pin is **best-effort** (`|| true`) and never fails a build — a
warm-root failure only costs a future recompile, it is not a correctness gate. The
`rm -f` of the retired `mvm-warm-latest` is best-effort cleanup; no migration step —
new builds create `mvm-warm-builder` / `mvm-warm-workload`.

## Testing

`render_flake_cmd_sh` already has script-content unit tests
(`builder_vm_runtime.rs:2004`, `:2044`). Follow that pattern:

- Update/add one script-content test asserting the generated script pins **both**
  `mvm-warm-builder` and `mvm-warm-workload` via the per-kind `case`, no longer
  writes `mvm-warm-latest` except the `rm -f` cleanup, and matches on the
  `*-mvm-builder-vm-*` derivation-name prefix.
- Update any existing test that asserts the literal `mvm-warm-latest` pin name.

A comment in the script ties the `mvm-builder-vm-` match to
`nix/images/builder-vm/flake.nix` so a future rename is caught in review.

## Gates

`cargo fmt --all --check`, `cargo clippy --workspace --all-targets -D warnings`,
`cargo nextest run -p mvm-build`, `cargo test -p mvm-build --doc`. No live builder-VM
boot is required to land this (script-generation + content tests only). A live
confirmation (alternating `dev up` / `machine run` without a cold recompile) is an
environment-gated follow-up.
