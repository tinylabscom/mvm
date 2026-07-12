# SP3 — Seed the dev-shell Nix closure into the builder pack

**Status:** design finalized 2026-07-11 (decisions confirmed with owner)
**Relation:** Plan 213 SP3 (instant first-use). Builds on SP1 (versioned pack cache), SP2 (install-time prefetch), SP4 (benchmark). Umbrella design: `specs/notes/instant-first-use-pack-design.md`.

## Motivating measurement (SP4 bench, Hetzner qemu builder, 2 runs — directional)

Building a *trivial* fixture in the builder VM took **~153 s (p50)**. A trivial build isn't 153 s of compilation — that time is **Nix evaluation + closure fetch/realise** of the nixpkgs/toolchain closure. Seeding that closure into the builder's Nix store ahead of time removes the fetch/eval, dropping the build toward near-instant. The mechanism is validated with a large, clear win; the finding is backend-agnostic (closure cost, not VMM cost) and only grows for heavier real builds.

## Decisions (confirmed)

1. **Content — the dev-shell toolchain closure.** Seed the transitive closure (`nix-store -qR` of the dev-shell derivation) of the toolchain the builder exists to provide: cargo/rustc + uv + pnpm + the nixpkgs base that `dev up` / common builds pull. That closure is exactly what the ~153 s was spent fetching.
2. **Size — content-defined, no hard cap.** The seed is whatever that closure is (~1 GB, cargo/rustc-dominated). It's paid once at prepare/install time (off the hot path — SP2), justified by ~150 s saved per build. Guard against accidental bloat with a **release-pipeline soft alarm** (fail the pack build if the seeded closure exceeds a generous threshold, e.g. 2 GB uncompressed). Revisit a core/extended split only if prepare-time cost becomes painful (SP4 measures it).
3. **Parity — hvf-first (day-one), then libkrun, then Linux/qemu.** Dev is Mac-first (macOS 26+ Apple Silicon → hvf is the default builder), so the hvf builder's closure-attach path lands first and is live-tested on this Mac. The import *mechanism* is identical across backends; only the host-side "attach the closure NAR to the builder VM" wiring is per-backend.

## Invariant

The seeded closure is a **builder-pack artifact imported only into the builder VM's persistent Nix store**. It is never included in, copied to, or reachable from a workload microVM rootfs (already CI-enforced by `xtask check-guest-images-no-builder-tools`). Workload VMs stay minimal.

## Mechanism

- **Producer:** a NAR export of the toolchain closure (`nix-store --export $(nix-store -qR <toolchain>)`) becomes a builder-pack file; wire the already-present-but-unused `PackOutputs.closure_hash`; it rides the pack's existing per-file hash + signature machinery.
- **Consumer (guest):** at the first-boot seed step in `mvm-host-vm-init` (right after the existing `seed_nix_store`/`load_seeded_nix_db`), if a closure NAR is present and its content hash hasn't been imported, `nix-store --import` it, then stamp a **content-keyed idempotency marker** (so a changed closure re-imports; an unchanged one is skipped). **Fail-open** — an import failure logs and continues (an accelerator, never a hard dependency).
- **Host wiring (per-backend):** attach the resolved pack's closure NAR to the builder VM as a read-only share, hvf first.
- **Timing:** imported at prepare time (SP2's `bootstrap` path), captured into the warm builder snapshot when that lands — so first real use restores an already-seeded builder.

## Decomposition (sub-PRs, in order)

- **S3.1 — Schema + producer (offline, PR-safe).** `--closure <nar>` on `mvm-builder-pack-tool`; `BuildBuilderPackParams.closure: Option<PathBuf>`; copy+hash into the pack + set `closure_hash`; keep it optional in `validate_required_outputs` (older/opt-out packs stay valid). Unit-tested. No VM.
- **S3.2 — Guest import + idempotency (fail-open).** In `mvm-host-vm-init`: `nix-store --import` of the closure NAR + a content-keyed marker, after the existing seed step. Unit-test the marker/decision logic; the import itself is exercised live.
- **S3.3 — HVF host wiring (day-one target).** Attach the closure NAR share to the hvf builder VM; resolve it from the verified pack. Live-testable on this Mac.
- **S3.4 — Release-pipeline closure production.** Add a step to `release.yml`'s builder-pack job that exports the dev-shell toolchain closure deterministically, passes `--closure`, and soft-alarms on size (>2 GB). This is where the "content = dev-shell toolchain" decision is encoded.
- **S3.5 (follow) — libkrun + Linux/qemu host wiring.** The same attach for the other builders.

## Sequencing & validation

S3.1 → S3.2 → S3.3 gets a live hvf end-to-end on this Mac (build the pack with a small closure, prepare, boot the hvf builder, confirm the seeded closure is imported and a build that would have fetched it is now fast). S3.4 wires the real dev-shell closure into releases. S3.5 extends parity. Re-run the SP4 bench (`ops bench first-use`) before/after to quantify the win against the ~153 s baseline.

## Live validation (2026-07-11, Linux/qemu builder)

The full chain was booted end-to-end on a real qemu builder VM with a
102 MB, 61-path test closure staged at `nix-closure.nar`:

- Host resolved the NAR, staged it into its own read-only share dir, and
  attached it to the VM as the `closure-seed` virtio-fs share.
- Guest mounted `/closure-seed`, and `mvm-host-vm-init` imported the NAR:
  `importing seeded closure /closure-seed/nix-closure.nar (<hash>)`, no
  fail-open warning.
- The content-keyed marker `/nix-store/.seed-closure-imported` was stamped
  with the closure hash (so an unchanged closure is a no-op next boot), and
  the closure's store paths (glibc, bash, …) are present in the persistent
  Nix store.

Two bugs the unit tests missed were caught by the live boot and fixed:

1. **Import ran before the mount.** The import call sat inside
   `setup_nix_store` (Track A), which completes before the virtio-fs join /
   disk-transport staging that mounts `/closure-seed` — so it read an
   unmounted path and silently imported nothing. Moved to after both mount
   paths.
2. **Mount point not baked.** The builder rootfs boots read-only, so the
   guest can't `mkdir /closure-seed` at runtime (`create /closure-seed:
   Read-only file system`). It's now pre-created in `mkGuest` alongside
   `/work`, `/out`, `/job`, `/mvm-bins`.

**hvf (disk-transport) parity** shares the same guest import + baked mount
point; its host-side attach (NAR as a tar entry on the input disk) is
unit-tested but not yet live-booted — the dev Mac's Stage 0 store is
degraded (corrupt store + `/homeless-shelter` purity), which fails the
builder base-image rebuild before the hvf builder boots. Live hvf boot is
pending a clean macOS Stage 0 environment.

## Deferred / not here

- Warm-builder-snapshot capture (adjacent warm-start work) — SP3 leaves the seam; capturing the seeded store into a snapshot is separate.
- A core/extended closure split — only if SP4 shows prepare-time cost is painful.
- Live hvf disk-transport boot (blocked on the dev Mac's Stage 0 rot; the mechanism is unit-tested and shares the validated guest path).
