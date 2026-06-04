# Plan 158 — Restore the bundled default microVM image

**Status:** proposed
**Owner:** unassigned
**Related:** ADR-002 (claims 3 + 8), ADR-051 (runtime overlay), Plan 115 / ADR-064 (image consolidation), Plan 74 W1.4b (overlay-aware sidecar). Supersedes the "default-microvm image gap" note.

## Goal

Restore the bundled **default production microVM image** so that `mvmctl up` / `mvmctl run` / `mvmctl exec` with **no** `--flake` / `--template` / `--image` boots a real, admittable, verity-sealed image — and so claim 3's CI witness has a representative bundled prod image again. The standalone image flake (`nix/images/default-tenant`) was removed during the Plan 115 image consolidation; the host still tries to download + boot it.

## Why it's currently broken (grounded findings)

1. **The host expects a download-only image that doesn't exist.**
   `ensure_default_microvm_image()` (`crates/mvm-cli/src/commands/env/apple_container.rs:3815`)
   checks `~/.cache/mvm/default-microvm/{vmlinux,rootfs.ext4}`, else calls
   `download_default_microvm_image()` (`:3832`), which fetches release assets
   `default-microvm-vmlinux-<arch>` + `default-microvm-rootfs-<arch>.ext4`
   (`:3843-3844`) + the per-arch checksums. Called from `up.rs:1543`, `exec.rs`,
   `ops/bench_probe.rs`. The release job that produced those assets was removed
   in PR #567 (it built the nonexistent `nix/images/default-tenant`).

2. **Even with bytes, it can't pass admission.**
   `admit_overlay_aware()` (`crates/mvm-build/src/builder_vm.rs:850`) refuses any
   rootfs that lacks an `mvm-meta.json` sidecar (`:853-860`) or whose sidecar has
   `overlay_aware: false` (`:861-869`, field at `:243-244`). The download-only
   default image ships **no sidecar** and **no `/mvm/runtime` mount point**, so
   the runtime overlay can't attach and admission refuses it. Boot-path callers:
   `mvm-backend/src/{apple_container.rs:103, backend.rs:137, libkrun.rs:197,
   vz.rs:210, cloud_hypervisor.rs:135}`.

3. **It isn't verity-sealed (claim 3).**
   The backend probes `{parent}/rootfs.verity` + `rootfs.roothash` siblings
   (`crates/mvm-backend/src/microvm.rs:1589-1611`), wires them as `/dev/vda`(ro)
   + `/dev/vdb` and puts `mvm.roothash=` on the cmdline (`:1620-1632, 1801-1850`).
   The default image ships neither sidecar.

## Architecture facts the plan builds on

- **`mkGuest`** (`nix/lib/mk-guest.nix:71-113`) produces a single ext4 (`$out`,
  `:901-960`) and **does not** emit verity sidecars. An `entrypoint.command` /
  `entrypoint.services` form makes the image **sealed/prod** (`isDev=false`,
  `:116-119`): rootless entrypoint uid 1000, `do_exec` stripped from the agent
  (`:140-143`), `/etc/mvm/variant="prod"`. Modern mkGuest is overlay-aware and
  exposes `passthru.mvm` metadata incl. `overlayAware` (`:944-960`).
- **Nix-emitted verity is a proven pattern**: `nix/images/runtime-overlay/flake.nix`
  runs `veritysetup format` **inside the derivation** with pinned cryptsetup +
  deterministic flags (block sizes, zero salt, `SOURCE_DATE_EPOCH=0`, fixed UUID
  `…beef`) and emits `overlay.{ext4,verity,roothash}` (`:167-185, 288-312`). The
  data-block size (1024) must match `mvm-verity-init` constants.
- **`seal_with_verity`** (`crates/mvm-build/src/oci_to_rootfs/verity.rs:119-182`)
  is currently **test-only** (callers only in `crates/mvm-build/tests/
  oci_verity_sealing.rs`); the OCI-pull CLI path does not call it. So there is no
  host-side seal step to reuse for a flake build today.
- **Sealed-prod `.mvm` packing** (`crates/mvm-build/src/packed_artifact.rs:9-14,
  212-216, 350-359`) *requires* `rootfs.verity` + `roothash`; nothing auto-generates
  them for flake builds.

## Design decisions (recommendations)

**D1 — Image build: a new `nix/images/default-tenant/` flake calling current
`mkGuest`.** Recommended. The historical flake (`nix/default-microvm/flake.nix`
at commit `20a789d7`) is stale (input path `../guest-lib` → `../lib`, no explicit
`entrypoint`). Author fresh against the current API rather than resurrect.
Entrypoint: a minimal **sealed/prod** default — `entrypoint.command` running a
busybox shell-less idle/echo so the image is sealed (uid 1000, no `do_exec`).
This both fixes admission (mkGuest bakes `/mvm/runtime` + emits the overlay-aware
sidecar metadata) and gives claim 3 a representative prod image.

**D2 — Verity: Option (a), seal inside the Nix build.** Recommended over the
host-side `seal_with_verity` (test-only, breaks Nix purity, Linux-only) and over
"overlay-only, don't seal the rootfs" (fails sealed-prod / claim 3). Emit
`rootfs.verity` + `rootfs.roothash` from the flake by reusing runtime-overlay's
exact `veritysetup format` recipe (same pinned cryptsetup, block sizes, salt,
determinism). This keeps verity in the Nix dep graph and matches the shipped
overlay pattern.

**D3 — Sidecar: emit `mvm-meta.json` next to the rootfs from `passthru.mvm`.**
The flake (or the release job) writes the `GuestSidecar` JSON
(`overlay_aware: true`, name, sealed, init_system, agent_binary, …) so
`admit_overlay_aware` passes. Confirm the exact serialization shape against
`GuestSidecar` (`crates/mvm-build/src/builder_vm.rs:207-245`) and reuse the same
writer the normal build pipeline uses if one exists (W6.2 emit site — locate
during Task 1).

**D4 — Keep the download contract, extend the asset set.** Keep
`~/.cache/mvm/default-microvm/` + the `default-microvm-*` asset names; add the
new siblings (`rootfs.verity`, `rootfs.roothash`, `mvm-meta.json`) so the backend
verity probe + admit gate are satisfied from a pure download.

**D5 — Leave the security.yml lanes on the runtime overlay (Plan-568 state).**
Once this image exists, the `verified-boot-artifacts` lane *could* point back at
it, but the overlay witness already exercises the identical seal; revisit only if
we want the bundled-image rootfs specifically witnessed. Out of scope here.

## Workstreams

### Task 1 — Author `nix/images/default-tenant/flake.nix`
- [ ] Locate the W6.2 `mvm-meta.json` emit site (grep `GuestSidecar` writer /
      `mvm-meta.json` in `crates/mvm-build`) and the runtime-overlay verity
      recipe (`nix/images/runtime-overlay/flake.nix:288-312`).
- [ ] Write the flake: `mkGuest { name = "mvm-default-microvm"; entrypoint.command
      = [ … minimal sealed idle … ]; packages = [ pkgs.busybox ]; }`, then a
      `veritysetup format` derivation phase (mirroring runtime-overlay) producing
      `$out/{vmlinux, rootfs.ext4, rootfs.verity, rootfs.roothash, mvm-meta.json}`.
      `mvm-meta.json` serialized from `passthru.mvm` with `overlay_aware = true`.
- [ ] `nix flake lock` committed (`flake.lock`).
- [ ] Add an eval smoke test under `nix/tests/` (mirror `nix/tests/mk-guest-eval.nix`)
      asserting the package evaluates and the sidecar carries `overlay_aware: true`.
- [ ] **Cannot be built on a macOS dev host** — validated by CI (the
      `Nix flake check (Linux eval)` lane + the release/security `nix build` lanes).

### Task 2 — Re-add the `default-microvm` release job
- [ ] In `.github/workflows/release.yml`, re-add a `default-microvm` matrix job
      (aarch64 + x86_64) that `nix build ./nix/images/default-tenant#…default`
      and uploads `default-microvm-{vmlinux,rootfs.ext4,rootfs.verity,
      rootfs.roothash,mvm-meta.json}-<arch>` + `default-microvm-<arch>-checksums-sha256.txt`.
- [ ] Add `default-microvm` back to the `release` job `needs:` and the nullglob
      asset list (the slots PR #567 removed). It stays best-effort under the
      #566 `if: !cancelled() && needs.build.result == 'success'` gate — an
      image failure still won't block the binary download.

### Task 3 — Extend `download_default_microvm_image`
- [ ] In `crates/mvm-cli/src/commands/env/apple_container.rs:3832`, fetch the new
      siblings (`rootfs.verity`, `rootfs.roothash`, `mvm-meta.json`) into
      `~/.cache/mvm/default-microvm/` alongside `vmlinux` + `rootfs.ext4`, and
      extend SHA-256 verification to cover them (same checksums manifest).
- [ ] `ensure_default_microvm_image()` (`:3815`) returns the dir; confirm the
      backend's verity probe (`microvm.rs:1589`) and `admit_overlay_aware`
      (`builder_vm.rs:850`) both resolve their files from that dir layout.

### Task 4 — Tests
- [ ] Rust unit test: `download_default_microvm_image` places all five files +
      rejects a tampered `rootfs.verity` (mirror the `install_sh` / kernel
      download tamper tests; use the `MVM_UPDATE_DOWNLOAD_URL` override pattern).
- [ ] Rust test: a default-image dir with the emitted `mvm-meta.json` passes
      `admit_overlay_aware` (and a sidecar-less dir is refused) — pins D3.
- [ ] CI: the new flake builds in the release + security `nix build` lanes.

### Task 5 — Docs + memory
- [ ] Update the install/reference docs that mention the default image; remove
      the "default image can't boot the admitted path" caveat once Tasks 1-4 land.
- [ ] Note the restored image in ADR-051 / ADR-002 image inventory if applicable.

## Risks / open questions

- **Local un-validatability:** the flake's `nix build` cannot run on a macOS dev
  host; every build assertion here is CI-gated. Treat the first CI run as the
  real validation loop.
- **Sidecar writer reuse (D3):** if no reusable `mvm-meta.json` writer exists for
  the Nix path, Task 1 must serialize `GuestSidecar` by hand — keep it byte-for-byte
  compatible with `GuestSidecar::read_from_dir` (`builder_vm.rs:207-245`).
- **Verity determinism:** the data-block size + cryptsetup pin **must** match
  `mvm-verity-init` and runtime-overlay exactly, or the guest fails to assemble
  the dm-verity device at boot. Copy the recipe verbatim; don't re-derive.
- **Claim 8 (admitted ExecutionPlan):** this plan makes the image *bootable +
  overlay-admittable + verity-sealed*. Whether the no-flake path also synthesizes
  a signed `ExecutionPlan` for it is a separate concern (claim 8) — verify the
  `up`/`exec` no-flake path already does, or scope it as a follow-up.

## Success criteria

- [ ] `mvmctl up` with no flake/template/image downloads + boots the default image
      through the normal admitted path (overlay attached, dm-verity active) on a
      Linux/KVM host.
- [ ] A tagged release publishes the five `default-microvm-*` assets + checksums.
- [ ] CI builds the flake; the download + admit tests pass; existing gates stay green.
