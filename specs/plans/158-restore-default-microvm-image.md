# Plan 158 — Restore the bundled default microVM image

**Status:** proposed
**Owner:** unassigned
**Related:** ADR-002 (claims 3 + 8), ADR-051 (runtime overlay), Plan 115 / ADR-064 (image consolidation), Plan 74 W1.4b (overlay-aware sidecar). Supersedes the "default-microvm image gap" note.

## Goal

Restore the bundled **default microVM image** so that `mvmctl up` / `mvmctl run` /
`mvmctl exec` with **no** `--flake` / `--template` / `--image` boots a real,
admittable image. The standalone flake (`nix/images/default-tenant`) was removed
in the Plan 115 consolidation; the host still tries to download + boot it.

**Dual image, keyed on `BuildMode` (decided 2026-06-04).** The flake produces
**two** variants, matching mvm's existing dev/prod tiers (`mvm_build::pipeline::
BuildMode`, `--dev`/`--prod`, default `--prod` — `up.rs:781`):

| Variant | `mkGuest` form | Tier | Verity | `exec`/console | Distribution |
|---|---|---|---|---|---|
| **dev** | `entrypoint.shell` (`isDev`) | dev | no (ADR-002 dev-VM exemption) | **yes** (agent ships `do_exec`, entrypoint uid 0) | built **locally** in dev mode; not shipped |
| **prod** | `entrypoint.command` (sealed) | prod | **yes** (rootfs.verity + roothash) | no | **shipped** as the `default-microvm-*` release assets |

Rationale: a single image can't be both interactive *and* sealed (sealed refuses
`exec`/console by design). The dev variant is the interactive scratch default; the
prod variant is the hardened image that ships for hosting. This is the documented
dev/prod split, not a new posture.

**Security posture (verified against `mk-guest.nix` + ADR-002).** The microVM
isolation boundary (hypervisor, seccomp-jailed VMM, no host-fs beyond shares,
default-deny egress, proxy 0700 + port allowlist) holds identically for **both**
variants — the host is protected either way. The **dev** variant relaxes
*in-guest* defense-in-depth only: entrypoint uid 0 (`defaultEntrypointUid = if
isDev then 0 else 1000`), `do_exec` compiled in (`withDevShell = isDev`), no
rootfs verity — exactly the dev tier ADR-002 §"Verified boot is mandatory for
production microVMs" explicitly exempts. **Untrusted/production workloads must run
in the prod variant (or a sealed user flake), never the dev default.**

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

**D1 — A new `nix/images/default-tenant/` flake with TWO `mkGuest` variants.**
Author fresh against the current API (the historical `nix/default-microvm/flake.nix`
at `20a789d7` is stale — input `../guest-lib`→`../lib`, no explicit entrypoint).
- `packages.<sys>.dev` — `mkGuest { entrypoint.shell = "/bin/sh"; … }` →
  accessible, `do_exec`, uid 0. Built locally in dev mode; **not** verity-sealed.
- `packages.<sys>.default` (= prod) — `mkGuest { entrypoint.command = [ … minimal
  idle … ]; … }` → sealed, rootless uid 1000, no `do_exec`; **verity-sealed**
  (D2). This is what ships.
Both use the **workload kernel** (`builder-vm`'s `workload-kernel` attr, which
enables `MD BLK_DEV_DM DM_VERITY` — `nix/images/builder-vm/flake.nix:480, 506`)
and both emit the overlay-aware `mvm-meta.json` (D3) so admission passes.

**D2 — Verity (prod variant only): seal inside the Nix build.** Reuse
runtime-overlay's exact `veritysetup format` recipe (pinned cryptsetup 2.8.6,
data-block 1024, hash-block 4096, zero salt, sha256 — `runtime-overlay/flake.nix:
180-203, 288-312`) over the prod variant's `rootfs.ext4`, emitting `rootfs.verity`
+ `rootfs.roothash`. The dev variant is not sealed (ADR-002 dev-VM exemption). The
backend probes these siblings + builds the `mvm.roothash=` cmdline host-side
(`microvm.rs:1589-1632`), so the flake only emits artifacts — no baked cmdline.

**D3 — Sidecar: emit `mvm-meta.json` via `builtins.toJSON` from `passthru.mvm`.**
The `GuestSidecar` struct (`crates/mvm-base/src/runtime_meta.rs`, written by
`GuestSidecar::write_to_dir` / `SIDECAR_FILENAME`; mirror at `builder_vm.rs:207-245`)
is `#[serde(rename_all="camelCase")]` with fields `name, accessible, sealed,
entrypointKind, initSystem, expectedBootMs, agentBinary, rootlessEntrypoint,
hypervisor, overlayAware`. mkGuest's `passthru.mvm` carries all of these, so the
flake emits the file with `builtins.toJSON` of an attrset using those exact
camelCase keys — no hand-formatting, guaranteed to parse. Both variants set
`overlayAware = true`; dev sets `sealed=false/accessible=true`, prod the inverse.

**D4 — Resolution keyed on `BuildMode`; only prod ships.**
`ensure_default_microvm_image()` (`apple_container.rs:3815`) takes the resolved
`BuildMode`:
- **Prod** → download the shipped `default-microvm-*` assets (now incl.
  `rootfs.verity`, `rootfs.roothash`, `mvm-meta.json`) into
  `~/.cache/mvm/default-microvm/prod/`, SHA-256-verified.
- **Dev** → build the `dev` variant **locally** from the in-repo flake (source
  checkout) — dev images are never published (matches the
  source-checkout-builds-locally invariant); cache at `…/default-microvm/dev/`.
Callers (`up.rs:1543`, `exec.rs`, `bench_probe.rs`) pass the mode they already
resolve (`BuildMode`, default Prod — `up.rs:781`).

**D5 — Leave the security.yml lanes on the runtime overlay (Plan-568 state).**
Once the prod variant exists, `verified-boot-artifacts` *could* witness it too,
but the overlay already exercises the identical seal; out of scope here.

## Workstreams

### Task 1 — Author `nix/images/default-tenant/flake.nix` (two variants)
- [ ] `packages.<sys>.dev` = `mkGuest { name = "mvm-default-microvm-dev";
      entrypoint.shell = "/bin/sh"; packages = [ pkgs.busybox ]; kernel = <workload>; }`
      → assemble `$out/{vmlinux, rootfs.ext4, mvm-meta.json}` (no verity).
- [ ] `packages.<sys>.default` (prod) = `mkGuest { name = "mvm-default-microvm";
      entrypoint.command = [ "/bin/sleep" "infinity" ]; packages = [ pkgs.busybox ];
      kernel = <workload>; }` → assemble `$out/{vmlinux, rootfs.ext4, rootfs.verity,
      rootfs.roothash, mvm-meta.json}`, sealing the rootfs with the runtime-overlay
      `veritysetup format` recipe (D2).
- [ ] Source the **workload kernel** (`workload-kernel` attr — `builder-vm/flake.nix:
      480-506`): either add `builder-vm` as a flake input and use its output, or
      replicate `mkWorkloadKernel` (`extraEnables = ["MD" "BLK_DEV_DM" "DM_VERITY"]`).
      Decide during impl; prefer the flake-input form to avoid recipe drift.
- [ ] `mvm-meta.json` via `builtins.toJSON` of `passthru.mvm` (D3).
- [ ] **`flake.lock` must be generated in a nix env** (cannot be produced on a
      macOS host) — seed from a sibling flake's lock if inputs match, else
      `nix flake lock` in CI/Linux.
- [ ] Eval smoke test under `nix/tests/` (mirror `nix/tests/mk-guest-eval.nix`):
      both variants evaluate; dev sidecar `sealed:false`, prod `sealed:true`, both
      `overlayAware:true`.
- [ ] **Cannot be built/locked on a macOS dev host** — validated by CI (the
      `Nix flake check (Linux eval)` lane + the release/security `nix build` lanes).

### Task 2 — Re-add the `default-microvm` release job (PROD variant only)
- [ ] In `.github/workflows/release.yml`, re-add a `default-microvm` matrix job
      (aarch64 + x86_64) that `nix build ./nix/images/default-tenant#…default`
      (the **prod** variant) and uploads `default-microvm-{vmlinux,rootfs.ext4,
      rootfs.verity,rootfs.roothash,mvm-meta.json}-<arch>` +
      `default-microvm-<arch>-checksums-sha256.txt`. The dev variant is **not**
      shipped.
- [ ] Add `default-microvm` back to the `release` job `needs:` + the nullglob
      asset list (the slots PR #567 removed). Best-effort under the #566
      `if: !cancelled() && needs.build.result=='success'` gate.

### Task 3 — Make `ensure_default_microvm_image` `BuildMode`-aware
- [ ] In `crates/mvm-cli/src/commands/env/apple_container.rs:3815`, take the
      resolved `BuildMode`. **Prod:** `download_default_microvm_image` fetches the
      five prod assets into `…/default-microvm/prod/`, extending SHA-256
      verification to all five. **Dev:** build the `dev` variant locally from the
      in-repo flake into `…/default-microvm/dev/` (no download).
- [ ] Thread the mode from callers (`up.rs:1543`, `exec.rs`, `bench_probe.rs`).
- [ ] Confirm the prod dir layout satisfies the backend verity probe
      (`microvm.rs:1589`) and `admit_overlay_aware` (`builder_vm.rs:850`).

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
