# W8 Wave 0 — in-tree image producer deletion inventory

Backing: preview
Validation: check-doc-links

Issue #3366. Execution plan: `specs/plans/2026-09-24-image-cutover-and-deletion.md`.
Re-scanned from `origin/main` at `9ebb81b459` on 2026-09-24. Line numbers
drift; each wave revalidates its rows against `main` before it lands.

Classes: **D** delete with the wave · **K** keep · **E** edit text, a fixture
or a path · **R** re-point: no literal path, but the code depends on the
in-tree flakes through a helper and must be rewired.

## What `nix/images/` contains (17 files)

- `builder-vm/`: `flake.nix`, `flake.lock`
- `default-tenant/`: `flake.nix`, `flake.lock`
- `initramfs/`: `flake.nix`, `flake.lock`
- `runtime-overlay/`: `flake.nix`, `flake.lock`
- `kernel/`: `flake.nix`, `flake.lock`, `base.nix`, `builder.nix`, `workload.nix`, `workload-k8s.nix`, `README.md`
- `examples/llm-agent/default.nix`
- `version.nix` (`"0.18.0-rc.2"`)

Literal `nix/images` references outside `specs/` and the tree itself: **80
files**. `specs/` holds 40 more files (77 lines) and stays as history. The
repository-root `flake.nix` exposes no image outputs.

## Wave 1 — `mvm-build`

| file | line(s) | class | reason |
|---|---|---|---|
| crates/mvm-build/src/image_source.rs | 62-64 | D | `IN_TREE_IMAGE_MARKER = "nix/images/builder-vm/flake.nix"` |
| 〃 | 158-161, 173 | D | `ImageSource::InTree { root }` variant and its `tier()` arm |
| 〃 | 253-276 | D/K | `resolve_image_source` / `select_image_source`: drop the `in_tree` parameter and arm; keep configured → `LocalCheckout` and `Released` |
| 〃 | 279-284 | D | `in_tree_images()` |
| 〃 | 394-402 | K/E | `mvm_source_checkout_at` keys on `Cargo.toml`, not the flakes; comment at 397 edits |
| 〃 | 405-464 | K/D | keep `resolve_current_source` / `select_with_discovery` (`MVM_IMAGES_DIR`, then sibling `../mvm-images`); delete the in-tree fallback (459-461) and its warning text (454) |
| 〃 | 474-498 | D | `in_tree_overlay_checkout_root()`, `MVM_RUNTIME_OVERLAY_SOURCE_ROOT`, `in_tree_overlay_at()` — called from mvm-build, mvm-client and mvm-cli |
| crates/mvm-build/src/image_source/tests.rs | 132-155, 468-518 | D | in-tree window tests |
| 〃 | 325-328 | K | negative fixture: an mvm checkout is not an images checkout |
| crates/mvm-build/src/builder_vm_image.rs | 57-66 / 91 | D / E | `builder_vm_source_checkout_root()` probes the in-tree flake / error text |
| crates/mvm-build/src/builder_vm_bootstrap.rs | 28, 193, 253, 643, 677 | R | source-checkout re-exec gated on `builder_vm_source_checkout_root` |
| crates/mvm-build/src/runtime_overlay.rs | 11, 423, 434 | E | docs |
| 〃 | 466-474, 607-609 | D | `flake_path()` and `runtime_overlay_source_checkout_root()` hard-code the in-tree flake |
| 〃 | 1199-1210, 1290, 1306, 1346 | D | tests asserting the in-tree flake path |
| crates/mvm-build/tests/runtime_overlay_build.rs | whole file | D | Linux `nix build` of the in-tree overlay |
| crates/mvm-build/src/libkrun_builder.rs | 2083 / 4024-4029 / 4958-4971 / 6263 | E / K / D / R | comment / arbitrary fixture string / in-tree flake tests / workspace via `builder_vm_source_checkout_root` |
| crates/mvm-build/src/bin/stage0-init.rs | 1070-1076 | D | default in-guest flake `path:/work/nix/images/builder-vm#packages` |
| crates/mvm-build/src/{initramfs,stage0,stage0_kernel,builder_vm_runtime}.rs | 9 / 7 / 39 / 601 | E | comments |
| crates/mvm-build/src/bin/{mvm-builderd,mvm-egress-proxy,mvm-host-vm-init}.rs, `mvm-host-vm-init/{proxy,workload}.rs` | various | E | docs and error text |
| crates/mvm-build/examples/builderd-buildimage.rs | 8 | E | doc path |
| crates/mvm-build/src/pipeline/dev_build.rs, image_source/build.rs | 491, 578 | E | comments |

## Wave 2 — `mvm-cli` (compile-coupled to Wave 1)

| file | line(s) | class | reason |
|---|---|---|---|
| crates/mvm-cli/src/commands/env/builder_vm.rs | 277-304 | D/R | `find_builder_vm_flake()` / `…_is_source_checkout()` — the CLI's source-checkout signal is the in-tree flake; re-point to `mvm_source_checkout` |
| 〃 | 96-111, 243-258 | R / D | `images_built_from_source()` (keep the LocalCheckout half) / in-tree source fingerprint |
| crates/mvm-cli/src/commands/env/builder_vm/bootstrap.rs | 176-179 | D | `ImageSource::Released \| ImageSource::InTree { .. } => None` |
| 〃 | 244-300 | D | tool-builder Stage 0 build from the in-tree flake; re-point to published fetch |
| 〃 | 286, 539-558 | E | stale comment, error texts |
| 〃 | 663-666, 1083-1090 | R / D | pack path gated on the flake probe / workspace root derived from the flake |
| crates/mvm-cli/src/commands/env/builder_vm/builder_vm_bootstrap_tests.rs | 124-135, 169-210, 294, 343, 902-1275 | D | in-repo flake and fingerprint tests |
| crates/mvm-cli/src/commands/env/builder_vm/stage0_cache.rs | 389, 442-540 | D | `builder_vm_source_fingerprint`, `BUILDER_FLAKE_NIX_INPUTS`, `workspace_root_for_builder_flake` |
| crates/mvm-cli/src/commands/env/builder_vm/default_microvm.rs | 65 / 432-438 / 590-611 | R / D / D | kernel source signal / dev variant builds in-tree / `path:/work/nix/images/default-tenant` |
| crates/mvm-cli/src/commands/env/builder_vm/kernel.rs | 5, 10, 73 / 152-199 / 675-756 | E / D / D | docs / in-repo kernel flake source incl. `workload-k8s` and the `InTree` arm / tests constructing `InTree` |
| crates/mvm-cli/src/commands/env/builder_vm/sdk_sidecar.rs | 192, 260-285 | D | builder script `nix build 'path:/work?dir=nix/images/builder-vm#…'` and its test |
| crates/mvm-cli/src/commands/build/{runtime_overlay,sdk_sidecar}.rs | 110-121 / 84-94 | D | `--source build` in-tree arms; keep the pair arms |
| crates/mvm-cli/src/commands/build/{kernel,fc_builder_image,persistent_builder}.rs | 4 / 5 / 513 | E | docs; 513 is already stale |
| crates/mvm-cli/src/commands/build/kernel.rs | 192 | K | cites the budget gate |
| crates/mvm-cli/src/commands/vm/exec.rs | 34 | E | `--manifest` help text |
| crates/mvm-cli/src/doctor/image_source.rs | 113-121, 158-168 | D | doctor `InTree` arm and its test |
| crates/mvm-cli/src/update.rs | 153-154 | E | doc |
| crates/mvm-cli/tests/agent_workload_example.rs | 94-116 | R | reads `nix/images/examples/llm-agent/default.nix` (moves in Wave 4) |
| crates/mvm-cli/src/{commands/vm/up/kernel.rs, doctor/builder.rs, commands/image/boot/update.rs, commands/mod.rs, commands/env/builder_vm/bootstrap_tests.rs} | 158 / 396-401 / 61 / 621 / 220 | R | source-checkout signal and fingerprint consumers |

## Wave 3 — workflows (8 files)

| file | line(s) | class | reason |
|---|---|---|---|
| cache-warm.yml | 97-102 | D | warms in-tree runtime-overlay and default-tenant; keep the `./nix#checks` leg |
| ci.yml | 137-141 | E | `scope.kernel` path regex |
| 〃 | 1276-1347 (`kernel`) | D/R | `scripts/build-kernel-artifacts.sh` builds from `nix/images/builder-vm` |
| 〃 | 1557-1640 | D/R | overlay static-musl, glibc-free and 50 MB footprint steps build in-tree; re-point at the mvm-images checkout as `guest-image-boot` does |
| 〃 | 1536-1544, `boot-latency`, `guest-image-boot` | K | eval loop shrinks by itself; boot witnesses consume mvm-images |
| ci-full.yml | 296-406 / 779-795 / 184-281 | D / E-R / D-R | `builder-vm-image-linux` / `no-kvm-bootstrap` hide-and-compile / `source-bootstrap-linux` cold Stage 0 |
| kernel-cve-watch.yml | 22 | E | `paths: nix/images/kernel/**` |
| kernel-build.yml | 63 | D/R | publishes kernels via `build-kernel-artifacts.sh`; mvm-images owns kernel publication |
| release-boot-image.yml | whole file | D | the legacy producer, including `qemu-wasm-site-pack` |
| release.yml | 295-351, 353, 371, 739-740 | D / E | `initramfs-image` builds `./nix/images/initramfs`; `needs`/`if`/asset list follow; the W7.1 mirror step retires only after Wave 0.5 ships |
| security.yml | 703-829, 896-1327 | D/R | `verified-boot-artifacts`, `sealed-prod-no-ssh`, `builder-vm-image-reproducibility`, `pack-reproducibility-{builder,runtime}` build in-tree |
| security.yml `flake-locks-clean`, update-image-pin.yml, image-pair.yml | — | K | no in-tree dependency |

Same PR as Wave 3: `tests/github_actions_aarch64_no_kvm.rs:42`,
`xtask/src/check_workflow_paths.rs` (985-989, 1060, 1087, 1459-1466,
1482-1487), `scripts/local-aarch64-no-kvm-smoke.sh:68-71`.

## Wave 4 — tree, gates and stragglers

| file | line(s) | class | reason |
|---|---|---|---|
| nix/images/** | 17 files | D | the tree |
| Justfile | 753-760 / 375-376 | D / R | `_release-prep` bumps `nix/images/version.nix` / `e2e-source-bootstrap` |
| xtask/src/check_runtime_overlay_version.rs, check_all.rs:229, main.rs:470,597 | — | D | gate reads `nix/images/version.nix`; retire with the `_release-prep` edit |
| xtask/src/check_guest_binary_lists.rs | 10, 36, 130 | R | reads the in-tree overlay flake inside check-all |
| xtask/src/check_kernel_pin_freshness.rs | 86 | R | `nix eval nix/images/kernel#…`; would silently lose the pin |
| xtask/src/build_dev_image.rs, main.rs:487,705 | — | D | already dead: targets the removed `nix/images/builder/` |
| xtask/src/perf.rs | 81, 1006 | R | test reads the overlay flake for the block size |
| xtask/src/check_image_reproducibility.rs | 31-36 | K | walks `nix/` generically |
| xtask/src/check_guest_agent_in_all_images.rs, check_guest_images_no_builder_tools.rs | — | K | read only `nix/lib/mk-guest.nix` and crate source |
| xtask/src/check_kernel_config_budget.rs | 79-83 | K | loses its only producer (`build-kernel-artifacts.sh`); decided with that script |
| scripts/build-kernel-artifacts.sh, scripts/e2e-source-bootstrap.sh | — | D/R | in-tree kernel and cold Stage 0 builds |
| tests/nix_flake_structure.rs | 175, 456-457, 977, 1302-2144 | D | structural tests of the in-tree flakes |
| tests/release_assets.rs | 630 | R | reads the overlay flake |
| tests/smoke_invoke.rs.spec | 3-199 | D | uncompiled spec citing a path that does not exist |
| nix/packages/qemu-wasm-smoke-image.nix | 22 | R | `import ../images/kernel/base.nix` — hard eval break of `./nix` |
| nix/lib/workspace-filter.nix | 4-7 | E | comment |
| examples/agent-workload/flake.nix:18, examples/claude-code/flake.nix:38 | — | R | import `${mvm}/images/examples/llm-agent` |
| examples/claude-code/README.md:110, schema/workload-ir-v0.json | — | E | path text; regenerate the schema from `network_policy.rs:111` |
| crates/{libkrun-sys/src/sys.rs:344, mvm-agentd/src/guest_mount.rs:1247, mvm-backends/src/driver/qemu.rs:152, mvm-conformance/src/lib.rs:396, mvm-contract/src/policy/{audit.rs:335,network_policy.rs:111}, mvm-core/src/config.rs:36, mvm-fs/src/initramfs.rs:3, mvm-runtime/src/vm/template/lifecycle/artifacts.rs:43,521} | — | E | comments, docs, error and skip text |
| crates/mvm-core/src/image_set/tests.rs | 175 | K | fixture string |
| crates/mvm-vmm/src/host/runtime_meta.rs | 571, 587 | D | cross-language sidecar guard reads the in-tree flake; the guard moves to mvm-images |
| crates/mvm-conformance/tests/steps/initramfs.rs:65, crates/mvm-client/src/launch/{runtime_overlay.rs:26, runtime_source.rs:269} | — | R | in-tree overlay root helper |
| .githooks/pre-commit:289, .gitignore:27-31, CLAUDE.md:161,256, README.md:1016 | — | E | live text |
| public/src/content/docs/{contributing/development.md, guides/builder-vm.md, guides/dev-image.md, guides/ir-to-image.mdx, guides/kernels.md, install/macos.md, reference/cli-commands.md, reference/releases.md} | — | E | live docs |

## Totals against the plan's snapshot

- Workflows: the same 7 with a literal hit, plus `kernel-build.yml`
  indirectly. `security.yml` was listed as E; it carries five D/R jobs.
- Crate files: 44 with a literal hit (mvm-build 17, mvm-cli 16, mvm-contract 2,
  mvm-core 2, one each in libkrun-sys, mvm-agentd, mvm-backends,
  mvm-conformance, mvm-fs, mvm-runtime, mvm-vmm) — the snapshot's count — plus
  12 indirect crate files the snapshot did not list.
- Other literal files: 29 (xtask 7, tests 4, scripts 2, docs 8, one each in
  Justfile, CLAUDE.md, README.md, .gitignore, .githooks, examples, nix/lib,
  schema).

## Findings that change the wave plan

1. `nix/flake.nix` stops evaluating: `nix/packages/qemu-wasm-smoke-image.nix`
   imports `../images/kernel/base.nix`.
2. Waves 1 and 2 are compile-coupled (`ImageSource::InTree` and
   `in_tree_overlay_checkout_root` have arms in mvm-cli and mvm-client); they
   land together.
3. The CLI's source-checkout signal is the in-tree builder flake. Deleting it
   would flip contributor builds to installed behaviour in kernel resolution,
   `doctor builder`, `image boot update` and the bootstrap pack gate; the
   signal re-points to `mvm_source_checkout` first.
4. A contributor build with no sibling `mvm-images` and without
   `release-artifact-bootstrap` has no builder image once the in-tree arm is
   gone; its default must fetch the published image.
5. Two in-tree-only artifacts: the dev default-tenant variant and the
   `workload-k8s` kernel.
6. `nix/images/version.nix` is the overlay/sidecar/initramfs `VERSION` source,
   bumped by `_release-prep` and gated by `check-runtime-overlay-version`.
7. Gates: `check-guest-binary-lists` fails hard; `check-kernel-pin-freshness`
   degrades silently; `check-kernel-config-budget` loses its producer.
8. Initramfs: `release.yml`'s `initramfs-image` is the only in-mvm publisher,
   and the initramfs is not a signed image-set root member.
9. Two example flakes and `agent_workload_example.rs` depend on
   `nix/images/examples/llm-agent`.
10. The `runtime_meta.rs` default-tenant sidecar guard loses its subject.
11. CI lanes that witness the in-tree source path (`source-bootstrap-linux`,
    `no-kvm-bootstrap`, the footprint step) retire or re-point.
12. Already dead: `xtask build-dev-image`, `persistent_builder.rs:513`,
    `bootstrap.rs:286`, `.gitignore:27-31`, `smoke_invoke.rs.spec`.
