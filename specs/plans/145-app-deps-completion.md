# Plan 145 — Complete the build-time application-deps story

## Context

`v0.15.2` shipped TypeScript/Node workloads with a **nix-native** build-time
deps path: when a bundle carries `package-lock.json`, the generated flake builds
`node_modules` via nixpkgs `importNpmLock` and bakes it into the read-only app
derivation (symlinked at `/app`, resolved as `/app/node_modules` at runtime).
That path is reproducible and hermetic but unhardened — no SBOM, no CVE gate, no
attestation — and npm-only.

The repo also has the **hardened** sealed-volume pipeline (ADR-047 / claim 11):
the builder VM installs deps into `~/.mvm/volumes/deps/<hash>/` carrying
`content/`, `sbom.cdx.json`, `fetch.log`, `cve.json`, and a hash-chained
`meta.json`; `mvm_sdk::compile::deps_audit::verify_sealed_volume` re-verifies it
at admit time; `ExecutionPlan` pins it via `DepsVolumeBinding { volume_hash,
manifest_sha256 }`. The install side is wired for libkrun
(`mvm-build/src/libkrun_builder.rs` `BuilderJob::Install` →
`finalize_install_job`); `mvm-host-vm-init/src/install.rs` runs the installer +
SBOM + CVE.

**The gap:** nothing mounts that sealed volume into a running workload. There is
no deps-volume mount in `crates/mvm-backend/src/libkrun.rs` or
`nix/lib/mk-guest.nix` — `/app` is a read-only nix-store symlink with no
`node_modules`/`.venv` beside it. So the hardened path can build + audit + admit
a volume but the function never sees it. This is true for **every** language,
not just Node. Closing it is the difference between "deps are CVE-gated" on paper
and at runtime.

This plan completes the build-time deps story: the missing sealed-volume runtime
mount (the headline), plus two smaller follow-ups left from the v0.15.2 work.

Two layers, deliberately kept distinct (per ADR-046's two-acquisition-paths
framing):
- **nix-native bake** (shipped) — dev/reproducible, deps in the RO app image.
- **sealed volume** (this plan) — hardened/audited, deps in a pinned RO volume
  mounted at boot. Selected by tier (`GateLevel::Dev` vs `Prod`) and/or explicit
  `mvm.{python,node}_deps(lockfile=…)`.

## Workstream A — Sealed-volume runtime mount (the missing claim-11 leg)

Make a workload boot with its admitted deps volume mounted read-only, so the
baked `verify_sealed_volume` + `DepsVolumeBinding` actually gate what the
function loads.

- [ ] **Boot-config wiring.** Thread `ExecutionPlan.deps_volume_binding`
      (`mvm-plan/src/types.rs` `DepsVolumeBinding`) from admission
      (`crates/mvm-cli/src/commands/vm/`) into the backend launch config so the
      backend knows the on-disk path `~/.mvm/volumes/deps/<volume_hash>/content`
      and the language (→ guest mount target).
- [ ] **libkrun mount first** (`crates/mvm-backend/src/libkrun.rs` +
      `mvm-libkrun` supervisor config): add a read-only virtio-fs share for the
      volume `content/`, mirroring how the builder VM shares `/job`. Mount target
      per language: Node → `/app/node_modules`, Python → `/app/.venv` (or export
      `NODE_PATH`/`PYTHONPATH` to the share — pick the one that resolves without
      shadowing the baked source; node_modules-beside-source resolves natively).
- [ ] **mk-guest `/init`** (`nix/lib/mk-guest.nix`): mount the share at the
      chosen path during stage setup, read-only, before the boot command stages
      `/app`. Keep it conditional (no binding → no-op) so deps-free workloads are
      unchanged.
- [ ] **Admit-time re-verify already exists** — confirm the supervisor calls
      `verify_sealed_volume` on the pinned `volume_hash`/`manifest_sha256` before
      mount, and refuses on drift (tie into the existing
      `mvm_supervisor::verify_audit_chain` admission path).
- [ ] **Backend coverage:** libkrun + Vz first (matches the gateway-audit
      substrate coverage note — Firecracker/apple-container deferred, and
      apple-container is blocked on the `vmlinux` papercut, see
      `specs/notes/vz-and-apple-container-builder-papercuts.md`).
- [ ] **Tests:** unit — binding → mount-config mapping per language; negative —
      tampered volume refused before boot. E2E — `mvmctl up` a Python deps
      example (`examples/python/hello-app-with-deps`) and confirm the workload
      imports the sealed dep; byte-flip `cve.json` → admission refuses.

## Workstream B — pnpm / yarn in the nix-native path

Today `flake.rs` keys on `package-lock.json` and uses `importNpmLock` (npm only).

- [ ] Detect `pnpm-lock.yaml` → build via `pnpm.fetchDeps` (nixpkgs) instead of
      `importNpmLock`; `yarn.lock` → the yarn-berry equivalent. Branch on the
      lockfile filename present in `./src`, same `nodeHasLock` site in
      `crates/mvm-sdk/src/compile/flake.rs`.
- [ ] Reconcile with the IR `NodeTool` enum (`mvm-ir` already has
      `Pnpm`/`Npm`/`Yarn`) so an explicit `mvm.node_deps(lockfile=…, tool=…)`
      and the file-presence auto-detect agree.
- [ ] Tests: flake-codegen asserts the right builder per lockfile; an example
      per tool if cheap.

## Workstream C — Bare `package.json`, no lockfile

Today a `package.json` with no lockfile silently falls through to the plain
copy — deps are not installed and the function fails at runtime with no signal.

- [ ] Dev: emit a clear `[mvm] warning:` at compile that deps won't be installed
      without a lockfile (point at `npm install` to generate one).
- [ ] Prod (`GateLevel::Prod`): fail closed — a dependency set with no pinned
      lockfile is non-reproducible and must not ship.
- [ ] Tests: compile-time warning present (dev); prod gate refuses.

## Sequencing & risk

- WS-A is the substantive vertical and touches the backend + nix boot path. The
  builder-VM/Vz area is actively churning (`slim-builder-kernel`,
  `kernel-build-command`, `builder-vm-repro`, `reconcile-538`) — coordinate /
  rebase to avoid collisions; do the mount work after that settles.
- WS-B and WS-C are self-contained in `flake.rs` / compile and can land first as
  fast-follows to `v0.15.2`.
- No new runtime deps; reuse nixpkgs fetchers and the existing audit crates.

## References
- ADR-047 (`specs/adrs/047-app-deps-audit-pipeline.md`) — sealed-volume pipeline, claim 11.
- ADR-046 — two artifact layers / two acquisition paths.
- `crates/mvm-host-vm-init/src/{install,install_spec}.rs` — installer + spec.
- `crates/mvm-build/src/libkrun_builder.rs` — `BuilderJob::Install` arm.
- `crates/mvm-sdk/src/compile/{flake,deps_audit}.rs` — nix-native bake + volume verify.
- `crates/mvm-plan/src/types.rs` — `DepsVolumeBinding`.
- `specs/notes/vz-and-apple-container-builder-papercuts.md` — backend blockers for full coverage.
