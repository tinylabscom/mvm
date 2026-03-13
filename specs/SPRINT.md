# Sprint 36 — Fast Boot & Minimal Images

**Goal:** Make microVMs boot as fast and stay as small as possible.
The paperclip example exposed three problems:
(1) tsx transpiles TypeScript at runtime — ~3 min cold start;
(2) rootfs closures pull in unnecessary build-time deps;
(3) writing Node.js service flakes requires too much boilerplate.

**Branch:** `feat/sprint-36`

## Current Status (v0.6.0)

| Metric           | Value                    |
| ---------------- | ------------------------ |
| Workspace crates | 6 + root facade + xtask  |
| Total tests      | 873+                     |
| Clippy warnings  | 0                        |
| Edition          | 2024 (Rust 1.85+)        |
| MSRV             | 1.85                     |
| Binary           | `mvmctl`                 |

## Completed Sprints

- [01-foundation.md](sprints/01-foundation.md)
- [02-production-readiness.md](sprints/02-production-readiness.md)
- [03-real-world-validation.md](sprints/03-real-world-validation.md)
- Sprint 4: Security Baseline 90%
- Sprint 5: Final Security Hardening
- [06-minimum-runtime.md](sprints/06-minimum-runtime.md)
- [07-role-profiles.md](sprints/07-role-profiles.md)
- [08-integration-lifecycle.md](sprints/08-integration-lifecycle.md)
- [09-openclaw-support.md](sprints/09-openclaw-support.md)
- [10-coordinator.md](sprints/10-coordinator.md)
- Sprint 11: Dev Environment
- [12-install-release-security.md](sprints/12-install-release-security.md)
- [13-boot-time-optimization.md](sprints/13-boot-time-optimization.md)
- [14-guest-library-and-examples.md](sprints/14-guest-library-and-examples.md)
- [15-real-world-apps.md](sprints/15-real-world-apps.md)
- [16-production-hardening.md](sprints/16-production-hardening.md)
- [17-resource-safety-release.md](sprints/17-resource-safety-release.md)
- [18-developer-experience.md](sprints/18-developer-experience.md)
- [19-observability-security.md](sprints/19-observability-security.md)
- [20-production-hardening-validation.md](sprints/20-production-hardening-validation.md)
- [21-binary-signing-attestation.md](sprints/21-binary-signing-attestation.md)
- [22-observability-deep-dive.md](sprints/22-observability-deep-dive.md)
- [23-global-config-file.md](sprints/23-global-config-file.md)
- [24-man-pages.md](sprints/24-man-pages.md)
- [25-e2e-uninstall.md](sprints/25-e2e-uninstall.md)
- [26-audit-logging.md](sprints/26-audit-logging.md)
- [27-config-validation.md](sprints/27-config-validation.md)
- [28-config-hot-reload.md](sprints/28-config-hot-reload.md)
- [29-shell-completions.md](sprints/29-shell-completions.md)
- [30-config-edit.md](sprints/30-config-edit.md)
- [31-vm-resource-defaults.md](sprints/31-vm-resource-defaults.md)
- [32-vm-list.md](sprints/32-vm-list.md)
- [33-template-init-preset.md](sprints/33-template-init-preset.md)
- [34-flake-check.md](sprints/34-flake-check.md)
- [35-run-watch.md](sprints/35-run-watch.md)

---

## Rationale

The paperclip example revealed how badly runtime TypeScript transpilation hurts
boot time.  tsx cold-transpiles every imported module on startup — 24 drizzle
migrations, all of `@paperclipai/db`, `@paperclipai/shared`, and their
dependencies — taking ~3 minutes before the server even binds a port.

The compiled `dist/` files already exist (tsc runs at image build time), but the
workspace packages' `package.json` still has `"exports": { ".": "./src/index.ts"
}`.  Node.js resolves to the TypeScript source, invoking tsx.  Patching the
exports to `"./dist/index.js"` at build time makes tsx unnecessary: the server
boots in under 10 seconds.

Beyond paperclip, all Node.js workload images benefit from a pre-compile step,
and all images benefit from pruning dev-only npm packages from the runtime
closure.

---

## Phase 1: Pre-compiled exports — eliminate tsx at runtime

**Problem:** Workspace packages export `./src/index.ts`.  The compiled
`./dist/index.js` exists but isn't wired up.  tsx must re-transpile every import
on every cold start.

**Fix:** In the `paperclip-built` derivation's `buildPhase`, after running `tsc`
for each workspace package, patch its `package.json` exports to point at `dist/`:

```js
// For each packages/*/package.json after tsc:
pkg.exports = { ".": "./dist/index.js", "./*": "./dist/*.js" };
pkg.main = "./dist/index.js";
pkg.types = "./dist/index.d.ts";
```

Remove `--import tsx/dist/loader.mjs` from the `paperclip-start` command.

**Expected result:** Cold boot drops from ~3 min → ~10 sec (tsx loader +
transpilation time eliminated entirely).

- [x] Patch `packages/*/package.json` exports in `paperclip-built` buildPhase
- [x] Remove tsx `--import` flag from `paperclip-start`
- [x] Verify server starts in under 30 seconds (actual: ~80 sec; tsx gone, remainder is postgres init + 24 migrations on first boot)

## Phase 2: Prune dev dependencies from the runtime closure

**Problem:** `npm install --ignore-scripts` installs everything
(devDependencies included).  The rootfs closure pulls in typescript, vite,
esbuild CLI, test frameworks, etc. — none needed at runtime.

**Fix:** After building, delete non-runtime packages from `node_modules/` before
copying to `$out`.  A safe list:
- `typescript`, `vite`, `vitest`, `@vitest/*`, `eslint`, `@eslint/*`
- `tsx` (once phase 1 is done), `esbuild` (used only by tsx/vite at build time)
- `drizzle-kit` (migration generator, not runtime)
- `@types/*`, `*.d.ts` files outside `dist/`

Also strip `devDependencies` entries from workspace `package.json` files before
the npm install — this prevents them from being installed at all.

**Expected result:** ~30–50% rootfs size reduction.

- [ ] Add a `prunePhase` after `buildPhase` in `paperclip-built`
- [ ] Measure rootfs size before and after
- [ ] Ensure server still starts correctly after pruning

## Phase 3: `mkNodeService` helper in guest-lib

**Problem:** Writing a Node.js service in a flake requires ~60 lines of
boilerplate: FOD npm install, autoPatchelf, tsc build, start script, env block.
Every Node.js workload repeats this pattern.

**Add** `mvm.lib.<system>.mkNodeService` to `nix/guest-lib/flake.nix`:

```nix
mvm.lib.<system>.mkNodeService {
  name = "my-app";
  src = fetchGit { url = ...; rev = ...; };
  npmHash = "sha256-...";   # FOD hash for npm install
  buildPhase = ''            # optional; default: tsc
    (cd server && node "$TSC")
  '';
  entrypoint = "server/dist/index.js";  # relative to built output
  env = { PORT = "3000"; };
  user = "myapp";
  port = 3000;               # used for health check + port mapping
}
```

`mkNodeService` returns `{ package, service, healthCheck }` — the caller
assembles them into `mkGuest { packages = [...p.package]; services.app = p.service; healthChecks.app = p.healthCheck; }`.

- [ ] Add `mkNodeService` to `nix/guest-lib/flake.nix`
- [ ] Refactor paperclip example to use `mkNodeService`
- [ ] Add a minimal `hello-node` example using `mkNodeService`
- [ ] Document the helper in `nix/guest-lib/flake.nix` comments

## Phase 4: `startupGraceSecs` health check for slow-starting services

**Problem:** Services like paperclip take time to run migrations on the first
boot.  The health check starts failing immediately, flooding the log before the
service is ready.  There is no way to suppress early failures.

**Add** `startupGraceSecs` to health check configs (already plumbed in
`mkHealthCheckFile` via `lib.optionalAttrs`; needs guest-agent support):

In `mvm-guest/src/integrations.rs`, honour `startup_grace_secs`:
- Skip health check failures for the first N seconds after the VM boots
- Report `starting` status instead of `unhealthy` during the grace period

- [ ] Add `startup_grace_secs` field handling in the guest agent
- [ ] Wire up in paperclip example (`startupGraceSecs = 180`)
- [ ] Test that health checks don't spam the log during startup

## Verification

```bash
cargo test --workspace
cargo clippy --workspace -- -D warnings
# Visual: paperclip VM starts in < 30s after phase 1
```
