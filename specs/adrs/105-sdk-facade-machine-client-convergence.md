# ADR-105: SDK ↔ facade machine-driving convergence on the `MvmClient` trait

- Status: Proposed
- Date: 2026-07-01
- Owner: MVM Project
- Related: `specs/notes/mvm-client-facade-design.md` + Plan 216 (the `mvm-client` facade), ADR-104 (cloud control-plane trust boundary — the facade's remote path), ADR-041 (signed audited execution plans — claim 8, the admission the local `run` path must not skip). Sequenced by: Plan 218.

## Update (2026-07-06): the trait lives in `mvm-core`, one user-facing crate

The original decision below put the trait + DTOs in a standalone `mvm-client`
crate and pushed `LocalBackend` into a second `mvm-client-local` crate to keep
the first `mvm-*`-free. Two crates, two imports (`mvm_client::{MvmClient, …}` +
`mvm_client_local::LocalBackend`) — confusing for consumers.

That two-crate split is replaced. The trait + DTOs + `MockBackend` + the remote
`GatewayBackend` now live in **`mvm-core::client`**, behind a `client` feature
(the gateway behind `client-remote`). `LocalBackend` and `connect` live in a
single user-facing **`mvm-client`** crate that re-exports the `mvm-core::client`
surface, so consumers write one import:

```rust
use mvm_client::{MvmClient, MachineSpec, LocalBackend};
```

**Why this is now the right home** — and why the "rejected: put it in
`mvm-core`" bullet below was mistaken: it claimed the `check-core-runtime-free`
gate "forbids pulling async runtimes there." The gate (`xtask
check-core-runtime-free`) only forbids **`tokio`**. `async-trait` is a
proc-macro (`proc-macro2`/`quote`/`syn`) that desugars async methods to boxed
futures — it pulls no async runtime — so gating it behind `client` keeps
`mvm-core`'s default closure `tokio`-free, and the guest-agent gate
(`check-guest-agent-runtime-free`, which *does* forbid `async-trait`) stays
green because the guest never enables the feature. The cycle the split existed
to avoid also dissolves: `mvm-core` is the foundation everyone already depends
on, so `mvm-sdk` reaches the trait via `mvm-core/client` with no new edge, and
`LocalBackend`'s `mvm-backend` dependency stays above the foundation in
`mvm-client`. `mvm-sdk`'s subprocess `SubprocessBackend` and the cycle guard
(`no_backend_dep.rs`) are unchanged in intent.

The prose below is the original (superseded) reasoning, kept for history.

## Context

There are **two** clients that drive local microVM lifecycle, with overlapping responsibility and different mechanisms:

- **`crates/mvm-sdk/src/machine.rs`** — a builder-based client (`MachineClient`, `Machine::{start, stop, exec, shell}`, `MachineRunBuilder{image, command, …}`) whose module doc says it *"deliberately shells to `mvmctl machine …`"* — it drives lifecycle by spawning the `mvmctl` subprocess.
- **`crates/mvm-client`** — the `MvmClient` facade: `list_machines` / `run_machine` / `stop_machine` / `machine_logs` over `LocalBackend` (in-process) or `GatewayBackend` (REST). Landed in Plan 216.

Both drive machines; the SDK reinvents it via subprocess. That is the repo's most common bug source (duplicated logic drifts) applied to a security-sensitive surface — the SDK's `run` and the facade's `run` both ultimately need the signed-plan admission (claim 8), and two separate drivers means two places to get admission right (or wrong).

### Why the SDK shells a subprocess — the constraint that shapes any fix

The dependency graph runs high→low:

```
mvm-client (local feature) → mvm-backend → mvm-build → mvm-sdk → mvm-core
```

`mvm-sdk` sits **below** the runtime. If the SDK linked `LocalBackend` (which pulls `mvm-backend`), the result is a cycle: `mvm-sdk → mvm-client(local) → mvm-backend → mvm-build → mvm-sdk`. The process boundary in `machine.rs` is a **deliberate** way to sidestep that cycle, not an oversight. Any convergence must respect it.

### The unlock

The trait + DTOs must live in a crate whose **manifest declares no `mvm-*` dependency at all**. A first attempt — `mvm-client` with `default-features = false` — **fails**: Cargo detects cycles on the *manifest* graph, **optional dependencies included**. Because `mvm-client`'s manifest declares `mvm-backend` (for the `local` feature), it forms a cycle regardless of features:

```
mvm-sdk → mvm-client → mvm-backend → mvm-build → mvm-network → mvm-sdk
```

(verified live: `cargo` refuses with `cyclic package dependency: mvm-backend depends on itself`). Turning the feature off does not help — the edge is in the manifest.

The real fix is structural: **extract `LocalBackend` (the only `mvm-backend`-linking piece) into a separate `mvm-client-local` crate.** Then `mvm-client` holds the trait + DTOs + `GatewayBackend` + `connect` and its manifest carries **zero `mvm-*` deps**, so `mvm-sdk` can depend on it freely. `mvm-client-local` sits *above* the runtime (it links `mvm-backend`) and is used by the CLI. `connect(Target::Local)` — which can no longer reach `LocalBackend` — directs callers to construct `mvm_client_local::LocalBackend` directly.

## Decision

Keep the two crates and their **distinct responsibilities** — `mvm-sdk` is *authoring* (the `Workload` IR: image, entrypoints, deps, resources, network, hooks), `mvm-client` is *operating* (drive machine lifecycle). Converge only the overlapping *"drive a machine"* mechanism onto the shared trait:

1. **One interface: `MvmClient`.** The trait + DTOs are the single machine-driving contract, in `mvm-client` — whose manifest carries no `mvm-*` dependency (`LocalBackend` moved to `mvm-client-local`). Every layer depends on that cycle-free crate for the contract.
2. **Three impls, one per layer's constraint:**
   - `LocalBackend` (in-process) — CLI. Needs the runtime; lives above it.
   - `GatewayBackend` (REST) — studio / remote. No runtime dep.
   - **A subprocess impl in `mvm-sdk`** — the SDK keeps shelling `mvmctl machine`, but *behind `MvmClient`*, so it satisfies the same contract while respecting the cycle.
3. **One spec vocabulary.** The SDK's `Workload`/`App` IR is the rich authoring definition; it **lowers** to the facade's operational `MachineSpec` (a projection: image/resources/env → the run spec). No second parallel spec type maintained by hand.
4. **One admission path.** When the admitted-boot library seam lands (issue #1388 / Plan 214), *both* `LocalBackend::run` and the SDK's subprocess `run` route through the **same** admitted-boot function. There is never a second, admission-skipping boot path — the property claim 8 protects.

## Consequences

- The SDK's bespoke `machine.rs` shrinks to an `MvmClient` impl + the authoring-side builders; its ad-hoc lifecycle surface stops being a parallel API.
- Callers (SDK live/invoke, CLI, studio) program against `MvmClient`, so swapping transport or moving a workload local↔remote is a backend choice, not a rewrite.
- `MachineSpec` gains a documented lowering from `Workload`; the two stop drifting.
- No dependency cycle is introduced: the shared surface is the runtime-free trait+DTOs; runtime-linking impls stay in the crates that already sit above the runtime.

## Alternatives considered

- **Make `mvm-sdk` depend on `LocalBackend`.** Rejected — introduces the `mvm-sdk → mvm-backend → mvm-build → mvm-sdk` cycle. The subprocess boundary exists precisely to avoid this.
- **Merge `mvm-sdk` and `mvm-client`.** Rejected — they are genuinely different responsibilities (authoring vs operating) at different points in the dep graph; merging would drag the runtime under the SDK.
- **Leave two drivers, document the overlap.** Rejected — the duplication is on the security-critical `run`/admission path; two drivers means two admission implementations to keep correct. Converging on one trait + one admitted-boot fn is the whole point.
- **Put the shared spec/trait in `mvm-core`.** Considered. The trait is async (`async-trait`); `mvm-core` is the runtime-free foundation and the `check-core-runtime-free` gate forbids pulling async runtimes there. Keeping the trait in `mvm-client` (default-features light) is the cycle-safe home; `mvm-core` may hold pure DTO structs if reuse warrants.

## Scope / sequencing (Plan 218)

- **P1** — `mvm-sdk` depends on `mvm-client` (`default-features = false`); add a subprocess `impl MvmClient` (list/stop/logs) that shells `mvmctl machine`. Additive; the existing builders stay.
- **P2** — Define the `Workload`/`App` → `MachineSpec` lowering; the SDK's run builder produces a `MachineSpec`.
- **P3** — Migrate SDK live/invoke call sites to the `MvmClient` trait; retire the duplicated bits of `machine.rs`.
- **P4** — When the admitted-boot seam lands, wire `LocalBackend::run` **and** the SDK subprocess `run` through the one admitted-boot library fn. Closes issue #1388 for the facade.

## Runbook: publishing the mvm SDKs (consolidated from specs/runbooks/publish-sdks.md)

# Runbook: publishing the mvm SDKs (PyPI + npm)

Publishes the Python SDK (`crates/mvm-sdk/python`, package **`mvm`**) and the
TypeScript SDK (`crates/mvm-sdk/typescript`, package **`mvm-sdk`**) to PyPI and
npm. Driven by `.github/workflows/publish-pypi.yml` and
`publish-npm.yml`, alongside the existing `publish-crates.yml`.

**Why these ship coupled to the toolchain:** the SDK emits the Workload
IR that the *same-version* `mvmctl` consumes (`launch.json`
`toolchain_version` == mvmctl `CARGO_PKG_VERSION`). Both workflows refuse
to publish unless the SDK version equals the release tag, so a published
SDK can never drift from the toolchain. Bump the SDK versions in the same
commit that bumps the toolchain.

## One-time setup (manual — outward-facing, do these first)

These claim public names and configure credentials; they can't be
automated from the repo.

### 1. Names + orgs

- **PyPI: `mvm`** under the **`runmvm`** PyPI org. The project already
  exists (latest `0.1.2`; history 0.1.0–0.1.2) — manage it from the
  `runmvm` org. The distribution name stays `mvm` and the import stays
  `import mvm` (PyPI orgs don't scope names).
- **npm: `@runmvm/mvm`** — a **scoped** package under the **`runmvm`**
  npm org. This is a rename from the old unscoped `mvm-sdk` (latest
  `0.1.2`), so `@runmvm/mvm` is a fresh package: the first publish
  creates it under the org. TS import becomes `from "@runmvm/mvm"`.
  Optionally retire the old name: `npm deprecate mvm-sdk "moved to
  @runmvm/mvm"`.

Local is `0.15.0`, not on either registry, so the first publish is a
clean bump (no duplicate-version rejection) that aligns the registries
with the toolchain. Re-check anytime:

```sh
curl -s https://pypi.org/pypi/mvm/json | python3 -c 'import sys,json;print(json.load(sys.stdin)["info"]["version"])'
curl -s https://registry.npmjs.org/@runmvm/mvm | python3 -c 'import sys,json;print(json.load(sys.stdin).get("dist-tags",{}).get("latest","(unpublished)"))'
```

### 2. PyPI — Trusted Publishing (no token)

The `mvm` project already exists, so add a **regular** trusted publisher
to it: PyPI → project `mvm` → **Manage** → **Publishing** → **Add a new
publisher** (GitHub):

- Owner: `tinylabscom`
- Repository: `mvm`
- Workflow name: `publish-pypi.yml`
- Environment: `pypi`

(No API token is stored — the workflow authenticates via OIDC.) Also
create a repo **Environment** named `pypi` (Settings → Environments) if
you want required reviewers gating publishes. If you'd rather not use
trusted publishing, drop a `PYPI_API_TOKEN` secret and swap the publish
step to `with: { password: ${{ secrets.PYPI_API_TOKEN }} }`.

### 3. npm — org + automation token

- Ensure the **`runmvm`** npm org exists and your account is a member
  with publish rights.
- Create a **granular automation token** scoped to publish under
  `@runmvm/*` (npm → Access Tokens → Granular → Packages and scopes →
  `@runmvm`).
- Add it as repo secret **`NPM_TOKEN`** (Settings → Secrets → Actions).
- The package is scoped, so the publish must be public — the workflow
  passes `--access public` and `package.json` sets
  `publishConfig.access = public`.

## Rehearse (safe, no upload)

Run each workflow via **Actions → Run workflow** with `dry_run: true`:

- PyPI: builds sdist+wheel, runs the version guard, **skips upload**.
- npm: `npm ci && npm run build && npm publish --dry-run` (no upload).

Fix anything that fails here before a real release.

## Publish (real)

Publishing is tied to a GitHub Release so crates + PyPI + npm go out
together at one version:

1. Bump versions in the **same commit**:
   - `crates/mvm-sdk/python/pyproject.toml` `version`
   - `crates/mvm-sdk/typescript/package.json` `version`
   - the workspace/toolchain version (`Cargo.toml`) — keep all three equal.
2. Tag + release:
   ```sh
   gh release create v0.15.0 --generate-notes
   ```
   The `release: published` event fans out to `publish-crates.yml`,
   `publish-pypi.yml`, and `publish-npm.yml`. Each asserts its package
   version equals `0.15.0` and refuses otherwise.
3. Verify:
   ```sh
   pip index versions mvm        # or: pip install mvm==0.15.0
   npm view @runmvm/mvm version
   ```

## Notes

- Both packages are pure (Python: zero runtime deps, hatchling; TS: tsc →
  `dist`), so there's nothing platform-specific to matrix.
- The SDKs are **host authoring tools** — they are never installed into a
  workload guest (the `@mvm.app` decorator is stripped from the bundled
  source at compile, see `crates/mvm-sdk/src/compile/strip_framework.rs`).
- For contributors working from a source checkout, prefer the editable
  install over the published package so the SDK always matches local
  HEAD (see the development guide).
