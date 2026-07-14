# Runbook: publishing the mvm SDKs (PyPI + npm)

Publishes the Python SDK (`sdks/python`, package **`mvm`**) and the
TypeScript SDK (`sdks/typescript`, package **`@runmvm/mvm`**) to PyPI and
npm. Driven by `.github/workflows/publish-sdk.yml`, which fans out to the
reusable `.github/workflows/publish-pypi.yml` and `publish-npm.yml` jobs.

The SDK publish lane is explicit and separate from ordinary runtime releases:
runtime tags stay on `vX.Y.Z`; SDK publication only runs for `sdk-vX.Y.Z`
releases or an explicit workflow dispatch rehearsal. `sdks/release.toml` is the
checked-in source of truth for the SDK release version, package metadata
targets, and CLI resolution order.

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

The manifest currently carries `0.15.1`. Re-check the registries anytime:

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
- Workflow name: `publish-sdk.yml`
- Environment: `pypi`

(No API token is stored — the workflow authenticates via OIDC.) The PyPI
publisher should bind to the orchestrator workflow (`publish-sdk.yml`), not
the reusable leaf, because GitHub's standard OIDC claims describe the calling
workflow and expose the called reusable workflow separately via
`job_workflow_ref`. Also create a repo **Environment** named `pypi`
(Settings → Environments) if you want required reviewers gating publishes. If
you'd rather not use trusted publishing, drop a `PYPI_API_TOKEN` secret and
swap the publish step to `with: { password: ${{ secrets.PYPI_API_TOKEN }} }`.

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

Run **Publish SDKs** (`publish-sdk.yml`) via **Actions → Run workflow** with
`dry_run: true`:

- orchestrator preflight: validates `sdks/release.toml`, package metadata,
  the single-CLI contract, and registry version availability;
- PyPI leaf: builds sdist+wheel, runs `twine check`, installs the built wheel
  in a clean venv, imports `mvm`, and **skips upload**;
- npm leaf: runs `npm ci && npm run build`, `npm pack`, installs the packed
  tarball in a clean temp project, imports `@runmvm/mvm`, and **skips upload**.

The same dry-run path is exercised on every branch push by the CI lane
`SDK release dry-run`.

Fix anything that fails here before a real release.

## Publish (real)

Publishing is tied to a dedicated SDK GitHub Release:

1. Update the SDK release set in the **same commit**:
   - `sdks/release.toml` `version`
   - `sdks/python/pyproject.toml` `version`
   - `sdks/typescript/package.json` `version`
2. Tag + release:
   ```sh
   gh release create sdk-v0.15.1 --generate-notes
   ```
   The `release: published` event triggers `publish-sdk.yml`. Its preflight
   job asserts the package metadata matches `sdks/release.toml`, that the
   release tag equals `sdk-v0.15.1`, and that the version is not already
   present on PyPI or npm before it calls the reusable PyPI/npm publish jobs.
3. Verify:
   ```sh
   pip index versions mvm        # or: pip install mvm==0.15.1
   npm view @runmvm/mvm version
   ```

## Rollback expectations

- If preflight fails, fix the manifest/package metadata or bump the SDK version
  and cut a new `sdk-vX.Y.Z` release; nothing has been published yet.
- If one registry publish succeeds and the other fails, do not retry the same
  version blindly. PyPI versions are immutable and npm provenance should stay
  one-version-per-release. Cut a new SDK version after fixing the fault.
- If npm succeeds but the release should no longer be advertised, deprecate the
  published version on npm and cut a replacement SDK release.

## Notes

- Both packages are pure (Python: zero runtime deps, hatchling; TS: tsc →
  `dist`), so there's nothing platform-specific to matrix.
- Runtime `vX.Y.Z` releases do **not** attempt PyPI/npm publication anymore;
  `publish-sdk.yml` refuses to fan out unless the release tag is `sdk-vX.Y.Z`.
- The SDKs are **host authoring tools** — they are never installed into a
  workload guest (the `@mvm.app` decorator is stripped from the bundled
  source at compile, see `crates/mvm-sdk/src/compile/strip_framework.rs`).
- For contributors working from a source checkout, prefer the editable
  install over the published package so the SDK always matches local
  HEAD. Published SDKs use the ordinary `mvmctl`; source checkouts can
  point `MVM_CLI_BIN` at a locally built `mvmctl`.
