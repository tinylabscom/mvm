# Runbook: publishing the mvm SDKs (PyPI + npm)

Publishes the Python SDK (`sdks/python`, package **`mvm`**) and the
TypeScript SDK (`sdks/typescript`, package **`mvm-sdk`**) to PyPI and
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

### 1. Names — already claimed by Tinylabs

As of 2026-06-03 both projects exist and are owned by Tinylabs:

- PyPI **`mvm`** — latest `0.1.2` (history: 0.1.0, 0.1.1, 0.1.2).
- npm **`mvm-sdk`** — latest `0.1.2`.

So there's nothing to claim. Local is `0.14.0`, which is **not** on either
registry, so publishing it is a clean bump (no duplicate-version
rejection) that catches the registries up to the toolchain. Re-check
anytime:

```sh
curl -s https://pypi.org/pypi/mvm/json | python3 -c 'import sys,json;print(json.load(sys.stdin)["info"]["version"])'
curl -s https://registry.npmjs.org/mvm-sdk | python3 -c 'import sys,json;print(json.load(sys.stdin)["dist-tags"]["latest"])'
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

### 3. npm — automation token

- Create the package owner/org and a **granular automation token** with
  publish rights on `mvm-sdk` (npm → Access Tokens → Granular).
- Add it as repo secret **`NPM_TOKEN`** (Settings → Secrets → Actions).

## Rehearse (safe, no upload)

Run each workflow via **Actions → Run workflow** with `dry_run: true`:

- PyPI: builds sdist+wheel, runs the version guard, **skips upload**.
- npm: `npm ci && npm run build && npm publish --dry-run` (no upload).

Fix anything that fails here before a real release.

## Publish (real)

Publishing is tied to a GitHub Release so crates + PyPI + npm go out
together at one version:

1. Bump versions in the **same commit**:
   - `sdks/python/pyproject.toml` `version`
   - `sdks/typescript/package.json` `version`
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
   npm view mvm-sdk version
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
