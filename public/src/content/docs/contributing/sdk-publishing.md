---
title: Configure SDK publishing
description: Configure the mvm PyPI Trusted Publisher and protect release approvals.
---

The Python project on PyPI is **mvm**. Its upload job belongs to the top-level
`.github/workflows/publish-sdk.yml` workflow. The reusable
`publish-pypi.yml` workflow only builds, inspects, and smoke-tests distributions;
it does not request a PyPI token or upload them.

## Configure GitHub first

In `tinylabscom/mvm`, open **Settings → Environments → pypi**.

1. Add a trusted maintainer or team under **Required reviewers** and enable
   **Prevent self-review** where available.
2. Under **Deployment branches and tags**, select **Selected branches and tags**.
   Add a **tag** rule for `sdk-v*`; do not add a branch rule for this release
   environment.
3. Protect creation and changes of SDK release tags using repository rulesets.
   Environment approval is not a substitute for controlling which commits can
   become release tags.

The environment name must remain exactly `pypi`. Do not store a PyPI API token
in it: this workflow uses GitHub OIDC and a short-lived PyPI credential.
These are administrator settings, not settings applied by checking out the code.

## Register the existing project on PyPI

Sign in to PyPI using an account with owner access to `mvm`.

1. Open [Your projects](https://pypi.org/manage/projects/).
2. Select **Manage** beside **mvm**, then **Publishing** in the project sidebar.
3. Add a **GitHub Actions** Trusted Publisher with these exact values:

   | Field | Value |
   |---|---|
   | Owner | `tinylabscom` |
   | Repository name | `mvm` |
   | Workflow name | `publish-sdk.yml` |
   | Environment name | `pypi` |

   “Workflow name” means the **filename**, not the workflow's display title
   (`Publish SDKs`) and not the full `.github/workflows/` path.

4. Click **Add** and confirm the entry appears in the project's publisher list.
5. Retire the obsolete `publish-pypi.yml` publisher once the reviewed workflow
   migration is deployed and that old publishing path is no longer needed.
   Adding the new entry does not automatically remove the old authorization.

Use the existing project's Publishing page, not the account-level pending
publisher form intended to create a new project. Adding a publisher does not
upload a package or change an existing release.

See PyPI's [publisher setup instructions](https://docs.pypi.org/trusted-publishers/adding-a-publisher/)
and [reusable-workflow restriction](https://docs.pypi.org/trusted-publishers/troubleshooting/#reusable-workflows-on-github).
The top-level SDK workflow deliberately has no `workflow_call` trigger.

## Validate before publishing

Land the reviewed workflow change before creating a release tag from it.
Run **Actions → Publish SDKs → Run workflow** on a branch with `dry_run=true`
to validate SDK builds, artifact handoffs, package checks, and smoke tests.
That rehearsal intentionally skips PyPI upload and does **not** validate token
exchange or the registered Trusted Publisher.

For a separately approved release:

1. Follow the repository's SDK version/compatibility preparation process.
   The SDK version is declared in `crates/mvm-sdk/sdks/release.toml`; it is
   distinct from the CLI version.
2. Publish a GitHub Release for the corresponding `sdk-v` version tag on the
   reviewed commit. This triggers real SDK publication, including the npm
   release path; do not use it as an authentication experiment.
3. Wait for preflight, BDD, and Python distribution builds to succeed.
4. Review the commit, version, package evidence, and target environment before
   approving the `pypi` deployment.
5. Confirm the upload and subsequent registry checks succeed. Inspect the new
   release's PyPI provenance for `tinylabscom/mvm`, `publish-sdk.yml`, and `pypi`.

PyPI package uploads are not a reversible test operation. If token exchange
fails with `invalid-publisher`, compare the four registration values above
against the workflow and environment; do not fall back to a long-lived token
or weaken approval rules to get the release through.
