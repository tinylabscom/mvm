# Runbook: release-signing GitHub Environments

Three CI jobs mint keyless (OIDC/Fulcio) cosign signatures whose
certificate SAN encodes the workflow ref that produced them. That ref
is exactly the identity `crates/mvm-core/src/release_trust.rs` checks
at verify time (`RELEASE_IDENTITY_TEMPLATES` /
`REVOCATION_IDENTITY_TEMPLATES`), so whoever can trigger the workflow
from an arbitrary ref can mint a trusted identity. Each job is gated
behind a GitHub **Environment** whose "Deployment branches and tags"
rule is the actual enforcement point — the `environment:` key in the
workflow YAML alone does nothing until the environment is configured.

## One-time setup (manual — Settings → Environments)

### 1. `release-signing`

- Repo → **Settings → Environments → New environment** → name
  `release-signing`.
- Under **Deployment branches and tags**, select **Selected branches
  and tags** and add a tag rule matching `v*`. This ensures the
  `release.yml@refs/tags/v…` SAN can only be minted from an actual
  version-tag push, never a branch or a `workflow_dispatch` run.
- Consumed by (`.github/workflows/release.yml`):
  - `builder-vm-image` — signs the attested builder pack manifest.
  - `default-microvm` — signs the attested runtime pack manifest.

### 2. `revocations-signing`

- **New environment** → name `revocations-signing`.
- Under **Deployment branches and tags**, add a tag rule matching
  `revocations` (the literal tag name, not a glob — this job only ever
  runs off that one tag).
- Do **not** reuse `release-signing` here: its tag rule (`v*`) would
  never match the `revocations` tag and would permanently block this
  job.
- Consumed by (`.github/workflows/revocations.yml`):
  - `publish` — signs the pack revocation list.

## Why this step can't be skipped

GitHub auto-creates an environment the first time a workflow
references it in an `environment:` key, but that auto-created
environment starts with **no protection rules at all** — any ref can
run the job and mint a signature under that identity until someone
visits Settings and adds the branch/tag restriction above. The
`environment:` line in the workflow is necessary but not sufficient;
these Settings steps are what actually constrain which ref can mint a
valid signing identity. Do them before the first real release/revocation
publish, not after.

## Verify

- Push a `v*` tag and confirm `builder-vm-image` / `default-microvm`
  wait on (or run under) the `release-signing` environment in the
  Actions run view.
- Force-push the `revocations` tag and confirm `publish` in
  `revocations.yml` runs under `revocations-signing`.
- A run attempted from a non-matching ref (e.g. `workflow_dispatch` on
  `main`, or a tag that doesn't match the rule) should be blocked by
  the environment before the job's steps execute.
