# Cloudflare Workers Static Assets migration

Backing: shipped-source
Validation: check-sprint-append

## Goal

Move the public Astro site from the legacy `mvm` Pages project to an assets-only
`mvm` Worker so deployments use Cloudflare's primary application platform and
gain Worker versions, rollbacks, observability, and future bindings without
putting static requests through unnecessary Worker code.

## Repository migration

- [x] Replace the Pages Wrangler output setting with a Worker Static Assets
      directory, explicit preview URLs, and the generated Astro 404 page.
- [x] Change local production, version-preview, and Cloudflare-preview commands
      from Pages commands to their Worker equivalents.
- [x] Rename and update the deployment workflow so it authenticates before the
      expensive build and deploys the `mvm` Worker from checked-in config.
- [x] Preserve the generated `_headers` policy and post-deployment wire check.
- [x] Reject builds that exceed the portable Worker Static Assets file-count or
      per-file-size limits, with positive and negative tests.
- [x] Update operator and contributor documentation without removing the old
      Pages deployment before the Worker is proven.

## Production rollout

- [x] Confirm `CLOUDFLARE_API_TOKEN` is account-scoped and has **Workers Scripts:
      Edit** permission before the first automated Worker deployment.
- [x] Deploy `mvm` from `main`, verify its `workers.dev` URL, representative
      documentation routes, the custom 404 page, and the browser WebLinux demo.
- [x] Inventory every custom domain on the old Pages project, attach each
      production hostname to the `mvm` Worker, and verify traffic, TLS, and
      COOP/COEP headers on `/` and `/demo/weblinux/`. The inventory found
      `runmvm.com` as the sole custom hostname on the Pages project.
- [ ] After a rollback window, remove the old `mvm` Pages project and delete the
      unused `runmvm` Worker only after confirming it has no domains, routes,
      bindings, secrets, or triggers.

## Security invariants

- Cloudflare credentials remain in GitHub Actions secrets or local OAuth
  storage and never enter repository files or workflow output.
- The API token is scoped to the deployment account and only the permissions
  needed to upload the Worker; route-edit permission is added only if CI owns
  domain attachment.
- Static assets bypass Worker code by default. Adding an entry point or
  `assets.run_worker_first` requires an explicit use case and review.
- Production cutover retains the Pages endpoint as a rollback target until the
  Worker has passed the live header and browser-demo checks.

## Rollout evidence

- The account-owned `mvm-deploy` token has Workers Scripts write access, and the
  post-merge workflow authenticated with it successfully.
- The `mvm` Worker serves both its `workers.dev` hostname and `runmvm.com`; the
  homepage, documentation, custom 404, and complete WebLinux asset set passed
  live checks, including the required COOP/COEP headers.
- The detached `mvm-8a8.pages.dev` project and the unused `runmvm` Worker remain
  available through the rollback window and are not production traffic targets.
