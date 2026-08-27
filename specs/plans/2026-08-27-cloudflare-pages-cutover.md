# Cloudflare Pages cutover

Backing: shipped-source
Validation: check-sprint-append

## Goal

Make the documentation site reproducibly deployable to the existing Cloudflare
Pages project with a repository-local Wrangler configuration, then move the
production hostname from GitHub Pages to that deployment.

## Tasks

- [x] Install and pin Wrangler in the Astro site workspace.
- [x] Download the existing `mvm` Pages configuration and declare `dist` as the
      Pages build output.
- [x] Pin the non-secret Cloudflare account ID so stale local Wrangler state
      cannot redirect commands to another account.
- [x] Add local production, preview-deployment, and Cloudflare-preview scripts.
- [x] Make the GitHub Pages workflow deploy from the checked-in Wrangler config.
- [x] Fail fast unless the GitHub repository secrets can access the `mvm` Pages
      project in their selected Cloudflare account.
- [x] Keep project creation out of deployment so an existing project does not
      produce an expected-failure annotation on every successful run.
- [x] Validate the site and publish a production-branch Pages deployment.
- [x] Verify the Pages deployment URL serves the required COOP/COEP headers.
- [x] Select the newest semantic boot-image release that actually contains the
      complete QEMU site pack rather than assuming the newest release has it.
- [x] Refuse deployment unless the built WebLinux shell, engine, compressed
      module, kernel, and root filesystem are all present and non-empty.
- [x] Use the same complete-bundle validator for local Wrangler commands and
      GitHub Actions, with positive and negative regression coverage.
- [ ] Attach `gomicrovm.com` to the `mvm` Pages project and verify the production
      hostname serves those headers instead of GitHub Pages.

## Security invariants

- Cloudflare credentials stay in local OAuth storage or GitHub Actions secrets;
  no token or account credential is committed.
- The checked-in configuration contains only non-secret project metadata.
- Production deployment retains the generated `_headers` policy and is verified
  over HTTPS after upload.
