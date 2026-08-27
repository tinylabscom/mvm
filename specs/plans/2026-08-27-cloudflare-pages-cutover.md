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
- [x] Add local production, preview-deployment, and Cloudflare-preview scripts.
- [x] Make the GitHub Pages workflow deploy from the checked-in Wrangler config.
- [x] Fail fast unless the GitHub repository secrets can access the `mvm` Pages
      project in their selected Cloudflare account.
- [x] Validate the site and publish a production-branch Pages deployment.
- [x] Verify the Pages deployment URL serves the required COOP/COEP headers.
- [x] Select the newest semantic boot-image release that actually contains the
      complete QEMU site pack rather than assuming the newest release has it.
- [ ] Attach `gomicrovm.com` to the `mvm` Pages project and verify the production
      hostname serves those headers instead of GitHub Pages.

## Security invariants

- Cloudflare credentials stay in local OAuth storage or GitHub Actions secrets;
  no token or account credential is committed.
- The checked-in configuration contains only non-secret project metadata.
- Production deployment retains the generated `_headers` policy and is verified
  over HTTPS after upload.
