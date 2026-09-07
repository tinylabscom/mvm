# Shared website shell

Backing: shipped-source
Validation: check-sprint-append

**Status: IMPLEMENTATION COMPLETE — PR REVIEW PENDING**
**Last updated: 2026-09-07**
**Branch:** `fix/site-spacing-doc-loader`

## Goal

Use the homepage header consistently across the public blog and pricing routes,
make the blog discoverable from the shared navigation, and render homepage
content immediately without the scroll-triggered reveal effect. Keep every
non-doc route on the same responsive content gutter, and keep docs development
free of stale content-loader and invalid code-fence warnings.

This UI-only workstream intentionally excludes the separate deny-all article,
which remains private under its own release review.

## Work

- [x] Add Blog to the shared desktop and mobile navigation.
- [x] Render the shared header component from the blog layout.
- [x] Convert pricing from a standalone HTML response to an Astro page using
      the shared header while preserving its content and interactions.
- [x] Remove the homepage content-reveal observer and hidden-state CSS.
- [x] Add CI-wired regressions for navigation, shared-shell reuse, and immediate
      homepage rendering.
- [x] Run the complete website check and production static build.
- [x] Deploy website source changes automatically after they merge to `main`,
      while preserving release, tag, and manual deployment triggers.
- [x] Give the homepage, blog, architecture, and pricing routes one shared
      72rem content width with 1.5rem/2rem responsive gutters; leave docs on
      Starlight's independent content sizing.
- [x] Clear only Astro's generated content data store before `docs-dev` so a
      stale cache cannot emit duplicate IDs.
- [x] Use renderer-valid `rust ignore` fence metadata while preserving the
      conformance compiler's explicit opt-out contract.
- [x] Add regressions for the public-page gutter, targeted cache cleanup,
      Markdown fence metadata, and whitespace-separated conformance attributes.
- [x] Verify the website build and exact `docs-dev` startup, plus desktop and
      mobile browser geometry across every non-doc route.
