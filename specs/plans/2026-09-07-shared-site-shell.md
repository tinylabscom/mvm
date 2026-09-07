# Shared website shell

Backing: shipped-source
Validation: check-sprint-append

**Status: IMPLEMENTATION COMPLETE — PR REVIEW PENDING**
**Last updated: 2026-09-07**
**Branch:** `fix/shared-site-shell`

## Goal

Use the homepage header consistently across the public blog and pricing routes,
make the blog discoverable from the shared navigation, and render homepage
content immediately without the scroll-triggered reveal effect.

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
