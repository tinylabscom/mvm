# Publish both SDK sidecar libc variants

Backing: shipped-source
Validation: check-sprint-append

## Goal

Publish distinct glibc and musl SDK sidecar archives for every supported
architecture, and make the downloader select the archive whose filename binds
the requested libc.

## Checklist

- [x] Qualify SDK sidecar release names by architecture and libc.
- [x] Build and upload glibc and musl sidecars for aarch64 and x86_64.
- [x] Remove the single-published-libc assumption from the downloader.
- [x] Make both release trains require, attach, sign, and consume both variants.
- [x] Add positive musl acquisition, unknown-libc refusal, release-matrix, and
      asset-name regressions.
- [x] Complete workspace, Clippy, gated-target, formatting, and policy
      validation.
- [ ] Merge the repair through the queue and close issue #3045.
