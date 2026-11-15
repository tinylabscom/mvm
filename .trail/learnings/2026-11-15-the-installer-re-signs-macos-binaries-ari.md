---
title: "The installer re-signs macOS binaries on purpose, so the post-install smoke compares them ignoring the signature"
author: Ari
date: 2026-11-15
branch: docs/trail-installer-resign
cost: { minutes: 60 }
id: l-7cd75916
scope: repo
status: active
src: agent
touches:
  - install.sh
  - scripts/published-installed-boot.py
---

## Decided
The installed-boot smoke accepts a macOS install that differs from the tarball only in its code signature. install.sh stays as it is: it re-signs on purpose, because a release that ships an entitlement profile is signed with it (a comment and a test say so).

## Tried and ruled out
Skipping the re-sign for an already-entitled binary: it reverses that decision, so it is a maintainer call. Stripping signatures with the codesign tool and hashing the rest: the two files still differ.

## Watch out
A re-signed file differs only in the signature blob and three header size fields; the smoke masks exactly those and keeps the exact check for everything else. On a prerelease GitHub turns a tilde in an asset name into a dot, so a lookup by the tilde name fails.

In the code:
- install.sh (sign_release, already_entitled)
- scripts/published-installed-boot.py (unsigned_macho_digest)
