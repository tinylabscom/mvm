---
title: A "legacy" grep is a claim to verify, not a finding — four of six families were live code with a wrong comment
date: 2026-08-27
tags: [refactor, dead-code, docs-drift, falsification]
---

A full "remove all legacy" sweep on 2026-08-27 found six families. **Two were
real.**

Real:

- `RuntimeSourcePolicy` — staged-rollout scaffolding whose own doc said it
  changed "no backend behavior yet", with `RootfsOnly` as `#[default]`. It
  caused the launch failure that started the sweep.
- The per-rootfs verity initramfs — genuinely superseded by the universal one.

Mislabelled — live code carrying a wrong comment:

- `BuilderRoute::LegacyShell` — its only generic-dispatch site called
  `resolve_route(false, ..)` with `daemon_reachable` a hardcoded literal, so the
  "decision" had exactly one reachable answer. The shell-job channel it names is
  still the **only** channel for a generic builder job.
- `driver/{hvf,libkrun,qemu}_legacy.rs` — 55 live references, and `qemu.rs`
  calls `qemu_legacy::locate_qemu()` on every boot. Renamed to `*_process`.
- Six of ten "back-compat shims" were `#[serde(default)]` on new optional
  fields — the pattern CLAUDE.md **mandates**. Removing them would have added
  exactly the ceremony that rule exists to prevent.
- `template_list_legacy_names` claimed to power a migration banner and a
  `template list --legacy` flag. Neither exists anywhere in the CLI.

## How to apply

Treat a `legacy` / `back-compat` hit as a claim to verify: does the code have a
live caller, and does the comment match what it does? Where the code is fine,
**fix the comment and say why** — otherwise the next sweep re-flags it.
Deleting working code to satisfy a keyword search is the failure mode here.

Same shape as [[a-citation-can-resolve-to-its-own-test-fixture]]: prose
describing something that nothing implements.
