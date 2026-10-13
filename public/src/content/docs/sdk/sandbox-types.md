---
title: Sandbox types
description: Product-level sandbox patterns and their current mvm implementation status.
---

`mvm` exposes one secure runtime substrate: a built artifact booted in a
microVM with explicit policy, audit, and lifecycle state. Product-facing SDKs
can layer specialized helpers over that substrate.

`mvmctl machine fs` (below) is a hidden advanced verb: it works, but it does not
appear in `mvmctl machine --help`.

## Type matrix

| Type | Best for | Current path | SDK status |
| --- | --- | --- | --- |
| General sandbox | Commands, files, services, long-running work. | `mvmctl machine build`, `mvmctl machine run`, `mvmctl machine exec`, `mvmctl machine fs`, `mvmctl machine logs`. | Partial Python/TypeScript runtime surface. |
| Code sandbox | Short code execution and interpreter-style tools. | `mvmctl run -- <cmd>`, a named Python manifest, or the `CodeSandbox` helper. | `CodeSandbox` ships in Python and TypeScript. |
| Browser sandbox | Browser automation with Playwright/Puppeteer-like tooling. | Build a browser-capable Nix image, run automation inside the guest, declare any needed ports at boot, or use the `BrowserSandbox` helper. | `BrowserSandbox` ships in Python and TypeScript. |
| Desktop sandbox | GUI or computer-use workflows. | Backend- and image-specific today; use explicit images and port/console access. | Planned high-level helper. |
| Builder sandbox | Secure Linux image construction. | Project builder VM and persistent builder controls. | CLI-first today. |

## General sandbox

Use this for the broad lifecycle:

```sh
mvmctl init ./worker --preset python
mvmctl machine build --flake ./worker
mvmctl machine run --flake ./worker --name worker -d
mvmctl machine exec worker -- python /work/task.py
```

Security properties:

- guest code runs in a microVM backend where supported;
- host files enter only through explicit transfer, mounts, or build inputs;
- network exposure is explicit, and ingress ports are declared before boot;
- audit records connect build, admission, launch, and lifecycle operations.

## Code sandbox

Use one-shot execution when state should not persist:

```sh
mvmctl run --timeout 10 -- python -c 'print(2 + 2)'
```

Use a named sandbox when state is intentional:

```sh
mvmctl machine run --flake ./python-tool --name pytool -d
mvmctl machine exec pytool -- python /work/cell.py
```

Security requirements for SDK helpers:

- bounded input size;
- timeout required or defaulted;
- output capture bounded and redacted before model use;
- no implicit network or secrets.

## Browser sandbox

Browser automation needs more policy than a normal command:

- browser packages declared in the Nix image;
- target domains allowed explicitly;
- downloads treated as untrusted files;
- cookies, profiles, cache, local storage, and screenshots treated as sensitive state;
- snapshots used only when retaining browser state is intentional.

See [Browser automation](/tutorials/browser-automation/).

## Desktop sandbox

Desktop or computer-use workflows need a display server, input events, and a
viewing/control channel. Keep these workflows development- or task-scoped until
the high-level SDK helper has explicit policy and tests.

Security requirements:

- no host desktop sharing by default;
- credentials injected only through reviewed paths;
- downloads and clipboard content treated as sensitive;
- remote viewing exposed only through explicit ports or endpoints.

See [Desktop automation](/tutorials/desktop-automation/).

## Builder sandbox

The builder VM is not the runtime guest. It is the controlled Linux boundary for
Nix evaluation, image builds, and microVM-specific tooling. Runtime guests boot
the resulting artifacts.

See [Builder VM](/guides/builder-vm/).

## Related pages

- [Lifecycle matrix](/sdk/lifecycle-matrix/)
- [Runtime SDK](/sdk/runtime/)
- [Policy profiles](/guides/policy-profiles/)
