---
title: "ADR-031: Cross-platform strategy — Linux native, macOS native, Windows Tauri-only"
status: Proposed
date: 2026-05-07
related: ADR-005 (libkrun pivot), plan 60-mvm-libkrun-migration, plan 53-cross-platform-roadmap
---

## Status

Proposed. CI matrix expansion lands in Phase 0; Windows Tauri path validated in Phase 5.

## Context

Three host classes need first-class support:

1. **Linux** — primary deploy target + dev environment. KVM available; Firecracker is the preferred backend.
2. **macOS** — dev environment (developers running mvm locally) + `mvm-studio` Tauri host. Hypervisor.framework available; libkrun via libkrun is the backend.
3. **Windows** — dev + `mvm-studio` Tauri host. Hyper-V / WHvPlatform is theoretically available, but libkrun/libkrun's native Windows support is unverified at the time of this ADR.

A naive "support all three at the CLI level" plan implies Windows-native builds of `mvmctl`, `mvm-hostd`, and the SDK. That commits us to a long-tail Windows-specific test surface for a small slice of users.

The user clarified the intent: **`mvm-studio` (Tauri) is the supported Windows surface**. The mvm/mvmd binaries can run inside the Tauri host's bundled environment (potentially WSL2-backed). Native Windows CLI is best-effort.

## Decision

| Platform | CLI support | SDK support | Backend | Notes |
|---|---|---|---|---|
| Linux x86_64 | first-class (release wheel) | first-class | Firecracker preferred; libkrun fallback | Production target |
| Linux aarch64 | first-class | first-class | Firecracker (where KVM available) | Production target |
| macOS arm64 (Apple Silicon) | first-class | first-class | libkrun (libkrun on Hypervisor.framework) | Dev + mvm-studio |
| macOS x86_64 | best-effort (no CI gating) | best-effort | libkrun | Apple is deprecating; we follow |
| Windows x86_64 | **Tauri-only** | first-class via `mvm-studio` | libkrun if available; WSL2-backed otherwise | mvm-studio bundles |

**Specifically**:
- Linux + macOS get full CI gating (build, test, lint, smoke).
- Windows CI gating covers: SDK builds (Python wheel, npm package), `mvmctl --version` smoke, but NOT live microVM integration tests.
- `mvm-studio` (sibling repo `../mvm-studio`) packages mvmd + mvm + libkrun in a Tauri shell. Windows users install one Tauri app, get the full UX.

## Consequences

**Positive**:
- Engineering effort scales with user value: Linux/macOS get the deepest investment.
- Windows gets a quality user experience (Tauri app) without subjecting the codebase to Windows-specific bug tail (registry quirks, path encodings, console-vs-GUI shenanigans).
- `mvm-studio` becomes the single test point for Windows correctness.

**Negative**:
- A Windows developer wanting a pure terminal CLI workflow gets best-effort, not first-class. Acceptable for our user base (AI-agent operators, primarily macOS/Linux).
- Tauri + libkrun + WSL2 stacking adds layers; if any one layer breaks, the user is far from the bug.

**Neutral**:
- The Rust core compiles on Windows (no `unix`-only deps in the workspace lints); we just don't gate CI on Windows-CLI integration tests.

## Alternatives considered

- **Windows first-class CLI**: rejected. Too much surface for too few users; would slow Linux/macOS work.
- **Drop Windows entirely**: rejected. Tauri gives us a Windows path at low marginal cost.
- **WSL2 as the "official" Windows path**: partially adopted — Tauri can use WSL2 internally where libkrun-native isn't available.

## Threat model impact

- The Tauri shell on Windows is itself an additional surface; threat-modeled separately in the `mvm-studio` repo.
- Windows-specific keystore (Credential Manager) is wired through the existing `keyring` crate; same `Keystore` trait, different OS impl.

## Compliance impact

- SOC 2: neutral — compliance happens at the deployment layer, not the dev OS.
- PCI/HIPAA: neutral — see above.
