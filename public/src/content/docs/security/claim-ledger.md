---
title: Security claim ledger
description: The public index of security and DX claims, their status, and the evidence needed before docs may rely on them.
---

This ledger is the docs-facing rule for strong claims. A page can describe a behavior as a product guarantee only when the relevant row is Shipped and links to implementation evidence.

For sandbox-parity claims, the detailed status table lives in [Sandbox parity status](/security/sandbox-parity-status/). This page adds the docs relaunch-specific claims around `mvm`, SDKs, Nix, OCI, and tutorials.

## Claim table

| Claim | Status | Evidence required before stronger language |
| --- | --- | --- |
| `mvm-runtime-boundary` | Shipped | Architecture docs and code paths show local runtime ownership of backend launch, guest protocol, builder VM dispatch, signed plan admission, and local audit. |
| `decorator-sdk-static-compile` | Preview | Static compile docs and tests prove declarations can emit Workload IR without importing user modules for supported syntax. |
| `runtime-sdk-lifecycle` | Planned | Python, TypeScript, and Rust lifecycle APIs pass shared create/exec/files/logs/snapshot/stop tests. |
| `secure-sandbox-product-parity` | Planned | [Plan 114](https://github.com/tinylabscom/mvm/blob/main/specs/plans/114-secure-sandbox-product-parity.md) tracks parity capability by capability without copying another product's runtime architecture. |
| `builder-vm-secure-builds` | Shipped | [Builder VM](/guides/builder-vm/) documents host-orchestrated Linux builds; source-checkout cache reuse and bootstrap policy are covered by current CLI behavior. |
| `persistent-builder-dx` | Preview | Low-level `persistent-builder` controls and build routing exist; top-level `cargo run -- dev up` and `cargo run -- build` docs must match the actual command behavior before this becomes Shipped. |
| `cold-mode-snapshot-recovery` | Preview | Recovery is an explicit backend capability matrix: machine-state save/restore is advertised by HVF and `apple-container` and by no other selectable runner, live-memory restore is advertised only by the test-support mock, the raw libkrun substrate's disk-only/standby primitives are not exposed by its selectable runner, and unsupported requests fail closed. Docs must name backend support and restore semantics. |
| `platform-linux-macos` | Shipped | Local docs name Linux execution and macOS as the supported targets and keep Windows in the future/issue-tracked bucket. |
| `platform-windows` | Planned | Windows docs link [mvm#428](https://github.com/tinylabscom/mvm/issues/428) and avoid implying shipped local runtime support. |
| `nix-first-auditability` | Preview | Builder VM docs, flake pinning docs, artifact provenance, and signed plan admission are linked from the guide. |
| `oci-compatibility` | Preview | OCI pull/materialization commands, digest verification, mutable-tag policy, cache isolation, and audit events are documented and tested. |
| `secure-agent-tutorials` | Planned | Agent, LLM, browser, file, and service tutorials name network, secret, filesystem, persistence, and audit boundaries. |

## Docs rules

- If a claim is Planned, examples may describe the intended shape but must label it Planned.
- If a claim is Preview, examples must name backend, platform, or feature limitations.
- If a claim is Shipped, examples must link to CLI, SDK, test, or ADR evidence.
- Pages should avoid broad security language when a narrower statement is more accurate.

## High-risk phrases

The docs lint already gates a small set of high-risk phrases for OCI, secret, and latency claims. New pages should avoid introducing equivalent language without adding a gate.

Examples of safer wording:

| Avoid | Prefer |
| --- | --- |
| "Run every registry image without limits" | "Run supported OCI inputs after digest resolution and verification." |
| "Secrets are impossible to leak" | "Secret references are designed to keep plaintext out of default guest-facing paths when the managed-ref flow ships." |
| "Instant boot" | "Measured boot and readiness numbers are published per backend and artifact." |

## Required link targets

Tutorials and SDK pages should link to at least one of:

- [Sandbox parity status](/security/sandbox-parity-status/)
- [CI-enforced security claims](/security/ci-claims/)
- [Threat model](/security/threat-model/)
