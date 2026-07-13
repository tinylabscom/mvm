---
title: LLM documentation index
description: A compact, LLM-friendly index of the mvm docs structure and high-signal pages.
template: doc
---

# mvm Documentation Index

`mvm` is a security-first local microVM runtime for building and running sandboxed workloads with signed plans, audited launches, and backend-specific snapshot recovery.

## Getting Started

- [Installation](/getting-started/installation/): install the CLI and prerequisites.
- [Quick Start](/getting-started/quickstart/): first local run.
- [Python quickstart](/getting-started/python-quickstart/): current Python SDK runtime and declaration paths.
- [Node.js quickstart](/getting-started/nodejs-quickstart/): current TypeScript SDK runtime and declaration paths.
- [Core concepts](/getting-started/core-concepts/): runtime, builder VM, Workload IR, plans, policy, and cold mode.
- [Design principles](/getting-started/design-principles/): security-first DX principles.
- [Builder VM](/guides/builder-vm/): host command, Linux build boundary, persistent builder personas.
- [Nix and OCI](/guides/nix-and-oci/): Nix-first auditability and OCI compatibility.
- [Policy profiles](/guides/policy-profiles/): restrictive, standard, dev, permissive, host-share, env, and seccomp posture.
- [Secrets and credentials](/guides/secrets-and-credentials/): reference-first credential delivery, grants, redaction, and retention rules.
- [Persistent workspaces](/guides/persistent-workspaces/): encrypted volumes, host-backed mounts, copy workflows, snapshots, and cleanup policy.
- [Audit and receipts](/guides/audit-and-receipts/): signed run receipts, audit chain checks, metrics, and boot reports.
- [Observability and results](/guides/observability-and-results/): result correlation, logs, receipts, audit IDs, boot reports, metrics, and redaction rules.
- [Network egress policy](/guides/network-egress-policy/): deny-first outbound grants for agents, services, package installs, and browser automation.
- [Agent tool contract](/guides/agent-tool-contract/): model-facing sandbox request/response schema, validation, redaction, and retention rules.

## SDK

- [SDK overview](/sdk/): runtime lifecycle API versus decorator declaration API.
- [Runtime SDK](/sdk/runtime/): imperative lifecycle surface.
- [Runtime modes](/sdk/runtime-modes/): record, plan, live, and static declaration execution modes.
- [SDK security model](/sdk/security-model/): host execution, guest execution, secrets, network, audit, and state retention.
- [Operations cookbook](/sdk/operations-cookbook/): current SDK calls, target helpers, and secure CLI fallbacks.
- [Decorator SDK](/sdk/decorator/): static workload declaration and Workload IR.
- [Declaration workflow](/sdk/declaration-workflow/): compile declarations, IR JSON, and runtime recordings into build artifacts.
- [Declaration cookbook](/sdk/declaration-cookbook/): concrete Python and TypeScript declaration patterns for secure Nix-first workloads.
- [Sandbox types](/sdk/sandbox-types/): general, code, browser, desktop, and builder sandbox patterns.
- [Lifecycle matrix](/sdk/lifecycle-matrix/): current CLI support, current SDK support, and runtime parity targets.
- [Errors & metrics](/sdk/errors-metrics/): SDK result, error, metrics, and audit correlation targets.
- [SDK reference](/sdk/reference/): language SDK status and parity target.
- [Python SDK](/sdk/python/): current and planned Python surface.
- [Node.js SDK](/sdk/nodejs/): current and planned TypeScript surface.

## Tutorials

- [Tutorials overview](/tutorials/): workflow map.
- [Agent sandbox](/tutorials/agent-sandbox/): run generated or third-party code.
- [Coding agent](/tutorials/coding-agent/): run coding-agent tasks with explicit filesystem, network, and persistence boundaries.
- [Code execution](/tutorials/code-execution/): execute commands and scripts.
- [File transfer](/tutorials/file-transfer/): upload and download files.
- [LLM tool integration](/tutorials/llm-tool-integration/): tool-loop sandboxing.
- [Browser automation](/tutorials/browser-automation/): browser sessions in microVMs.
- [Desktop automation](/tutorials/desktop-automation/): sensitive state and credential boundaries.
- [Interactive terminal](/tutorials/interactive-terminal/): debug access without making SSH the default path.
- [Any language](/tutorials/any-language/): language-agnostic guest workloads.
- [Services and ports](/tutorials/services-and-ports/): expose explicit ports.
- [Long-running services](/tutorials/long-running-services/): readiness, ports, logs, lifecycle, and policy.
- [Error handling](/tutorials/error-handling/): build, admission, runtime, file, network, and restore failures.
- [Cold-mode recovery](/tutorials/cold-mode-recovery/): pause, save, restore, wake.

## Architecture

- [Architecture overview](/architecture/overview/): local runtime flow.
- [Lifecycle states](/working/lifecycle-states/): running, stopped, paused, cold, restoring, and cleaned sandbox states.
- [Core components](/architecture/core-components/): CLI, SDKs, builder VM, supervisor, backend, and guest agent.
- [Control surfaces](/architecture/control-surfaces/): CLI, SDK, MCP, console, guest RPC, and not-claimed management surfaces.
- [Security and isolation](/architecture/security-isolation/): build, launch, runtime, policy, audit, and SDK boundaries.
- [Networking and storage](/architecture/networking-storage/): egress, ports, files, volumes, and snapshots.
- [Architecture reference](/reference/architecture/): crates, backends, builder VM, supervisor layers.
- [Platform support](/reference/platform-support/): host, backend, architecture, and support status matrix.
- [Guest agent](/reference/guest-agent/): guest protocol and readiness.

## Security

- [Security claim ledger](/security/claim-ledger/): docs-facing claim status.
- [Sandbox parity status](/security/sandbox-parity-status/): gated parity claims.
- [Matryoshka model](/security/matryoshka/): isolation tier model.
- [Threat model](/security/threat-model/): threat boundaries.
- [Verified boot](/security/verified-boot/): rootfs integrity posture.

## Platform

- Linux execution and macOS are current local targets.
- Native Windows is future work tracked in [mvm#428](https://github.com/tinylabscom/mvm/issues/428). WSL2 with nested `/dev/kvm` is the supported Windows-adjacent libkrun workload path.

## Claim Rules

- Strong claims need Shipped/Preview/Planned/Not claimed status.
- Runtime SDK lifecycle APIs are Partial until shared SDK tests cover the full lifecycle.
- Persistent builder DX is Preview until top-level `bootstrap` and `build` behavior is proven.
- OCI examples should use digest-pinned or clearly local/dev references.
- Secret examples should use references or redacted example values, not plaintext credentials.
