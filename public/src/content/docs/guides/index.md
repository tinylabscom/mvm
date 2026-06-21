---
title: Guides
description: Conceptual and operational guides for building, securing, and operating mvm sandboxes.
---

Guides explain how a part of `mvm` works and what tradeoffs to make when
you wire it into a real workflow. Use tutorials when you want a linear
task walkthrough. Use guides when you need a durable operating model,
policy decision, or troubleshooting path.

## Guides vs tutorials

| Section | Best for | Shape |
| --- | --- | --- |
| [Tutorials](/tutorials/) | Completing one workflow end to end. | Step-by-step, task-focused, narrow scope. |
| Guides | Understanding and operating a capability. | Concepts, policies, limits, and production decisions. |
| [Reference](/reference/cli-commands/) | Looking up exact commands, flags, paths, and constraints. | Exhaustive facts, not narrative. |

## Core operating guides

| Guide | Use it when |
| --- | --- |
| [Builder VM](/guides/builder-vm/) | You need Linux builds from a secure builder boundary. |
| [Machine use cases](/guides/machine-use-cases/) | You want to choose the right `mvmctl machine` workflow before reading internals. |
| [Machine limitations](/guides/machine-limitations/) | You need the explicit limits for machine networking, volumes, SSH-agent forwarding, macOS, GPU, and architecture support. |
| [Building MicroVM Images](/guides/building-microvm-images/) | You need to turn a flake and manifest into a bootable image. |
| [Nix and OCI](/guides/nix-and-oci/) | You need the Nix-first model plus OCI compatibility rules. |
| [Policy Profiles](/guides/policy-profiles/) | You need repeatable security defaults for sandbox classes. |
| [Secrets and Credentials](/guides/secrets-and-credentials/) | You need to pass sensitive values without widening exposure. |
| [Network Egress Policy](/guides/network-egress-policy/) | You need explicit outbound network policy and auditability. |
| [Persistent Workspaces](/guides/persistent-workspaces/) | You need state that survives across sandbox sessions. |
| [Audit and Receipts](/guides/audit-and-receipts/) | You need evidence for what built, ran, changed, and exited. |

## Agent integration guides

Start with [AI Agent Integration](/guides/ai-agent-integration/) for the
system shape, then use [Agent Tool Contract](/guides/agent-tool-contract/)
for the model-facing request and response boundary. Keep tool calls
narrow: explicit files, explicit argv, explicit timeouts, explicit egress,
and explicit retention.
