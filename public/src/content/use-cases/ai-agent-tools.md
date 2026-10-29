---
title: Let AI agents use tools without handing them your host
description: Give an agent Linux tools inside a dedicated microVM, with explicit inputs and a deliberate network policy.
team: AI engineering
outcome: Contain agent tool execution
order: 1
guide: /examples/ai-agent-sandbox/
guideLabel: Build an AI agent sandbox
---

## The situation

Your team is building an assistant that writes scripts, inspects files, or calls command-line tools. A generated command should not inherit a developer’s home directory, credentials, and network access simply because the assistant runs on their laptop.

## A workflow with mvm

1. Define a pinned workload with only the packages the tool needs.
2. Validate the agent’s tool arguments before submitting work.
3. Run the tool in a microVM rather than in the application’s host process. Start without network access; allow only the endpoints the task needs.
4. Return bounded, redacted output to the model. Stop or destroy the guest when the task is finished.

For example, a support assistant could inspect an explicitly supplied diagnostic bundle and return a summary without receiving access to the rest of the support engineer’s workstation.

## What your team gains

The tool environment becomes a reviewable part of the application instead of an accidental extension of the host. You can reason about the packages, files, and access a task needs separately from the agent’s instructions.

## What to plan for

Isolation does not make model output trustworthy or prevent prompt injection. Validate tool inputs, keep mounts narrow, and redact output before it enters model context. Network restrictions and credential handling must be configured for the selected runtime; do not assume every backend provides the same guarantees.
