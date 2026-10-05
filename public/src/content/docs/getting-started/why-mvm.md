---
title: Why mvm
description: Why mvm uses hardware-isolated microVMs for AI agents and untrusted workloads.
---

`mvm` is for code you do not want to trust with the host kernel: AI agents,
customer code, build jobs, and code interpreters. It keeps the local developer
workflow of a sandbox while making a microVM—not a host process—the isolation
boundary.

## A different boundary

Process sandboxes restrict a program under the host kernel. Containers add
namespaces and resource isolation but still share that kernel. An mvm workload
boots with its own Linux kernel under a hardware hypervisor.

That boundary is paired with four rules:

1. **No guest network device.** Outbound traffic crosses vsock and is originated
   by the host after policy admits it.
2. **A signed execution plan.** Filesystem, network, secret, tool, and runtime
   grants are decided before launch instead of being inferred from prompt text.
3. **Host-held credentials.** A workload receives a placeholder; the host
   substitutes the real credential only on an admitted destination.
4. **An auditable result.** Admission and runtime decisions are written to the
   chain-signed audit log.

Read the [threat model](/security/threat-model/) and
[security claim ledger](/security/claim-ledger/) for the exact boundaries,
witnesses, and limitations behind these statements.

## What you can use today

- Run an OCI image in a transient microVM with
  `mvmctl machine run --image alpine -- uname -a`.
- Build reproducible workloads from Nix flakes or Python and TypeScript
  declarations.
- Drive transient and persistent machines from the CLI, Python, TypeScript, or
  Rust.
- Declare default-deny egress, host-held secrets, resource limits, and signed
  policy profiles.
- Inspect denials with `mvmctl why`, verify audit sessions, and bring selected
  workspace changes back through the reviewed apply path.

Start with the [shortest path for your workflow](/getting-started/happy-paths/)
or choose a [Python](/getting-started/python-quickstart/),
[TypeScript](/getting-started/nodejs-quickstart/), or
[Rust](/getting-started/rust-quickstart/) client.

## Active product work

The following items are active work, not promises about the current release:

- A shorter `mvmctl run <image-or-bundle> -- <command>` entry point is tracked
  in [#4041](https://github.com/tinylabscom/mvm/issues/4041).
- Self-contained Python wheels and per-platform npm packages are in
  [#4053](https://github.com/tinylabscom/mvm/pull/4053).
- Signed `.deb` and `.rpm` release packages are in
  [#4047](https://github.com/tinylabscom/mvm/pull/4047).
- Signed agent and runtime packs, registry discovery, and run-by-name are
  tracked in [#3716](https://github.com/tinylabscom/mvm/issues/3716).
- Interactive denial review and policy-draft generation are tracked in
  [#3714](https://github.com/tinylabscom/mvm/issues/3714).
- Tool-scoped routes, credentials, and command mediation are tracked in
  [#3723](https://github.com/tinylabscom/mvm/issues/3723).

The umbrella [agent-sandbox product-surface tracker
#3731](https://github.com/tinylabscom/mvm/issues/3731) records which parts are
complete and which still need a live witness. Security wins over compatibility:
when a backend cannot enforce a requested boundary, mvm should refuse rather
than silently weaken it.
