---
title: Core components
description: The moving parts that make up the secure sandbox product.
---

## CLI

`mvmctl` is the local operator interface. It builds, launches, inspects, pauses, resumes, snapshots, logs, forwards ports, and performs guest RPC operations.

See [Control surfaces](/architecture/control-surfaces/) for how the CLI relates
to SDKs, console access, and guest RPC.

## SDKs

Python and TypeScript expose current runtime and declaration surfaces. Rust exposes the lower-level typed Workload IR builder and lowering contracts.

## Builder VM

The builder VM keeps Linux-specific build work in a controlled Linux environment. It is shared across worktrees by design and should not be forked per feature branch.

## Runtime supervisor

The runtime supervisor admits plans, launches the backend, wires guest communication, records local audit, and handles lifecycle transitions.

## MicroVM backend

Backends are implementation slots. Product behavior should describe the lifecycle and security contract, then name backend-specific limitations when they matter.

## Guest agent

The guest agent handles controlled RPC operations such as process execution, filesystem operations, readiness probes, and telemetry where supported.
