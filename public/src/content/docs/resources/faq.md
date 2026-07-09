---
title: FAQ
description: Common questions about mvm, SDKs, Nix, OCI, and platform support.
---

## Is mvm local or hosted?

`mvm` is the local runtime substrate. These docs focus on local build, launch, SDK, and microVM lifecycle behavior.

## Is OCI the core runtime model?

No. OCI is a compatibility input. The core model is Nix-built microVM artifacts, signed plans, explicit policy, and audit records.

## Why is there a builder VM?

The builder VM provides a Linux execution boundary for Nix builds and microVM image assembly. It also keeps Linux-only tooling out of host-side cargo workflows.

## Does Windows support ship today?

Partially. Native Windows is still future work tracked by
[mvm#428](https://github.com/tinylabscom/mvm/issues/428), but WSL2 with nested
`/dev/kvm` is the supported Windows-adjacent workload path for the libkrun
backend.

## Which SDK should I use?

Use Python or TypeScript for the current high-level runtime/declaration surfaces. Use Rust for typed Workload IR generation and lower-level tooling.

## When should I use static decorators?

Use static decorators for deployable workloads when you want declarations compiled without importing user modules.

## When should I use runtime SDK scripts?

Use runtime SDK scripts when your application owns sandbox lifecycle. Remember that record/live mode executes host-side SDK code.
