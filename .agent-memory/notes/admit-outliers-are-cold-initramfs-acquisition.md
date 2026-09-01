---
title: Multi-second admit outliers are a cold initramfs fetch inside the admit window, not the audit chain
date: 2026-08-30
tags: [perf, admit, initramfs, cache, falsification]
---

A `machine run` reporting an `admit` phase of 74s / 138s / 144s / 72s against a
~25ms steady state is `attach_universal_initramfs_if_cached` acquiring the
universal initramfs on a cold cache — inside the admit window, emitting nothing
while it does. Measured 2026-08-30: `admit_plan=64.0ms attach_overlay=0.9ms
attach_initramfs=72350.7ms`. Warm, that span is 0.2-1.8ms.

The cache goes cold after a build that changes the embedded host binaries the
initramfs packages, and after a kernel pin bump wipes
`~/.mvm/cache/builder-vm/<arch>/kernels/`. That is where the misleading "it is
always the first run after a build" pattern comes from — the trigger is the
build, but the cost is the fetch.

## Refuted — do not re-test these

- **`F_FULLFSYNC` stalls.** 4-6ms idle, 3-8ms under six concurrent 900MB
  writers. Two to four orders of magnitude too small.
- **Audit leaf-cache miss / segment rotation.** ~100ms. Real, and there is a
  separate genuine admit cost in chain re-verification — do not conflate the
  two; neither is seconds.
- **macOS validating a freshly written binary on first exec.** 0.83s vs 0.11s
  warm. Real, and 166x too small to explain a 72s span.

`MVM_PHASE_TIMING=1` names these spans. Before that they existed only at
`tracing::debug`, so catching an outlier meant having `RUST_LOG=debug` attached
in advance — which is why this took as long to find as it did.
