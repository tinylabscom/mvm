---
title: mvm-hostd's `--lib` tests race on tracing's global max-level filter, and only the non-nextest lane sees it
date: 2026-09-02
tags: [flaky, tracing, mvm-hostd, ci, nextest, falsification]
---

`supervisor::audit_mirror::tests::mirror_event_carries_non_sensitive_envelope_fields`
failed on PR #3109 with `assertion left == right failed / left: 0 / right: 1` —
the capture layer saw no event at all. The PR deletes the virtio-fs device and
its FUSE server and touches nothing in the audit mirror, so it read as a
mysterious coupling.

**It is not a regression. It is a flaky test.** Re-running the identical job on
the identical commit (`gh run rerun 33653066182 --job 100324800583`) came back
`success` with nothing else changed. Do not spend time bisecting a PR against
it.

## Why it can fail

`crates/mvm-hostd` has 121 `tracing::subscriber::with_default` call sites. The
`Dispatch` that installs is thread-local, but the max-level filter that
`tracing::info!` consults before it ever reaches a subscriber is a **process-global
atomic**, updated when a dispatcher is installed and restored when its scope
ends. `cargo test --lib` runs tests as threads in one process, so one test
leaving its `with_default` scope can lower the global filter while another is
mid-event, and the event is dropped before any layer sees it. Zero captured
events, no error, no panic in the code under test.

This is consistent with the observed failure and with the re-run passing, but it
was not proven by instrumenting the race — the empirical fact is the re-run, and
the mechanism is the best available reading of it.

## Why CI mostly does not see it

CLAUDE.md's named gate is `cargo nextest run --workspace`, which runs each test
in **its own process**. There is no shared global to race on, so nextest cannot
reproduce this no matter how many times it runs.

The lane that does hit it is the `Test eBPF telemetry load/attach` job, which
runs `cargo test -p mvm-hostd --lib`. That is the only place in CI where these
121 call sites share an address space. A green nextest run is therefore not
evidence that this class of flake is absent.

## What not to do

Do not "fix" it by asserting more loosely, and do not add a retry. Both hide a
real property: any test in this crate that asserts on captured `tracing` output
is unreliable under a threaded harness. If it becomes disruptive, the fix is
either to give the affected tests their own process (a nextest group) or to stop
asserting through the global filter — capture at the layer without relying on
`with_default` raising the process-wide max level.
