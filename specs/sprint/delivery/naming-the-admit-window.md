# Naming the parts of the admit window

**Status: COMPLETE**

## What was wrong

`admit` was a coarse bucket with no named parts. `exec.rs` said so in a comment:

> `admit_ms` is a window, not a call: it spans config assembly, admission, and
> the two artifact attachments. Admission instruments itself, and its spans
> account for roughly half the window, so the rest needs naming before any of it
> can be acted on.

The consequence was a recurring outlier nobody could explain: five launches
across two days with an `admit` of 74s, 138s, 144s and worse, against a ~25ms
steady state, always on the first run after some change. Every phase-timing
report could say *how long* the window took and nothing about *where*. The
sub-spans that would have answered it existed only at `tracing::debug`, so
catching one meant having `RUST_LOG=debug` already attached to the run that
happened to be slow.

Three mechanisms were tested and refuted before the instrumentation landed, all
of them plausible and all of them wrong:

| hypothesis | measured | verdict |
|---|---|---|
| `F_FULLFSYNC` stalling under I/O | 4–6ms idle, 3–8ms under six concurrent 900MB writers | refuted |
| audit leaf-cache miss / segment rotation | ~100ms | refuted |
| macOS validating a freshly written binary on first exec | 0.83s vs 0.11s warm | real, 166x too small |

## What changed

Three sub-phases under `admit`, recorded where the window is assembled and
rendered by the existing report: `admit_plan`, `attach_overlay`,
`attach_initramfs`.

## What it found, immediately

The first launch after the change reproduced the outlier and named it:

```
admit=72415.7ms
admit_plan=64.0ms  attach_overlay=0.9ms  attach_initramfs=72350.7ms
```

`attach_universal_initramfs_if_cached` acquires the universal initramfs when
its cache is cold, inside the admit window, silently — 72 seconds of it. Warm,
the same span is 0.2–1.8ms.

That accounts for every occurrence. The cache goes cold exactly when the
observations said: after a build that changes the embedded host binaries the
initramfs packages, and after a kernel pin bump wipes the artifact cache. It was
never the audit chain, which is where three sessions of effort went.

The remaining honest gap: the function is named `..._if_cached` and its slow
path is an acquisition, so a reader has no reason to expect it to block. Moving
that acquisition out of `admit` into artifact resolution — where the kernel
download already announces itself with "Preparing the workload kernel…" — is the
follow-up this measurement argues for, and is not done here.

## A test that was passing for the wrong reason

`tree_reports_the_budget_as_context_and_never_as_a_verdict` asserts the tree
renders no verdict tokens, by substring. `attach overlay` contains "over", so it
failed the moment a real span was named that way.

The check was already broken and only looked correct: `mount cache lookup`
contains "ok", and escaped solely because that span is not populated in the
fixture. It now compares whole words.

## Not done: teardown

Teardown was root-caused and the fix was attempted, measured, and reverted.

The cause is real and worth recording. `stop_pid_disappearance` scales with
guest RAM — 26ms at 256MiB, 213ms at 4GiB on the pre-existing build, roughly
50ms per GB — while the supervisor's own shutdown record totals ~889µs at every
size:

```json
{"watchdog_to_vcpu_exit_micros":91,"watchdog_join_micros":2,"io_thread_join_micros":19,
 "vcpu_destroy_micros":15,"vm_destroy_micros":321,"console_write_micros":441}
```

So the wait is the kernel reclaiming the guest's address space, not the
supervisor doing anything.

The attempted fix ended the host's wait on the supervisor's PID-file marker
instead of on process exit, on the premise that reclamation happens after `main`
returns. An A/B on one binary, both strategies, same guest size, showed no
difference:

| | marker | process |
|---|---|---|
| 512MiB | 168–177ms | 178–204ms |
| 2048MiB | 402–479ms | 391–472ms |

The premise was wrong: the guest memory is released *before* the supervisor
clears its marker, so waiting on the marker is the same wait. The change was
reverted rather than kept for its story — it added a polling loop in place of an
event-driven wait and bought nothing.

A real fix has to move the marker removal ahead of the guest-memory drop inside
the supervisor, which is a change to its shutdown ordering and its durability
guarantees. Not attempted here.

## Also observed, not investigated

Teardown at 512MiB measured ~36ms on the older main and ~170–200ms on current
main, with the kernel pin at 6.12.107 and a differently-featured build. That is
a 5x shift, but the two measurements differ in more than one variable, so it is
an observation to chase rather than a regression to claim.
