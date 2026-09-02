---
title: Teardown is guest RAM reclamation at ~50ms/GB, and the PID-marker fix does not help
date: 2026-08-30
tags: [perf, teardown, hvf, supervisor, falsification]
---

`stop_pid_disappearance` scales linearly with guest RAM: 26ms at 256MiB, 34-40ms
at 512MiB, 96-106ms at 2GiB, 204-213ms at 4GiB — roughly **50ms per GB**. That
is the kernel reclaiming the guest's address space, not the supervisor doing
work.

The HVF supervisor writes its own shutdown record to
`<vm_state_dir>/shutdown-timing.json` (read it by racing the transient reaper).
It totals **~889µs at every guest size**: `watchdog_to_vcpu_exit=91µs`,
`watchdog_join=2µs`, `io_thread_join=19µs`, `vcpu_destroy=15µs`,
`vm_destroy=321µs`, `console_write=441µs`. The supervisor is not the cost and
making it faster cannot help.

## Do not retry the obvious fix

Ending the host's wait on the supervisor's PID-file marker instead of on process
exit buys nothing. A/B on one binary, both strategies, same guest size:

| guest | marker | process |
|---|---|---|
| 512MiB | 168-177ms | 178-204ms |
| 2048MiB | 402-479ms | 391-472ms |

The guest memory is released *before* the supervisor clears its marker, so both
strategies wait for the same thing. Attempted and reverted 2026-08-30.

A real fix has to move the marker removal ahead of the guest-memory drop
*inside* the supervisor, which changes its shutdown ordering and its durability
guarantees. That is a design change, not a tuning change.
