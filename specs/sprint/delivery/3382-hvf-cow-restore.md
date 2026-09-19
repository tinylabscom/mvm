# Copy-on-write HVF restore from a verified private clone

An HVF snapshot frame used to carry the guest's whole RAM as a section, next to
the raw RAM file. A restore read that frame into the supervisor to reach a few
kilobytes of vCPU, GIC and device state, and the RAM it did map was opened by
path, separately from the open the checkpoint layer had hashed.

The frame now records where RAM sits in `memory.bin` (`RamLayout`: file offset,
length, page size). A restore refuses a range that is not aligned to the 16 KiB
hypervisor page, which the host page must divide, and refuses the old
inline-RAM format by name. Capture streams RAM from the live mapping and
publishes the frame by atomic rename after the RAM file is synced.

`restore_hvf_vm` clones `memory.bin` and the frame into the VM's state
directory, which must be owner-only and on a local filesystem. It opens each
clone read-only, removes its name, hashes it against the digest the checkpoint
recorded, and passes the supervisor only those two descriptors. The supervisor
refuses saved state named without descriptors, or a descriptor that still has a
name or is open for writing, and maps the RAM `MAP_PRIVATE` before the
reservation is registered with the hypervisor. The checkpoint layer leaves
those two digests to the restorer, so RAM is hashed once, on the bytes that are
mapped. An encrypted image is refused. On a filesystem that cannot clone, the
image is copied byte for byte on every restore and a warning is logged.

A restore is reported only after the supervisor writes `restore.ready`, which
it does once the saved state is adopted, mapped, validated and applied and its
vCPUs are released. A supervisor that refuses the state, exits early or never
reports ready fails the restore with its own stderr. Before, the pid file
appeared before any of that happened, so such a failure was reported as a
successful restore of a VM that was already gone.

## What the verification guarantees

The bytes mapped are the bytes verified, as against other users and against
later edits or replacement of the checkpoint. It is **not** a guarantee against
a process running as the same user. Such a process can open the clone for
writing in the few system calls between its creation and the removal of its
name — for the whole copy on a filesystem that cannot clone — and a
same-user loop that watches the directory wins that race often. This is out of
scope, not closed: the supervisor itself runs as the user, unsandboxed, and is
handed the path of the host signing key, so a same-user process (including a
compromised supervisor) can already rewrite a checkpoint before it is verified
or forge the chain entry for it. Sandboxing supervisors is plan item W5.7.

## Sharing and tenants

Restored guests share no memory pages at all: each restore maps its own clone.
That is stricter than W5.4 asked (sharing only within one tenant). A
restore or `vm_full` fork is also refused unless the restoring tenant matches the
tenant the checkpoint's creation entry was signed under. The recorded side is
authenticated. The restoring side is the tenant the caller says it runs as
(`MVM_TENANT` or the configured tenant), so this is a policy guard against
restoring into the wrong tenant, not an authenticated boundary. Warm-pool
claims are exempt: a pool parent is a factory boot that never ran a workload
and carries no plan, tenant, secrets or volumes.

## Teardown

Teardown used to zero every page `mincore` reported resident. For a restored
guest that is every page of the page-cache copy of its image, and writing to a
clean page of a private mapping copies it first — so stopping a restored guest
allocated a copy of its whole image just to zero it. On macOS it now zeroes a
file-backed page only if the guest wrote it (`MINCORE_COPIED` /
`MINCORE_ANONYMOUS`). Anonymous RAM is scrubbed as before.
Teardown tells the two kinds of page apart from the same file-backed range
record that free-page reporting (W4) uses to skip restored RAM
(`GuestRam::backing_regions`). This change first carried its own copy of that
record; when W4 landed first, it was dropped in favour of W4's.

## Measured (debug `just embed` builds, this Mac)

**Restore, `origin/main` vs this branch** (1-minute load 40–235; every run's
load is in the PR). Medians over the restores that completed. The wall-time
ranges overlap heavily at this load, so treat the medians as indicative only:

| guest RAM | tree | restores | wall time, median (range) | supervisor RSS when the command returned |
|---|---|---|---|---|
| 1 GiB | main | 9 | 41.4 s (27.6–99.2 s) | median 1042 MiB, transient |
| 1 GiB | branch | 9 | 21.2 s (16.3–90.2 s) | 18 MiB |
| 4 GiB | main | 0 of 6 | the command returned, but the supervisor was gone within 5 s | — |
| 4 GiB | branch | 9 | 77.9 s (47.5–165.6 s) | 20 MiB |

On `main` the ~1 GiB at return is transient. In 5 of the 9 1 GiB runs the
supervisor was back to 18–21 MiB five seconds later; in the other 4 it was still
about 1 GiB at that point. So the measured difference is the copy of RAM that
`main` holds during and just after a restore, not a steady-state figure. On `main`, a 4 GiB capture also failed 2 of 3 times ("hvf pause state
did not become resumed" after capture), and on this branch 3 of 3 captures succeeded.

**Stop of a restored guest, PR head before this teardown fix vs after**
(1-minute load 25–115). RSS was sampled every 50 ms, so the peak is a lower
bound. Before the fix every stop took 5.1–5.5 s — consistent with the 5 s
SIGTERM grace in `hvf_process.rs` expiring while the scrub was still running,
after which the supervisor is SIGKILLed:

| tree | guest RAM | run | load avg (1/5/15 min) just before | supervisor RSS 5 s after restore | peak supervisor RSS during stop | `machine stop` wall time |
|---|---|---|---|---|---|---|
| PR head | 1G | 1 | 29.39 25.56 34.04 | 19 MiB | 434 MiB | 5.28 s |
| PR head | 1G | 2 | 27.67 25.45 33.69 | 19 MiB | 347 MiB | 5.42 s |
| PR head | 1G | 3 | 30.66 26.39 33.70 | 19 MiB | 608 MiB | 5.26 s |
| PR head | 1G | 4 | 32.01 27.26 33.73 | 19 MiB | 917 MiB | 5.13 s |
| PR head | 1G | 5 | 26.67 26.41 33.19 | 19 MiB | 812 MiB | 5.26 s |
| this fix | 1G | 1 | 70.84 37.59 36.74 | 18 MiB | 18 MiB | 0.36 s |
| this fix | 1G | 2 | 74.64 43.68 39.06 | 18 MiB | 18 MiB | 0.25 s |
| this fix | 1G | 3 | 63.37 42.73 38.81 | 18 MiB | 18 MiB | 0.25 s |
| this fix | 1G | 4 | 48.16 40.79 38.22 | 19 MiB | 19 MiB | 0.25 s |
| this fix | 1G | 5 | 41.21 39.62 37.86 | 18 MiB | 18 MiB | 0.38 s |
| PR head | 4G | 1 | 54.80 43.35 39.39 | 19 MiB | 841 MiB | 5.25 s |
| PR head | 4G | 2 | 35.09 39.71 38.27 | 19 MiB | 872 MiB | 5.24 s |
| PR head | 4G | 3 | 24.82 36.16 37.06 | 19 MiB | 869 MiB | 5.24 s |
| PR head | 4G | 4 | 26.36 35.06 36.61 | 19 MiB | 474 MiB | 5.45 s |
| PR head | 4G | 5 | 36.21 35.92 36.77 | 19 MiB | 255 MiB | 5.52 s |
| this fix | 4G | 1 | 41.03 38.11 37.51 | 19 MiB | 19 MiB | 0.83 s |
| this fix | 4G | 2 | 114.90 75.08 52.86 | 19 MiB | 19 MiB | 0.58 s |
| this fix | 4G | 3 | 59.69 66.10 50.80 | 19 MiB | 19 MiB | 1.50 s |
| this fix | 4G | 4 | 49.68 62.04 50.15 | 19 MiB | 19 MiB | 0.71 s |
| this fix | 4G | 5 | 46.73 60.92 51.31 | 19 MiB | 19 MiB | 0.82 s |

Separately, every restore after a stopped restored run fails with `File exists`
unless `machine stop` is run a second time. That is already on `main` and is
not addressed here.

## Tests

- Layout encoding, alignment and refusal edges, including the 16 KiB granule
  against the host page.
- Verify-before-spawn, asserted with a spawner that counts launches.
- Supervisor refusals after the pid is published, never-ready timeouts, and the
  ready handshake.
- The mapped file is the unlinked clone, not the checkpoint, and an edit to the
  checkpoint between verification and mapping does not reach the guest.
- Teardown leaves a clean file mapping uncopied and still scrubs written pages.
- Refused inputs: symlinked sources, directories other users can write,
  non-local filesystems, encrypted images, named or writable inherited
  descriptors, a scope launcher that would drop the descriptors, and a named
  copy outliving its guard.
- Cross-tenant restore and fork refusals, and the signed chain reporting the
  creating tenant.
- The full CI gate list; the commands are in the PR.
