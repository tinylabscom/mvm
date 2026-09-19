# 3385 — guest disk flush cost on HVF, measured and then cut

The in-house virtio-blk device served every guest `VIRTIO_BLK_T_FLUSH` with
`File::sync_data`. On Apple hosts std implements that as `fcntl(F_FULLFSYNC)`,
which also empties the drive's write cache. A 4 KiB write followed by
`F_FULLFSYNC` measured p50 4.9–5.7 ms on this host; with `fsync(2)` it measured
p50 0.03–0.04 ms.

## What the measurement found

Measured on macOS 26 Apple Silicon under host load 250–320, with an isolated
`MVM_HOME` and `alpine:3.20` workloads. The HVF supervisor was temporarily
instrumented to count requests per disk, and a temporary switch changed how
flushes were served. None of that code ships.

- **A cold workload boot sends no flushes.** Every disk the HVF workload runner
  attaches is read-only (`workload_blocks` in `crates/mvm-vmm/src/host/spec_map.rs`),
  and a read-only disk does not offer flush. Over 6 boots, all 24 disk lifetimes
  recorded zero writes and zero flushes.
- **A guest that fsyncs often on a writable volume paid for it.** 500 ×
  (4 KiB write + fsync) on a `--volume img:/work:1G:rw` disk sent 502 flushes.
  The medians over N=5 were:

  | flush served by | time in flushes | guest workload |
  | --- | --- | --- |
  | `F_FULLFSYNC` | 3.1 s | 5.1 s |
  | `fsync(2)` | 0.12 s | 2.6 s |
  | no-op | — | 2.0 s |

- Bulk writes (18 flushes, 0.21 s) and an untar of 5000 files plus `sync` (3
  flushes, 0.05 s) were lost in load noise.
- One builder VM build sent 654 flushes to the nix-store disk, 11.7 s in total
  over a 32-minute run, with the slowest single flush taking 545 ms. The
  device serves requests inside the MMIO exit, under the shared device-bus
  lock, so a flush that slow stalls device access for every vCPU.
- Scratch disks already cost nothing. An ephemeral disk is served from RAM,
  where flush is a no-op, and the builder's per-job output disk sent zero
  flushes.

## The change

`crates/mvm-vmm/src/vmm/virtio.rs`, virtio-blk only:

- A guest flush on a writable file-backed disk calls
  `guest_flush_to_host_storage`. On Apple hosts that is `fsync(2)`: the data
  reaches the drive, but the drive's cache is not emptied. On every other host
  it is `sync_data`, which is `fdatasync` there and already the cheap operation.
  The platform split lives in that one function.
- The full flush (`sync_data`) runs once, when a writable file-backed image
  that took any write or discard is dropped. It is Drop and not a method the
  supervisor calls, because every way a VM ends releases its devices: guest
  power-off, stop signal, timeout, and a failed run. A call site could be
  missed; Drop cannot. A disk that was never written is released without the
  flush.
- A failed release flush is written to the supervisor's stderr, and teardown
  carries on. By then the bytes are already in the host's storage stack, and a
  VM that cannot stop is worse than one whose last writes have not yet left the
  drive cache. The flush is one synchronous call per disk and has no timeout.
- The two sync operations sit behind a small `DiskSync` pair of function
  pointers, so tests can count which one ran.

Checkpoint and snapshot need no flush. HVF full-VM capture already refuses a VM
with any writable disk (`ensure_every_disk_is_restorable` in
`crates/mvm-backends/src/driver/hvf.rs`). Nothing tested that refusal before;
now a test pins it: a writable disk is refused before any snapshot request is
written, and an all-read-only VM is admitted. This test stands in for "a
checkpoint captured right after writes verifies after restore", because on HVF
no such checkpoint can exist.

The new durability trade is documented in
`public/src/content/docs/guides/machine-limitations.md`. On an HVF volume, a
guest fsync survives a guest or VMM crash. It does not survive a host power
loss or kernel panic before the VM stops.

## Before and after

Both supervisor builds were run in the same session, interleaved with each
other via `MVM_HVF_SUPERVISOR_PATH`, in two batches of 5. Figures are medians
[min–max] over N=10:

| | before | after |
| --- | --- | --- |
| 500 × fsync, guest workload | 6430 ms [4460–9200] | 2210 ms [1140–7190] |
| same, whole `machine run` | 8238 ms [5701–10870] | 3880 ms [2049–12326] |
| cold boot, whole `machine run` | 1430 ms [633–3423] | 1543 ms [1007–3246] |
| cold boot, backend start | 643 ms [214–1175] | 654 ms [431–1577] |

The cold-boot difference is noise. That path attaches no writable disk, so
neither build flushes anything on it.

One live check covered stop and start. A `machine run` wrote a marker and an
8 MiB random blob to a `--volume` disk. A second run on the same image read
both back, and the blob's SHA-256 matched.

## Tests

- In `virtio.rs`:
  - a guest flush uses the guest-strength sync and not the release flush;
  - a failed guest flush reports an I/O error;
  - releasing a written disk runs the full flush exactly once, after two
    guest flushes;
  - an unwritten writable disk is released without the full flush;
  - a discard also marks the disk for the release flush;
  - a read-only disk never syncs;
  - the host guest-strength sync succeeds on a real file;
  - data written through the virtio queue survives releasing the device and
    reopening the image.
- In `hvf.rs`: the capture refusal and its admitted counterpart.

The four behavioural tests failed against the previous semantics, which were
temporarily restored for that check: guest flush as a full flush, and no
release flush.

## Not done, or observed

- W8.2a, dropping the flush offer on scratch disks, was not built: it is not
  material (see above). The Stage 0 root disk is the one scratch disk that
  still takes flushes, and now takes the cheap kind. Stage 0 was not measured.
- The builder build was measured once, before the change only. The builder VM
  was not re-measured afterwards.
- Unrelated and undiagnosed: in the bulk-write and untar volume runs, teardown
  took about 5.1 s in every flush mode, no-op included. The breakdown showed
  `stop_pid_disappearance` at about 5000 ms, followed by a force kill. The
  supervisor was not exiting within the stop grace after SIGTERM. Mount-only
  runs stopped in 0.5–1.6 s. Flush is not the cause, because the no-op mode
  shows the same delay.
