# #3381 — HVF returns freed guest memory to the host

Plan: `specs/plans/2026-09-16-sandbox-review-upgrades.md` W4.

Before this, an HVF guest that touched memory held it on the host for the rest
of its life: the in-house device model had no balloon, and the only `madvise`
on guest RAM ran at teardown.

## What changed

- **A reporting-only virtio-balloon** (`crates/mvm-vmm/src/vmm/virtio_balloon.rs`).
  It offers `VERSION_1`, `PAGE_REPORTING` and `DEFLATE_ON_OOM`, never asks the
  guest for pages, and returns inflate/deflate buffers unread. The reporting
  queue is index 2: the driver numbers only the queues whose features were
  negotiated. It sits at the MMIO slot and SPI after the entropy device, so no
  existing device moved.
- **Order per reported span:** unmap from the guest's hypervisor map, release
  the host pages, remap, and only then return the report. A remap is retried
  once; a span that still cannot be remapped is never returned and stops the
  device, because returning it would hand the guest an address with no memory
  behind it.
- **The host side is a trait**, `GuestPageRelease`, implemented for HVF in
  `crates/mvm-runtime/src/backends/hvf/page_release.rs`. The device's unit
  tests drive it with a fake that records the order of every call.
- **Private file mappings are skipped.** They already exist on `main`: the
  kernel image, and all of RAM on a restore from a memory blob. `GuestRam`
  now records them, and the device returns reports over them untouched.
- **Spans with nothing resident are skipped**, so a freshly booted guest
  reporting its never-touched memory costs no hypervisor calls.
- **Device state** is part of the snapshot frame (`DeviceKind::VirtioBalloon`,
  wire code 6) and restores with the others. A snapshot taken before this
  change has no balloon record and no longer restores.
- **Capability.** New `VmCapabilities::free_page_reporting`, true on HVF.
  `balloon` stays false there. `apple-container` clears it: the device is
  present, but nothing has shown Apple's prebuilt kernel reports free pages.
  `mvmctl doctor`'s capability matrix has a `page-reporting` column.
- **Guest kernel:** unchanged. `VIRTIO_BALLOON` selects `PAGE_REPORTING` in
  6.12; a built workload config confirms it, with `INIT_ON_FREE_DEFAULT_ON` and
  `PAGE_POISONING` off.

## Why not `MADV_FREE_REUSABLE`

It was built first and measured live. It dropped the footprint as expected, but
when the guest then refilled the 1.5 GiB it had freed, the VM process reported
**512 MiB** of footprint while **1621 MiB** was resident: pages marked reusable
and written again are never charged back until something calls
`MADV_FREE_REUSE`, and nothing can know when the guest reuses them. The release
maps fresh anonymous memory over the span instead. The same refill then showed
1611 MiB.

## Why not `balloon: true`

`balloon` means a host-driven inflate target: `balloon_set_target`, and
`mem_initial` booting pre-inflated. The reclaim controller's one action is
setting that target. A reporting-only device has no target, so advertising
`balloon` would be untrue and the controller would call a setter with nothing
behind it. The controller keeps skipping HVF, which is correct: reclaim here
needs no host action. `mem_initial` still has no effect on HVF.

## Live evidence

macOS 26 Apple Silicon, host load ~110–210, isolated
`MVM_HOME=/private/tmp/claude-501/3381/mvm-home`, `MVM_BOOT_IMAGE=fetch`,
`MVM_KERNEL_SOURCE=download`, debug `mvmctl` built with
`--features user,release-artifact-bootstrap,embed-host-bins` plus
`just build-supervisors`, then `mvmctl env sign`.

Guest: `mvmctl machine run --hypervisor hvf --image alpine --memory 2G -- sh -c …`
writing 768 MiB to each of two tmpfs mounts, removing both, waiting 40 s, then
writing them again. The measure is the supervisor process's `phys_footprint`
(`proc_pid_rusage(RUSAGE_INFO_V4)`, the figure `footprint(1)` and Activity
Monitor report), sampled every second. Footprint rather than RSS because it is
what the kernel charges the process for — and, as above, because RSS and
footprint can disagree, which is exactly the failure worth catching.

| Build | Footprint at free | Lowest within 30 s | First 1 GiB gone after | After refill |
| ----- | ----------------- | ------------------ | ---------------------- | ------------ |
| `main` | 1613 MiB | 1613 MiB | never | 1620 MiB |
| this branch | 1610 MiB | 78 MiB | 10.9 s | 1613 MiB |

Boot time, `machine run --image alpine --memory 2G -- true`, 20 boots per
build interleaved with `main`, `MVM_PHASE_TIMING=1`:

| | `main` median | this branch median | paired median difference |
| - | - | - | - |
| `backend_start` | 926 ms | 915 ms | +64 ms (new slower in 11/20) |
| `teardown` | 2311 ms | 1834 ms | −103 ms |

At this load the spread within one build is several hundred milliseconds, so
this shows no regression the host can resolve; it does not show a small one
cannot exist.

## Not done

- W4.5 as written (see above).
- Restored guests return nothing, because all of their RAM is a private file
  mapping. How to reclaim pages a restored guest has written belongs with the
  copy-on-write restore work (#3382).
