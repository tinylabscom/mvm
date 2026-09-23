# #3566 — multi-GPU ordinals and per-VM pinning

## What shipped

- The GPU endpoint now preserves each backend's real device count and native
  ordinals. The native CUDA/NVML backend already obtains those values from the
  dynamically loaded driver; the deterministic backend now models two distinct
  devices so the behavior is testable without GPU hardware.
- An optional device pin is carried from `--gpu-device ORDINAL` or
  `gpu_device = ORDINAL` through transient launches, persisted machine specs,
  start parameters, and the runner-spawned endpoint. A pin implies GPU
  remoting. The selected host device is the VM's only visible device and is
  presented as guest ordinal zero.
- Pinned endpoints validate the host ordinal against the backend count before
  listening. Requests for a hidden guest ordinal are refused rather than
  falling through to another host device. CUDA and NVML responses retain their
  respective invalid-device error domains.
- The runtime shim now validates `cudaSetDevice` against the reported count and
  lazily creates a context for each selected ordinal instead of refusing every
  ordinal except zero.

## Tests

Backend tests cover two distinct device identities, out-of-range rejection, and
guest-zero-to-host-one pinning. Endpoint integration tests cover unpinned
enumeration, pinned identity/count behavior, hidden guest-ordinal refusal, and
invalid-pin startup refusal. Manifest and CLI tests cover implicit GPU enablement
and ordinal persistence. Runtime-shim unit tests cover valid, negative, and
out-of-range device selections.

No physical multi-NVIDIA host is available in this worktree. Native code uses
the driver's real `cuDeviceGetCount`/`cuDeviceGet` and NVML count/handle calls;
the deterministic two-device endpoint is the portable evidence for this slice.
Physical-device validation remains tracked by #3561.
