# The Firecracker vCPU ceiling is the VMM's, not the wire format's

`mvmctl machine run --image alpine --cpus 9999` booted on HVF and failed on
Firecracker (#3051), which made a documented, portable flag backend-divergent:
the README says a request above the backend's vCPU ceiling is clamped to it with
a warning, and that only described one backend.

The clamp was not missing. It is one call, above the backends, in
`exec::resolve_launch` — the same function `mvmctl run`, `mvmctl machine run`
and the warm-pool resolver all reach — and it fired on Firecracker exactly as it
fires on HVF:

```
[mvm] firecracker supports at most 255 vCPU(s); 9999 requested, booting with 255
Error: starting transient microVM
  0: Firecracker API PUT /machine-config
  1: PUT /machine-config failed: HTTP 400 {"fault_message":"Machine config
     error: The number of vCPUs must be greater than 0, less than 32 ..."}
```

What was wrong was the number it clamped *to*. `FcDriver::capabilities()`
declared `max_vcpus: Some(u8::MAX)`, reasoning from the wire format —
`vcpu_count` is a byte, so 255 is the largest value that survives
deserialization. True, and not the limit that matters: `/machine-config`
validates the value as well as parsing it, and refuses anything above 32. So the
clamp faithfully produced a count the VMM would not boot, and the launch died
one step further along than it used to. The bug report quotes the older,
pre-clamp message (`invalid value: integer 9999, expected u8`); the failure
today is the second one. Both are the same defect.

HVF never had this problem because its ceiling is asked of the host
(`hv_vm_get_max_vcpu_count`, 64 on Apple silicon) rather than derived from a
type — so the clamp there had a real number to clamp to.

Firecracker now declares the ceiling it will actually boot on, and holds the
emitted body to it at the point of serialization, the way the libkrun and qemu
drivers already do for theirs. The reporting clamp stays where it was: one call
site, above the backend, where the request is still the user's and there is
somebody to warn. The driver-side bound is the floor under callers that never
passed through it, and it pins the declared ceiling and the emitted body to the
same constant so they cannot drift apart again — which is the shape of this bug.

32 was probed against the API rather than read out of Firecracker's source:
`vcpu_count: 32` answers 204, `64` and `255` answer 400, `9999` fails to
deserialize (v1.14.1).

## Witness

`features/suites/s31_launch_e2e/cli_launch_modes.feature:231` — *"a vCPU
request beyond the backend ceiling is clamped and reported"* — now passes on
Firecracker as it does on HVF. Live, on x86_64 Linux/KVM:

```
$ mvmctl machine run --image alpine --cpus 9999 -- sh -c 'echo clamped-and-booted'
[mvm] firecracker supports at most 32 vCPU(s); 9999 requested, booting with 32
clamped-and-booted            # exit 0

$ mvmctl machine run --image alpine --cpus 9999 -- sh -c 'echo $(nproc)/$(grep -c ^processor /proc/cpuinfo)'
32/32                          # the clamp is a real machine shape, not a message
$ mvmctl machine run --image alpine --cpus 32 -- sh -c 'nproc'
32                             # at the ceiling, unclamped and unwarned
$ mvmctl machine run --image alpine --cpus 2 --memory 512M -- sh -c '...'
2/2                            # ordinary requests unchanged
```

Unit witnesses in `crates/mvm-backends/src/driver/fc.rs`:
`an_oversized_vcpu_request_is_held_to_the_ceiling_the_driver_declares` reads the
ceiling off `capabilities()` and asserts the `/machine-config` body lands on it,
so a future edit cannot move one without the other;
`a_vcpu_request_within_the_ceiling_reaches_the_api_unchanged` asserts the bound
bounds rather than rewrites.
