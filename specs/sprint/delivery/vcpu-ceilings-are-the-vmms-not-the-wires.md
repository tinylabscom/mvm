# A vCPU ceiling is the VMM's, not the wire format's

`mvmctl machine run --image alpine --cpus 9999` booted on HVF and failed on
Firecracker (#3051) and on libkrun (#3065), which made a documented, portable
flag backend-divergent: the README says a request above the backend's vCPU
ceiling is clamped to it with a warning, and that described one backend of
three. The contract is that an over-large request is *granted the maximum*, not
refused and not fatal.

The clamp was not missing. It lives above the backends and asks each one for its
ceiling — `exec::resolve_launch` for transient runs (the function `mvmctl run`,
`mvmctl machine run` and the warm-pool resolver all reach) and
`mvm_client::clamp_vcpus_for_backend` for the persistent OCI path. Both read
`capabilities().max_vcpus`, so neither had to change here. It fired on both
failing backends exactly as it fires on HVF:

```
[mvm] firecracker supports at most 255 vCPU(s); 9999 requested, booting with 255
Error: starting transient microVM
  0: Firecracker API PUT /machine-config
  1: PUT /machine-config failed: HTTP 400 {"fault_message":"Machine config
     error: The number of vCPUs must be greater than 0, less than 32 ..."}

[mvm] libkrun supports at most 255 vCPU(s); 9999 requested, booting with 255
Error: starting transient microVM
  libkrun supervisor exited before binding vsock socket ...
  (status: signal: 6 (SIGABRT) (core dumped))
```

What was wrong was the number each clamped *to*. Both drivers declared
`max_vcpus: Some(u8::MAX)`, reasoning from the wire format — Firecracker's
`vcpu_count` and libkrun's `krun_set_vm_config` both take the count as a byte,
so 255 is the largest value that survives the call. True of both, and the limit
of neither. So each clamp faithfully produced a count its VMM would not boot,
and the launch died one step further along than it used to.

HVF never had this problem because its ceiling is asked of the host
(`hv_vm_get_max_vcpu_count`, 64 on Apple silicon) rather than derived from a
type — so the clamp there had a real number to clamp to.

Each driver now declares the ceiling it will actually boot on, and holds the
value it hands the VMM to that same constant, so the declared ceiling and the
value on the wire cannot drift apart again — which is the shape of this bug.
The reporting clamps stay where they were, above the backends, where the request
is still the user's and there is somebody to warn — and because they read the
declared ceiling rather than carrying their own, correcting the declaration
fixed both without touching either. The driver-side bounds are the floor under
callers that never passed through them, and match what the qemu driver already
did for its own.

## Where the two numbers come from

**Firecracker: 32.** `/machine-config` validates the value as well as
deserializing it. Probed against the API rather than read out of Firecracker's
source: `vcpu_count: 32` answers 204, `64` and `255` answer 400, `9999` fails to
deserialize (v1.14.1).

**libkrun: 64, and measured rather than asked** — because nothing will say.
`krun_set_vm_config` accepts every count from 1 to 255 and returns 0; the ones
it cannot honour abort the process inside `krun_start_enter`, which is why the
failure surfaced as a supervisor that died before binding its vsock socket,
naming neither vCPUs nor the count. `krun_get_max_vcpus()` answers **4096** —
KVM's own `KVM_CAP_MAX_VCPUS` forwarded verbatim, which the host confirms — and
libkrun aborts at 65 regardless. So the number is measured, and measured as a
constant and not a resource limit: the cliff sits exactly at 64/65 and does not
move when the guest is given eight times the memory. A number measured on one
host and hardcoded is how HVF once carried `Some(4)` recording a bug rather than
a limit (#2927), so the memory control is the part that matters here.

## Witness

`features/suites/s31_launch_e2e/cli_launch_modes.feature:231` — *"a vCPU
request beyond the backend ceiling is clamped and reported"* — now passes on
Firecracker and libkrun as it does on HVF. Live, on x86_64 Linux/KVM:

```
$ mvmctl machine run --image alpine --cpus 9999 -- sh -c 'echo clamped-and-booted'
[mvm] firecracker supports at most 32 vCPU(s); 9999 requested, booting with 32
clamped-and-booted             # exit 0

# the clamp is a real machine shape, not a message
$ ... --cpus 9999 -- sh -c 'echo $(nproc)/$(grep -c ^processor /proc/cpuinfo)'
32/32
$ ... --cpus 32 -- sh -c 'nproc'    ->  32     # at the ceiling: unclamped, unwarned
$ ... --cpus 2 --memory 512M -- ... ->  2/2    # ordinary requests unchanged

$ ... --hypervisor libkrun --cpus 9999 -- sh -c 'nproc'
[mvm] libkrun supports at most 64 vCPU(s); 9999 requested, booting with 64
64
$ ... --hypervisor libkrun --cpus 65 -- sh -c 'nproc'
[mvm] libkrun supports at most 64 vCPU(s); 65 requested, booting with 64
64
$ ... --hypervisor libkrun --cpus 64 -- sh -c 'nproc'  ->  64
$ ... --hypervisor libkrun --cpus 2  -- sh -c 'nproc'  ->  2
```

`mvm-client`'s `firecracker_vcpus_are_clamped_to_a_count_the_vmm_boots` used to
assert the clamp landed on `u8::MAX`, pinning the defect; it and its new libkrun
sibling now name the counts the VMMs boot.

Unit witnesses, one pair per driver, in `crates/mvm-backends/src/driver/`:
`an_oversized_vcpu_request_is_held_to_the_ceiling_the_driver_declares` reads the
ceiling off `capabilities()` and asserts the value handed to the VMM lands on
it, so a future edit cannot move one without the other;
`a_vcpu_request_within_the_ceiling_reaches_{the_api,libkrun}_unchanged` asserts
the bound bounds rather than rewrites.
