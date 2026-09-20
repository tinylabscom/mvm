# Firecracker keeps its sockets inside the Unix socket limit; the cold source witness runs on Firecracker again

Backing: shipped-source
Validation: cargo nextest run -p mvm-backends -E 'test(/fc::tests|daemon::tests|device_anchors/)' && cargo nextest run --test github_actions_extended_e2e

## What was failing

The nightly `source-bootstrap-linux` job failed twice with Firecracker as its
builder:

```
Stage 0 rootfs build: builder VMM-level failure: firecracker Stage 0: Firecracker API socket
/home/runner/work/_temp/source-bootstrap-home/vms/mvm-stage0-firecracker-26289-1789708959173633880/fc.socket
did not appear within 3s
```

The job had already uploaded `firecracker.log`, and nobody had read it:

```
Error: RunWithApi(FailedToBindAndRunHttpServer(IOError(Error { kind: InvalidInput,
  message: "path must be shorter than SUN_LEN" })))
```

That API socket path is 108 bytes. Linux allows 107 plus the NUL. The runner
was not the cause: the same 112-byte path fails the same way on the bare-metal
KVM host. The lane was pinned to QEMU on the theory that Firecracker Stage 0
could not boot on a hosted runner. The real cause was that its `MVM_HOME`,
under `runner.temp`, is 23 bytes longer than `~/.mvm`.

## The fix

Every other per-VM socket already moved to a short hashed `/tmp/mvm-sock/<hash>`
namespace when the state dir was too deep (`vm_socket_dir_at`). Firecracker's
own sockets did not: the API socket, the vsock mux, and every guest-dialed
`v.sock_<port>`. They now use the same fallback on the boot and control paths
(`fc_socket_dir`, `fc_api_socket_path`, `firecracker_vsock_uds_path`). For state
dirs that fit, the paths are byte-for-byte unchanged.

The snapshot, warm-restore, fork and sealed-snapshot paths locate the state dir
from where the socket is. A fork remaps the vsock socket's grandparent onto the
child's dir. With relocated sockets, that remap would carry the vsock and leave
the config and secrets drives pointing at the parent's copies. Those paths now
refuse relocated sockets by name (`ensure_fc_sockets_in_state_dir`), which
tells the operator to shorten `MVM_HOME`. Before this change the same case
failed at boot anyway.

## Failing fast, with the reason

- An API socket path the kernel would reject is refused before Firecracker is
  started.
- When the API socket does not appear, the error now quotes the last lines of
  Firecracker's stderr log. On a runner that is gone before anyone reads the
  file, that is the only way to see the reason.

The two-hour hang in the original 2026-09-16 reports (`mvm-egress-client did
not bind ... within 5s`, on `d530f731b9`) was a different failure. As diagnosed on the
issue, the guest most likely refused within its 5-second window and then halted
instead of powering off. Firecracker keeps a halted guest alive, so the host
waited out its builder timeout. The console halt watch added with Firecracker
builder jobs ends that wait. No console from those runs was kept, so that
diagnosis cannot be confirmed after the fact. That egress refusal does not reproduce
on current `main`, hosted or bare metal. In every run below Stage 0 passed its
egress readiness gate, which refuses the build when the proxy does not bind.
The bare-metal Stage 0 console shows the proxy bound within 0.1 s of the fork,
and the hosted builder-VM consoles show the same.

## Evidence

Scratch dispatch of the witness with `MVM_BUILDER_BACKEND=firecracker` on this
branch (Extended CI run 35463567722), on `ubuntu-latest` (Azure, nested KVM,
`kvm_intel`, Firecracker v1.17.0):

| home | result | build | sdk-sidecar (incl. Stage 0) | builder-image | flake-build | total |
|---|---|---:|---:|---:|---:|---:|
| `runner.temp/source-bootstrap-home` (the failing one) | passed | 594 s | 2915 s | 302 s | 47 s | 3858 s |
| `~/.mvm` | passed | 615 s | 2266 s | 304 s | 37 s | 3222 s |

The deep-home run's `/tmp/mvm-sock/<hash>/` held `fc.socket`, `runtime/v.sock`
and the egress endpoint socket, as intended.

The same witness with the deep home on the bare-metal KVM host (Firecracker
v1.14.1) also passed. It took 530 / 2528 / 270 / 44 s, 3372 s in total.

For comparison, the QEMU-pinned nightly on 2026-09-19 took 1043 s in the
sidecar phase. Firecracker's Stage 0 is slower there. One candidate, not
measured here: the `/logger` level is `Debug`, which makes Firecracker log
every vsock packet. That came to 163 MB of `firecracker.log` 17 minutes into a
Stage 0.

## Witness

`source-bootstrap-linux` names Firecracker again and drops the QEMU-only
provisioning (the `vhost-vsock` chown, the readable `/boot` kernel, and
`qemu-system-x86`/`qemu-utils`/`virtiofsd`). Its home is still the deep one, so
the lane also exercises the socket fallback.
