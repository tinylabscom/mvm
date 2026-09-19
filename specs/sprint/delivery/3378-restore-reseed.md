# #3378 — a restore reseed is reported only when it happened, and it is immediate

A guest restored from a snapshot could tell the host it had reseeded its random
generator when it had not. `GenIdReseeder::on_genid` logged a failed write to
`/dev/urandom` and returned `Reseeded` anyway, the agent turned that into
`reseeded: true`, and the host's identity gate had nothing to refuse. Even a
write that succeeded did not do what the comment said: it mixes bytes into the
kernel's input pool and leaves the generator behind `getrandom` on its old key
until the kernel's own reseed schedule comes round, so two clones of one
snapshot kept returning the same bytes for up to about a minute.

## What shipped

- `on_genid` takes the reseed as an injected step and returns `ReseedFailed`
  when it fails. The token is recorded only after a reseed succeeds, so a host
  retry with the same token reseeds instead of reading as "unchanged".
- A reseed is two ioctls on `/dev/urandom`, which the helper opens once at
  start: `RNDADDENTROPY` adds the 16-byte host token to the input pool and
  credits all 128 bits of it, then `RNDRESEEDCRNG` rekeys the generator — and
  the vDSO fast path, which watches the same generation counter — at once.
  Crediting is what makes the forced reseed take effect on kernels before 5.18,
  which skip a reseed with fewer than 128 credited bits. The token comes from
  the host's own generator, which the guest already trusts.
- The acknowledgement keeps two things apart. `success` covers what brings the
  guest back (hostname, clock, init signal). The reseed is reported on its own:
  `reseeded`, plus `reseed_shortfall` (`helper_missing` or `failed`) and the
  reason in `detail`. With a failed reseed folded into `success`, the resume
  path answered with advice about unmounted drives.
- Every host consumer says what to do. A fork or warm claim of a guest with no
  helper is refused with "rebuild the image with this mvm release and boot a
  fresh parent"; a failed reseed is refused with "retry the restore". A plain
  `mvmctl machine resume` of one paused VM reports a missing reseed in its
  summary and a warning rather than failing, because there is no sibling
  restored from the same memory.

## Why a helper process, and not a generation-ID device

The ioctls need `CAP_SYS_ADMIN`. The agent holds only `CAP_KILL` and
`CAP_SYS_TIME`, and giving it the broadest capability there is — even briefly,
even to hand on — would undo the reason it runs unprivileged. So a separate
process holds `CAP_SYS_ADMIN` and nothing else. It is the agent binary run with
`--crng-reseed-helper`, it takes no other configuration, and it is always
started by a process that is still root, never by the agent:

- On the universal initramfs the agent is PID 1 and still root at activation.
  Immediately before its own privilege drop, PID 1 starts the helper over a
  socket pair as uid/gid 988, with the bounding, permitted, effective,
  inheritable and ambient sets all exactly `CAP_SYS_ADMIN`, and no-new-privs.
  PID 1 then drops itself exactly as before.
- Under the shell `/init` of an mkGuest image, `/init` creates
  `/run/mvm/crng-reseed` owned by uid 988 and the agent's group, mode 0750, and
  launches the helper through `mvm-setpriv` as uid 988 in the agent's group,
  with `+sys_admin` and no-new-privs. The helper binds a 0660 socket there. The
  agent's own launch line is unchanged; it connects on its first restore and
  checks the peer with `SO_PEERCRED` before trusting a reply, which also
  defeats a workload that shares the agent's uid binding a fake helper first.
  `mvm-setpriv` does not narrow the bounding set on this path.

Uid 988 is reserved in mkGuest the way 989 is for the egress service: an image
whose agent, entrypoint, egress or builder uid collides with it fails to build.

Before serving, the helper makes itself non-dumpable, closes every descriptor it
did not expect, opens `/dev/urandom`, and installs a seccomp allowlist: socket
read and write, `accept4`, `close`, memory management, signal return, exit,
`fcntl` only for `F_GETFD`, and `ioctl` only for the two `random` requests. Any
other syscall kills it. The allowlist was derived by running the helper under
the filter on Linux, not guessed — the first run died on the `F_GETFD` a debug
build makes when it drops an owned descriptor.

The PID-1 spawn closes every descriptor above the socket pair in the child
before exec. Without that, the helper inherited the agent's vsock listener and
the live activation connection, because neither was close-on-exec. Both now are
(`SOCK_CLOEXEC`, `accept4`).

What a compromise buys: a compromised agent can make the helper reseed as often
as it likes, and every request adds 16 bytes of the agent's choosing to the
input pool credited as 128 bits of entropy. The credit is deliberate — the host
token is the reseed's only fresh input, and kernels before 5.18 skip a forced
reseed without it — and chosen bytes cannot cancel what the pool already holds.
The count matters only before the generator first initializes, where it could
have the kernel declare itself seeded early; every restore is long past that.
(Corrected by #3431; the first version of this note said the agent could cause
more reseeds "and nothing else".) A workload can do less: it cannot signal the helper, change its limits,
or trace it, and on mkGuest it cannot reach its socket unless it shares the
agent's group. A dead helper makes the next restore report `reseeded: false`,
which a fork or claim refuses.

The helper survives the agent's errors. Requests carry an id and replies echo
it, so a reply that arrives after a timeout is recognised and discarded rather
than read as the answer to the next request, and the socket pair is never
dropped. A kernel refusal is answered and the helper keeps serving.

The alternative was a generation-ID device, where the kernel reseeds itself when
the VMM changes the ID. That is not uniform: it needs a device model in each
VMM, apple-container boots a prebuilt kernel whose config we do not control, and
our own workload kernel does not carry the driver — the cached aarch64 workload
kernel config (6.12.107) has `# CONFIG_VIRT_DRIVERS is not set`, so `VMGENID` is
absent. The helper lives in the guest, so it behaves the same on every backend
that boots our agent.

## Upgrade impact

An mkGuest image built before this change has no helper in its `/init`. Booted
with the new runtime overlay, its agent reports `helper_missing`, so forks and
warm claims of it are refused with the rebuild instruction. A plain resume
originally only reported it; since #3431 it is refused the same way. The universal initramfs carries the helper as soon as it is rebuilt.
`fc_warm_pool_live`'s rootfs must be rebuilt for the same reason; its doc
comment says so.

## Workload descriptor inheritance (#3404)

Confirmed while doing this: the cold entrypoint, process RPC, warm workers,
detached execution, stream forwarding, lifecycle hooks, health checks, init
helpers, builder subprocesses, and nested runners could spawn children while
the agent held control-plane descriptors. Shared vsock listeners and accepted
connections now set close-on-exec at creation, and every child path applies one
shared `pre_exec` hook that closes all descriptors above stderr. The one warm
worker path that executes through an already-open program descriptor preserves
only that validated descriptor.

Two real Linux tests hold an intentionally inheritable socket while spawning a
workload. The cold-entrypoint and process-RPC witnesses each prove the child
sees only its declared standard streams and executable descriptor. The focused
Linux suite also ran successfully inside the project builder VM, alongside host
unit and integration tests, workspace clippy and check, gated-target checks,
the serialized workspace suite, and all repository gates.

## Tests

Unit tests cover the reseeder, the request/reply framing (ids, late replies,
split reads, malformed replies), the socket pair kept across every error, the
listening transport and its peer check, the acknowledgement builder, the
shortfall on the wire, the host's refusal advice for each cause, the resume
summary, `signal_post_restore` carrying the shortfall through, descriptor range
arithmetic, close-on-exec on the control sockets, and the mkGuest `/init` text
and reserved uid.

On the x86_64 Linux box, with glibc and musl builds, the helper runs as a real
process under its filter. Unprivileged, it answers the kernel's `EPERM` and
exits cleanly. As root with `MVM_GUEST_PRIVILEGED_TESTS=1`, the PID-1 spawn
shows `CapEff`, `CapPrm` and `CapBnd` of exactly `CAP_SYS_ADMIN`, `Seccomp: 2`,
`NoNewPrivs: 1`, uid 988, and only its socket and `/dev/urandom` above stdio,
and it actually reseeds; the listening helper started through `mvm-setpriv`
binds a 0660 socket and is trusted by uid.

The allowlist was then reviewed for aarch64, where some syscalls go by other
names (`dup3`, `ppoll`, `openat`, `newfstatat`). None of those is issued after
the filter goes on, so no entry changed for that reason; the review added
`mprotect` without `PROT_EXEC`, which musl's allocator can issue for a new
metadata area. Each entry now says why it is there. On aarch64 Linux (an arm64
container on an Apple Silicon host), with glibc and musl builds, the helper
tests pass unprivileged and, with `--privileged` and
`MVM_GUEST_PRIVILEGED_TESTS=1`, the privileged helper tests and the three
`guest_mount` privilege witnesses pass too. In CI, the unprivileged helper test
runs in the normal suite on both architectures, and the aarch64 lane runs the
privileged tests under `sudo` in a separate step.

The first aarch64 CI run passed the whole normal suite, including the
unprivileged helper test under its filter, and failed only the privileged step:
the runner's target directory sits below a home directory uid 988 cannot
traverse, so exec as the helper uid returned `EACCES`. That is the runner's
layout, not the helper's; in a guest the agent binary is on a world-traversable
path. The privileged process tests now copy the agent binary into a 0755
directory under `/tmp` before starting it under the helper uid.

The unprivileged helper test drives the whole serve loop: two frames carrying an
id the agent has moved past (the second a duplicate), then two ordinary
requests, all reaching the ioctls. It asserts the stale answers are discarded,
every request is answered, and the helper exits with status 0 rather than by
`SIGSYS`.

The root-gated witnesses in `guest_mount` read `/proc/self/status`, which
describes the main thread, while the test harness runs each test on another
thread, so the two that predate this change failed whenever they were enabled.
They now read `/proc/thread-self/status`.

## Not done

- No live evidence of two clones returning different `getrandom` output right
  after restore. It needs a rebuilt initramfs and runtime overlay carrying this
  agent and a fork on a live backend.
- Userspace generators seeded before the snapshot (a language runtime's own
  DRBG) are not reseeded by this; only the kernel generator is.
