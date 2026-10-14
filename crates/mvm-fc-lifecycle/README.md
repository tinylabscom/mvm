# Experimental Firecracker lifecycle service

This unpublished prototype adds **no default launch or cleanup integration**.
It is not a replacement for the existing host agent, and does not repair the
default non-root cleanup route. Root manually registers an already-created,
trusted Firecracker process. No spawn, privilege elevation, installer, package
activation, systemd unit, sudoers entry, or normal client integration is provided.

## Trust before execution

The service is a separate root package TCB, not the user-owned host agent or
its discovery path. An operator must independently review, build, verify and
install the executable as trusted root-owned code **before running it as root**.
Never run a user-owned `target/debug` or `target/release` executable with root
privileges. A path/ownership check performed after code starts executing cannot
retroactively make that execution safe. The launcher, dynamic loader,
dependencies, execution environment and Linux mounts must also be trusted.
Code approval is not permission to install or activate this service.

Only this invocation serves:

```text
/usr/libexec/mvm/mvm-fc-lifecycle serve --experimental
```

It requires Linux, real/effective UID 0, working pidfds, and the running
executable's exact inode/device/path match to the trusted installed file.
Privileged executable and registry discovery has no environment/PATH override.
Fixed locations:

| Object | Path | Operator prerequisite |
| --- | --- | --- |
| Service | `/usr/libexec/mvm/mvm-fc-lifecycle` | Root-owned regular executable; no group/other writes, set-ID bits, symlinks or extra hard links |
| Firecracker | `/usr/bin/firecracker` | Same file/ancestor trust policy; already-running root-owned process |
| Registry | `/var/lib/mvm/fc-lifecycle` | Precreated root-owned private directory, mode `0700` |
| Socket parent | `/run/mvm` | Precreated root-owned non-group/other-writable directory |
| IPC socket | `/run/mvm/fc-lifecycle.sock` | Created by service, root-owned mode `0666`; ownership authorizes nothing without peer credential checks |

All privileged ancestors must be root-owned non-group/other-writable directories,
without symlinks. The implementation opens paths descriptor-relatively with
`O_NOFOLLOW`. Missing paths refuse startup; nothing installs these prerequisites.
The service refuses any preexisting socket, even a stale one. Recovery after
exit therefore needs a separately authorized operator to inspect/remove the
stale socket before restarting; the prototype never unlinks it automatically.

## Protocol and authority

The crate exposes a bounded client `request` function; no existing CLI calls it.
Requests are four-byte big-endian lengths followed by one UTF-8 JSON value.
The sender must half-close its write side. Zero-length/oversize/truncated
frames, trailing bytes or additional frames refuse without dispatch.
Maximum frame/record size is 16 KiB. Each connection has a two-second total
I/O deadline, not a timeout reset by every byte. Before reading a body, intake
uses kernel credentials to admit only root or a UID with a registration. Each
UID has at most one active connection. Sixteen non-root slots and a separate
reserved root slot bound workers at seventeen: one slow UID cannot occupy the
other UIDs' slots or root's slot. Excess and unknown-UID connections close
immediately without blocking intake on response I/O.

At most 1024 registrations are retained. Root registry mutation is serialized;
authorized immutable handles are copied under the lock, then process/filesystem
validation and signaling run outside it. The kernel listener backlog is bounded.
Filesystem latency is not bounded by the socket I/O deadline; a blocked owner
inspection consumes that UID's slot, not the global registry lock. This is not
a guarantee against arbitrary host-wide resource exhaustion or connection floods.

Version-one request shapes:

- `{"version":1,"operation":{"op":"register","pid":123,"owner_uid":1000,"state_dir":"/home/user/vm","api_socket":"/home/user/vm/api.sock"}}`
- Stop/query operations contain only `op` (`stop` or `query`) and `id`, the
  actual server-returned 256-bit random registration ID encoded as 64 lowercase
  hexadecimal characters. They use the same outer `version`/`operation` envelope.

Unknown/duplicate fields are rejected. Register replies carry `result:
registered` and `id`. Stop/query replies carry `result: status` and `status`
(`running`, `stop_requested`, or `exited`). Dispatched rejected requests use
`result: refused`, without disclosing identity details; prebody admission
refusals close the connection. `stop_requested` means SIGTERM
was sent, not that exit or cleanup completed. No escalation, arbitrary signal,
scope or pathname cleanup is exposed.

The server derives peer UID using Linux `SO_PEERCRED`. JSON cannot supply
credentials. Register requires UID 0: `owner_uid` is a trusted root assertion,
which must match the kernel state-directory owner. Non-root peers cannot
register any PID, including their own. Stop/query accept only an opaque ID;
only its registered owner UID or root is authorized. Possession of another
UID's ID is not authority. Root delegation of a connected descriptor is itself
a trusted root action, outside the unprivileged-client boundary.

The client validates protected root-owned socket ancestors, socket inode/device
stability, installed service-file trust and the connected kernel peer UID 0.
It does not require an ordinary user to dereference `/proc/root-pid/exe`, which
Linux normally denies. Root itself is trusted, not protected against by this
prototype. The service self-checks its installed executable before serving.
No request bodies, IDs, paths, process details or workload secrets are logged.

## Registration and restart

The root operator must already know that the process and explicit state/socket
association are legitimate. This is **manual registration, not atomic trusted
spawn integration**. The service requires the socket directly inside the
asserted state directory, exact `--api-sock` argv binding, and all process UIDs
zero. State-directory ancestors may belong to root or the asserted owner but
may not be group/other writable; the final directory must belong to that owner.
Socket ownership must be root or that owner. Paths are absolute, bounded,
without NUL, symlinks, dot components or repeated/trailing separators.

Before recording authority the service opens the original pidfd and captures:
raw kernel start ticks, boot ID, installed executable device/inode, state
directory device/inode/owner/mode and socket device/inode/owner/mode. It retains
the original directory, socket and trusted executable descriptors alongside the
**original pidfd**. These pins prevent original inode numbers being recycled
while registration authority exists. Every query/stop compares both current
metadata on those original descriptors and freshly resolved paths to captured
evidence. Detected mismatches, unreadable or unsupported evidence refuse.

SIGTERM goes through the original pidfd, never a newly opened handle or numeric
PID. This prevents redirecting a signal to a recycled PID. Filesystem checks
and signal delivery are **not an atomic filesystem transaction**: no guarantee
is made that every concurrent rename/permission change after the checks will
be detected. Root manual registration remains an explicit trusted assertion.

Registry records are private root-owned regular files named only by generated
IDs. An unnamed `O_TMPFILE` inode is staged under the pinned registry directory,
written and file-fsynced, then atomically published using
`linkat(AT_EMPTY_PATH)` with no replacement, followed by directory fsync before
registration succeeds. Partial staging has no name in the authoritative record
namespace and disappears when closed; it cannot poison other valid records.
The filesystem and service privileges must support these primitives (including
the permission needed for `AT_EMPTY_PATH`); otherwise registration refuses
without a weaker fallback. A failure after publication may leave a complete
record without an acknowledged registration, requiring root reconciliation.
A locked registry prevents two instances. Records never come from workload
claim files. No legacy registration is auto-adopted.

**Restart refuses every recovered registration**, even an intact root record
whose device/inode/ticks values still match. The original filesystem descriptors
have been lost, so the record cannot prove that a user-owned inode was not
recycled while the service was down. No stronger trusted generation is available
in this prototype. It never transparently reopens authority from these records.
Corruption and unknown registry entries also refuse startup; missing records
grant no authority. Before restarting with an empty registry, a separately
authorized root operator must inspect/archive the old records and stale socket,
then manually re-register still-legitimate processes. No automatic pruning,
re-adoption, or unattended restart recovery is provided.

## Validation and limits

Native checks:

```bash
cargo test -p mvm-fc-lifecycle --lib
cargo test -p mvm-fc-lifecycle
cargo clippy -p mvm-fc-lifecycle --all-targets -- -D warnings
cargo fmt --all -- --check
git diff --check
```

Native process/storage/admission adapters, actual unprivileged file descriptor
mutation tests, publication fault boundaries and socket pairs cover authorization,
retained-handle use, evidence/permission changes, record corruption, per-UID
limits, protocol faults and deadlines. Native disk publication uses a portable
hard-link analogue, not the real Linux `O_TMPFILE` implementation.
These checks are **not evidence of real root serving,
Linux syscall behavior, storage crash durability or installed-service security**.
Production has no fixture trust bypass or configurable privileged locations.

`tests/linux_installed.rs` contains ignored installation-boundary witnesses.
They require separate approval, a disposable Linux builder test environment
with the exact trusted installation already active, explicit
`MVM_FC_LIFECYCLE_PRIVILEGED_TEST=1`, and selection of one exact ignored test
(not an unrestricted `--ignored` run). They do not install/start the service.
The invalid-payload non-root test is explicitly only a limited endpoint witness,
not authorization proof.

The root positive-control witness requires an already-running trusted candidate
described by test-only payload inputs `MVM_FC_TEST_PID`, `MVM_FC_TEST_OWNER_UID`
(nonzero), `MVM_FC_TEST_STATE_DIR`, and `MVM_FC_TEST_API_SOCKET`. These do not
override production service paths or trust rules. It first requires successful
root registration, then launches a separate same-payload probe with the owner UID
and requires non-root registration refusal. It writes a real durable registration
and leaves operator reconciliation necessary. Root must trust/install the
reviewed test harness before executing it: never elevate a user-writable test
binary or `cargo test` checkout. The child probe is not a standalone test.
Do not run these tests on the native macOS host. They are not a full privileged
lifecycle suite.

Remaining gates: fresh independent security review; actual privileged Linux
registration/termination, credential theft, inode substitution, pidfd refusal,
fsync/crash/restart fault tests; systemd/deployment and packaging review; atomic
trusted spawn integration. No root operation is authorized by this document.

Only after security validation may startup performance be compared on the same
release candidate, signed runtime and host: original invocation clock,
mandatory authentication, two warmups and twenty measured attempts, strict
per-sample startup <300 ms. Measure first service startup, restart and
accumulated registry state separately. No hidden durability work, source-cache
substitution or threshold relaxation is justified by this prototype.
