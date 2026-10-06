# mvm-jailer-lite seccomp profile

`ConfinementSpec::network_endpoint()` allowlists the syscalls
required for: read request bytes (read, splice, recvmsg);
write audit-chain entries (write, fsync, openat, close); socket
bind/accept/connect; memory + threading (mmap, munmap, futex,
mprotect); time (clock_gettime); signal handling (rt_sigprocmask,
rt_sigaction); process metadata (getpid, gettid, getuid, getgid,
getrandom); epoll multiplexing.

## Refusal posture

Default action on disallowed syscall: **Trap** → SIGSYS, visible in
core dumps + reproducible in tests.

`SeccompAction::Trap` (vs `SeccompAction::Errno(EACCES)`) is
intentional: a confined role is *expected* to be
killed by SIGSYS on a forbidden syscall, and the supervisor's
`BridgeRestartPolicy::HardFail` (ADR-003 §Decision 6) is the cleanup
mechanism — the dead bridge tears down the VM. `Errno` would let a
compromised bridge observe the rejection, retry, or pivot to a
different attack, which is exactly what we want to forbid: there is
no graceful in-process recovery for a violating syscall in this
threat model.

A refusal is not silent. `seccomp::apply` installs a `SIGSYS` handler
before the filter (`refusal_report.rs`) that writes one line to stderr —
the process, the architecture and number of the refused call, and the
self-test probe running at the time — and then re-raises, so the
process still dies of `SIGSYS` and the refused call never runs. The
launcher reads that status (it peeks at its unreaped child with
`waitid(WNOWAIT)`; a bare `kill(pid, 0)` answers for a zombie) and
quotes the line back to the operator.

The handler does not make the trap any more catchable than it already
was: `rt_sigaction` is on the allowlist, so a compromised process could
always install its own `SIGSYS` handler. `Trap` stops the call; it does
not, on its own, stop the process from observing that it was stopped.

## Self-test

Right after confining itself, `mvm-network-endpoint` runs
`self_test::ConfinementSelfTest::network_endpoint` on the confined
thread, before it reports ready: thread creation, a blocking-pool round
trip, clock and entropy, resolver set-up (`getaddrinfo` for
`localhost`, `res_init`, the UDP upstream socket), the trust-store
directory walk, the audit write path (create, `flock`, `fdatasync`,
rename, unlink), and a Unix-socket accept. These are the paths that
otherwise run only on first use, minutes into a session. A gap now
kills the endpoint at startup, the reporter names the probe, and the
launcher reports it before any guest boots.

The probes run under the C library the binary links. Release binaries
link musl statically, development builds link glibc, and the two do not
issue the same syscalls — musl's `open` on x86_64 is the legacy `open`,
glibc's is `openat`. Run the self-test against a musl build when
reviewing an allowlist change; `tests/confinement_self_test.rs` runs it
under the real filter and asserts that a filter missing a required call
is reported with the probe's name.

Adding a syscall to the allowlist requires deliberate review (this
file is the audit point). Never add: execve, setuid, setgid, ptrace,
capset. The `confined_role_allowlist_rejects_dangerous_syscalls`
unit test in `mod.rs` asserts these are absent.

## Adding a syscall

One place changes: `CONFINED_ROLE_SYSCALLS` in `seccomp.rs`. Add a
`(name, libc::SYS_*)` row in **both** the `#[cfg(target_arch =
"x86_64")]` and `#[cfg(target_arch = "aarch64")]` blocks (or under a
common cfg if the syscall exists identically on both).
`ConfinementSpec::network_endpoint()` in `mod.rs` derives its
`allowed_syscalls` list from that table, so the policy layer
picks up the new row automatically — no second edit, no drift.

If the name lands in the spec but the row is missing,
`confine_self` returns `JailerError::SeccompInstall("unknown syscall
name …")` at startup — fail-closed, exactly the discipline we want.
The `bridge_syscalls_has_no_duplicate_names` test guards against a
future arch-block edit accidentally shipping two rows for the same
name.

## Architecture differences

`stat` / `lstat` are x86_64-only; on aarch64 they're folded into
`fstatat`. `epoll_wait` is x86_64-only; on aarch64 it's folded into
`epoll_pwait`. `open` and `rename` are x86_64-only; on aarch64 they're
folded into `openat` and `renameat`. The fold happens inside
`CONFINED_ROLE_SYSCALLS` so the
policy layer stays arch-agnostic — `ConfinementSpec` mentions only
names, never numbers.
