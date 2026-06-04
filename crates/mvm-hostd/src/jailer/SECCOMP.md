# mvm-jailer-lite seccomp profile

`ConfinementSpec::firecracker_bridge()` allowlists the syscalls
required for: read packets from passt (read, splice, recvmsg);
write audit-chain entries (write, fsync, openat, close); socket
bind/accept/connect; memory + threading (mmap, munmap, futex,
mprotect); time (clock_gettime); signal handling (rt_sigprocmask,
rt_sigaction); process metadata (getpid, gettid, getuid, getgid,
getrandom); epoll multiplexing.

## Refusal posture

Default action on disallowed syscall: **Trap** → SIGSYS, visible in
core dumps + reproducible in tests.

`SeccompAction::Trap` (vs `SeccompAction::Errno(EACCES)`) is
intentional: the `mvm-firecracker-bridge` sidecar is *expected* to be
killed by SIGSYS on a forbidden syscall, and the supervisor's
`BridgeRestartPolicy::HardFail` (ADR-064 §Decision 6) is the cleanup
mechanism — the dead bridge tears down the VM. `Errno` would let a
compromised bridge observe the rejection, retry, or pivot to a
different attack, which is exactly what we want to forbid: there is
no graceful in-process recovery for a violating syscall in this
threat model.

Adding a syscall to the allowlist requires deliberate review (this
file is the audit point). Never add: execve, setuid, setgid, ptrace,
capset. The `firecracker_bridge_allowlist_rejects_dangerous_syscalls`
unit test in `lib.rs` asserts these are absent.

## Adding a syscall

One place changes: `BRIDGE_SYSCALLS` in `src/seccomp.rs`. Add a
`(name, libc::SYS_*)` row in **both** the `#[cfg(target_arch =
"x86_64")]` and `#[cfg(target_arch = "aarch64")]` blocks (or under a
common cfg if the syscall exists identically on both).
`ConfinementSpec::firecracker_bridge()` in `src/lib.rs` derives its
`allowed_syscalls` list from `BRIDGE_SYSCALLS`, so the policy layer
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
`epoll_pwait`. The fold happens inside `BRIDGE_SYSCALLS` so the
policy layer stays arch-agnostic — `ConfinementSpec` mentions only
names, never numbers.
