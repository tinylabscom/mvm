# Withdrawn: "fork in a fresh PID namespace fails under virtualization"

**Do not file this upstream.** This note used to hold a bugzilla.kernel.org
report claiming that fork/clone/clone3 inside a freshly created PID namespace
fails with ENOMEM/EINVAL after one or two children, under TCG, HVF and KVM,
on kernels 6.1 through 6.18. There is no such bug. Every reproducer ran
`unshare -Urmp …` without `-f`/`--fork`, and the failure is documented kernel
behaviour for that invocation.

## What actually happens

- Without `--fork`, `unshare` calls `unshare(CLONE_NEWPID)` and execs the
  command in its **own** (parent) PID namespace. Only the command's children
  enter the new namespace, and the first child becomes that namespace's
  PID 1.
- When that first child exits, the namespace has no init. Allocation is
  disabled (`PIDNS_ADDING` is cleared), so `alloc_pid()` returns `-ENOMEM`
  for every later fork into it (see pid_namespaces(7)). The result is "one or
  two children, then ENOMEM with gigabytes free and no reclaim".
- The exec'd program is in the parent namespace while `pid_ns_for_children`
  points at the new one, so `copy_process()` rejects `CLONE_THREAD` with
  `-EINVAL`. This is the Go runtime's
  `failed to create new OS thread (errno=22)` / `newosproc`.

Neither depends on the kernel configuration, the toolchain, the VMM or the
kernel version, which is why the matrix in #3599 found every combination
failing.

## Evidence

Bare metal (Hetzner, `systemd-detect-virt` = `none`, Ubuntu 6.8.0-139,
util-linux 2.39.3), 2026-09-24:

```
$ unshare -Urmp sh -c 'for i in 1 2 3 4 5 6 7 8; do (true) 2>/dev/null || printf F; done; echo DONE'
sh: 1: Cannot fork
$ unshare -Urmpf sh -c 'echo "pid in ns: $$"; for i in 1 2 3 4 5 6 7 8; do (true) 2>/dev/null || printf F; done; echo DONE'
pid in ns: 1
DONE
$ unshare -Urmp  python3 -c 'import threading; t=threading.Thread(target=lambda:None); t.start(); t.join(); print("thread ok")'
RuntimeError: can't start new thread
$ unshare -Urmpf python3 -c 'import threading; t=threading.Thread(target=lambda:None); t.start(); t.join(); print("thread ok")'
thread ok
```

The draft's claim that bare metal was unaffected came from production
workloads, which run under container runtimes that set up PID 1 correctly. The
reproducer itself was never run on bare metal.

## What stays open

The Kubernetes impact in #3599 ("CoreDNS and other Go pod inits die at
startup") was inferred from these probes. It was never observed through a real
container runtime. Whether pod sandboxes work on the `workload-k8s` kernel is
unknown until a real k3s pod runs; any hand-written PID-namespace probe must
use `--fork` (or be PID 1 itself).
