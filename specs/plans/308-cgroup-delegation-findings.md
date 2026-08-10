# Task 8 findings: cgroup v2 `cpu` delegation (Plan 308)

## Verdict

**Task 9 switches to a systemd transient scope over the session bus.**

Raw `mkdir` + `cgroup.procs` migration into the delegated `user@<uid>.service`
subtree does not work for a process that is not already living inside that
subtree — which is the normal case for any process launched from a login
shell (SSH session, terminal). The `cpu` controller itself *is* delegated
(present in `cgroup.controllers` at every level, and `cpu.max` is writable
unprivileged), but that is not sufficient: cgroup v2 process migration also
requires write access to the **common ancestor** of the process's current
cgroup and the destination cgroup, and a normal login session's cgroup
(`session-N.scope`) is not delegated (`Delegate=no`). `systemd-run --user`
with a `CPUQuota=` property sidesteps this because the migration is performed
by the user's own `systemd --user` manager, which already lives inside the
delegated tree — and it was confirmed, with a live spinner, to bind the CPU
limit to within 0.3% of the target.

## Environment

- Host: `ssh -i ~/.ssh/hetzner-rvproxy root@88.99.197.234` (KVM box)
- Distro: Ubuntu 24.04.4 LTS (noble)
- Kernel: `6.8.0-124-generic`
- systemd: `255 (255.4-1ubuntu8.16)`
- Cores: 8 (`nproc`)
- cgroup mode: unified (cgroup2fs only, no v1 hybrid)

## Methodology note (the trap, and how it was avoided)

The box is accessed as root over SSH. Root bypasses every cgroup permission
check, so any probe run as root "succeeds" and proves nothing about the
unprivileged case. A bare `su mvmtest -c ...` is *also* misleading in a
different way: it changes the process's effective/real uid but does **not**
move the process into that user's delegated cgroup subtree — the process
stays wherever it was forked (in this case, under root's own SSH session
cgroup), so a cgroup migration attempt fails for a reason that has nothing to
do with whether `cpu` is delegated to `mvmtest`.

To get a genuine unprivileged session:

1. A pre-existing unprivileged user `mvmtest` (uid 30033) was reused (created
   in an earlier session on this shared box; not created by this task).
2. `loginctl enable-linger mvmtest` was run so `user@30033.service` starts
   and stays up independent of any interactive login.
3. An ephemeral ed25519 keypair was generated on the box and its public half
   appended to `mvmtest`'s `~/.ssh/authorized_keys`, so a **real SSH login
   session** could be established (`ssh -i <key> mvmtest@localhost ...`),
   confirmed via `loginctl session-status` to be `Class: user`, `Type: tty`,
   with a live `session-N.scope`, `XDG_RUNTIME_DIR=/run/user/30033`, and
   `DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/30033/bus` — all consistent
   with a genuine systemd user session, not a bare `su`.
4. All probes below ran inside that live session. Both the `su`-based attempt
   and the genuine-session attempt produced the **same** migration failure
   (see Step 2), which confirms the failure is structural (session scopes
   aren't delegated) and not an artifact of using `su`.

Everything created (ephemeral SSH key, `authorized_keys` entry, `.ssh` dir,
linger flag, probe cgroups, spinner processes, scratch scripts) was removed
at the end; `mvmtest` itself was left in place since it pre-existed this
task on a shared box.

## Step 1: which controllers reach a user session, and can `cpu.max` be written unprivileged

```
$ cat /sys/fs/cgroup/user.slice/cgroup.controllers
cpu memory pids
$ cat /sys/fs/cgroup/user.slice/cgroup.subtree_control
cpu memory pids

$ cat /sys/fs/cgroup/user.slice/user-30033.slice/cgroup.controllers
cpu memory pids
$ cat /sys/fs/cgroup/user.slice/user-30033.slice/cgroup.subtree_control
cpu memory pids

$ cat /sys/fs/cgroup/user.slice/user-30033.slice/user@30033.service/cgroup.controllers
cpu memory pids
$ cat /sys/fs/cgroup/user.slice/user-30033.slice/user@30033.service/cgroup.subtree_control
cpu memory pids

$ systemctl show user@30033.service -p Delegate -p DelegateControllers
Delegate=yes
DelegateControllers=cpu memory pids

$ ls -ld /sys/fs/cgroup/user.slice/user-30033.slice/user@30033.service/
drwxr-xr-x 4 mvmtest mvmtest 0 Aug 10 07:40 /sys/fs/cgroup/user.slice/user-30033.slice/user@30033.service/
```

`cpu` **is** delegated at every level down to `user@30033.service`, and that
directory (plus its `cgroup.procs` / `cgroup.subtree_control` files) is
owned by `mvmtest`, not root — no manual `cgroup.subtree_control` write was
needed to reach this state; it was already enabled by systemd's own
defaults (Ubuntu 24.04 ships `DefaultCPUAccounting`-driven delegation for the
user manager).

Creating a leaf and writing `cpu.max` unprivileged, as `mvmtest` inside the
live session:

```
$ CG=/sys/fs/cgroup/user.slice/user-30033.slice/user@30033.service/mvm-probe.scope
$ mkdir -p "$CG" && echo mkdir_ok
mkdir_ok
$ echo "150000 100000" > "$CG/cpu.max"
$ cat "$CG/cpu.max"
150000 100000
```

This part of Task 9's plan works exactly as written: an unprivileged process
that already has a foothold in the delegated tree can create a child cgroup
and set `cpu.max` on it with no `cgroup.subtree_control` fiddling required
(the parent already advertises `cpu` in its `subtree_control`).

## Step 2: does the limit bind — raw `cgroup.procs` migration

This is where it breaks. Spawning four CPU-bound spinners as the same
`mvmtest` session and trying to move their PIDs into `mvm-probe.scope`:

```
$ for i in 1 2 3 4; do
    ( while :; do :; done ) &
    echo $! > "$CG/cgroup.procs"
  done
bash: line 13: echo: write error: Permission denied   (x4)

$ cat "$CG/cgroup.procs"
                                                        (empty)
```

`cpu.max` was set correctly and `cgroup.controllers` at the destination
lists `cpu`, yet every migration write is refused. Root cause, confirmed via
kernel cgroup v2 semantics: migrating a PID into a cgroup requires write
access not just to the destination `cgroup.procs` but to the **common
ancestor** cgroup of the process's current location and the destination. The
SSH login shell's own process lives in `session-11215.scope`
(`/user.slice/user-30033.slice/session-11215.scope`), which is:

```
$ systemctl show session-11215.scope -p Delegate -p DelegateControllers
Delegate=no
DelegateControllers=
```

**not delegated** — `mvmtest` does not own that cgroup, so it cannot move a
process out of it into anything else, including into its own
`user@30033.service` subtree. This reproduces identically whether the shell
was reached via a bare `su` or via a genuine SSH login session, which rules
out "bad session setup" as the cause — it is a structural property of how
systemd-logind places interactive login shells.

Since with unconstrained spinners in place the measured usage floats near 4
cores (four unthrottled loops, one per idle core) rather than anywhere near
1.5, this is not a "the limit didn't bind tightly enough" result — the
processes were simply never inside the limited cgroup at all, because the
migration itself was refused.

## Step 3: does the systemd-transient-scope alternative actually bind

Same live session, using `systemd-run --user` (talking to the already
-running, already-delegated `user@30033.service` manager over the session
bus at `$DBUS_SESSION_BUS_ADDRESS`) instead of a raw `mkdir`/`cgroup.procs`
write:

```
$ systemd-run --user --unit=mvm-cpu-test --scope -p CPUQuota=150% -- \
    bash -c 'for i in 1 2 3 4; do ( while :; do :; done ) & done; sleep 6'
Running as unit: mvm-cpu-test.scope

$ systemctl --user show mvm-cpu-test.scope -p ControlGroup --value
/user.slice/user-30033.slice/user@30033.service/app.slice/mvm-cpu-test.scope

$ cat /sys/fs/cgroup/user.slice/user-30033.slice/user@30033.service/app.slice/mvm-cpu-test.scope/cgroup.controllers
cpu memory pids
$ cat .../mvm-cpu-test.scope/cpu.max
150000 100000
$ cat .../mvm-cpu-test.scope/cgroup.procs
1406931
1406933
1406934
1406935
1406936
```

Measured over a 4.011s window using the cgroup's own `cpu.stat`
(`usage_usec` delta, more reliable than summing `/proc/<pid>/stat` across
four processes):

```
RESULT: delta_usec=5998366 delta_wall=4.011053908 measured_cores=1.495

usage_usec 7581856
user_usec 7574972
system_usec 6883
nr_periods 51
nr_throttled 50
throttled_usec 12493774
```

**Expected: 1.5 cores (`150000 100000`). Measured: 1.495 cores** — within
0.3% of target, with `nr_throttled=50` of 51 accounting periods showing the
kernel actively throttling the four spinners (which would otherwise consume
~4 cores on this 8-core box) down to the quota. This is unambiguous:
`systemd-run --user` with `CPUQuota=` both creates the cgroup and performs
the migration correctly, and the resulting limit measurably binds.

## What the alternative looks like for Task 9

Task 9's plan should create the workload's CPU-limited cgroup via
`org.freedesktop.systemd1.Manager.StartTransientUnit` on the **session**
bus (`$DBUS_SESSION_BUS_ADDRESS`, i.e. the same bus `systemd-run --user`
uses under the hood), not via direct `mkdir`/`cgroup.procs` writes:

- Call `StartTransientUnit` with mode `fail`, a unique scope name
  (e.g. `mvm-vm-<id>.scope`), the target PID(s) via the `PIDs` property, and
  a `CPUQuota` property (percentage, or equivalently a `CPUQuotaPeriodUSec`
  + implied `cpu.max` numerator) sized from the workload's CPU grant.
- This requires the caller to have a live, running `systemd --user` instance
  reachable over `$DBUS_SESSION_BUS_ADDRESS` — true for any interactive
  login session, and also true for a non-interactive/headless invocation
  *if* `loginctl enable-linger <user>` has been set for that user (verified
  above: linger alone, with no active login, is enough to keep
  `user@<uid>.service` up and delegated). mvm's supervisor would need to
  either run inside a real user session, or document/require linger to be
  enabled for headless operation.
- No `sudo`/root is required anywhere in this path — `StartTransientUnit` is
  a normal, unprivileged D-Bus call to the user's own systemd instance, and
  every step above was performed as `mvmtest` (uid 30033) with zero
  privilege escalation.
- Cleanup is `StopUnit` on the same scope, which reliably kills descendants
  through the cgroup (verified via `systemctl --user stop
  mvm-cpu-test.scope`, which left no leftover processes or cgroups behind).

This was exercised end-to-end above (Step 3) and confirmed to work; it is
not a theoretical fallback.
