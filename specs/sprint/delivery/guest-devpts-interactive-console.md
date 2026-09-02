# The guest never mounted devpts, so no OCI image could open a console

`mvmctl machine run --image rust -it -- /bin/bash` failed with:

```
Error: guest agent returned error: console open failed: openpty() failed
```

`openpty(3)` opens `/dev/ptmx` and then the slave the kernel allocated for it
at `/dev/pts/N`. devtmpfs supplies the `ptmx` node; it does not supply the
slave filesystem. The universal-initramfs boot path created `/dev/pts` as a
directory in `ensure_runtime_dirs` and never mounted `devpts` onto it, so every
`ConsoleOpen` request — `machine run -it` and `machine console` alike — died at
`openpty()` on every OCI image.

The empty directory is what made it survive: `/dev/ptmx` present plus
`/dev/pts` present reads as a working PTY setup at a glance, and only
`/proc/mounts` tells the two apart. Confirmed on a live guest before the fix:

```
$ mvmctl machine run --image alpine -- cat /proc/mounts
proc /proc proc ...
sysfs /sys sysfs ...
devtmpfs /dev devtmpfs ...
tmpfs /run tmpfs ...
tmpfs /tmp tmpfs ...
        # no devpts anywhere
```

## The same gap, two other places, already fixed

`nix/lib/mk-guest.nix` and `mvm-host-vm-init`'s `mount_pseudofs` both mount
devpts, and both carry a comment saying the block is kept symmetric with the
other. `guest_mount.rs` is the third side of that symmetry and was never
brought into it — the flake-built guests and the builder VM had the mount, and
only the universal-initramfs path (which is what `--image` boots) did not.

The `/dev/fd` family — `/dev/fd`, `/dev/stdin`, `/dev/stdout`, `/dev/stderr`
symlinked into `/proc/self/fd` — was missing from that path for the same
reason, and is fixed in the same function. Nothing creates them here: devtmpfs
makes device nodes, and this guest runs no udev, no mdev and no
systemd-tmpfiles. Without them bash process substitution fails with
`/dev/fd/63: No such file or directory`.

## Where it runs

`provision_pty_devices` is a step in `provision_guest_environment`, between the
pivot and the privilege drop. Both bounds matter: before the pivot the mount
lands on a `/dev` the workload never sees, and after the drop there is no
CAP_SYS_ADMIN left to mount with. A test asserts both.

Failure is loud but not fatal. A non-interactive workload needs neither the PTY
nor the symlinks, and refusing to boot over a console it will never open would
turn a degraded shell into a dead machine. It is reported directly rather than
through `note_optional_step`, which suppresses on a read-only rootfs: both land
on devtmpfs, so a sealed image is not an explanation here and the failure is
real either way.

A container runtime that already mounted devpts for the namespace, and took
CAP_SYS_ADMIN away afterwards, is recognised from `/proc/mounts` and skipped.

## Why no test caught this

The launch-modes suite covers `machine run --image alpine -- <cmd>` in a dozen
shapes and could not reach this one. `-t`/`--tty` refuses without a terminal on
stdin — "interactive `-t`/`--tty` needs a terminal on stdin" — and every step in
that suite drives `Command::output()`, which pipes stdin. The suite stopped at
the CLI's own gate and never asked a guest for a console. There was no
interactive scenario because there was no way to write one.

Three scenarios close it, in `s31_launch_e2e/cli_launch_modes.feature`:

- **an interactive run gets a real pseudo-terminal in the guest** — the actual
  `-it` shape, driven through a host PTY allocated by a new
  `I launch {string} on a terminal` step. Asserts the guest's `tty` answers
  `/dev/pts/N`; a console that was never allocated still runs the command and
  still prints, so only that answer distinguishes a PTY from a pipe.
- **the guest mounts devpts so a console can be opened** — the same defect as
  the mount it is, on the non-interactive path, so it runs on a host with no
  terminal to give.
- **the /dev/fd family resolves in the guest**.

`scripts/e2e-launch-modes.sh`'s `MIN_SCENARIOS` floor goes 17 → 20.

The unit tests are source-text assertions in `guest_mount.rs` rather than in
`guest_bootstrap.rs`, where they belong by subject: that module is
`cfg(target_os = "linux")`, so its tests never run on the macOS hosts this is
mostly developed on — which is where the missing mount would have been caught.

One of those tests initially passed with the fix commented out: a substring
search over the function body matched `// provision_pty_devices();` as happily
as the call, which is the exact shape of losing the step. It now parses
statement lines with comments stripped, and goes red when the call is removed
or commented.

## Verified live

macOS 26 / HVF, `--image alpine` and `--image rust`:

```
$ mvmctl machine run --image alpine -- sh -c 'grep /dev/pts /proc/mounts; readlink /dev/fd'
devpts /dev/pts devpts rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=000 0 0
/proc/self/fd

$ script -q /dev/null mvmctl machine run --image rust --env NAME=ari \
    --mount $PWD:/work -it -- /bin/bash -c 'tty; echo NAME=$NAME; ls /work/Cargo.toml'
/dev/pts/0
NAME=ari
/work/Cargo.toml
```

## The gate's own floor was unreachable

`scripts/e2e-launch-modes.sh` asserts a minimum count of scenarios actually
executed, so that a glob matching nothing cannot pass as a green gate. It was
set to 17 against an authored count of 17 — but one scenario, the launch-budget
threshold, is gated on `MVM_BDD_PERF_BUDGET=1`, so only 16 ever ran on a host
without it and the floor could never be met there.

It had never fired, because it is only reached after a fully green cucumber
run: `pipefail` fails the pipeline as soon as any scenario fails, and the
script exits before the check. The first all-green run on this host is what
surfaced it.

The floor is now 19 — the executed count, not the authored one — and the
comment says which of the two it is.
