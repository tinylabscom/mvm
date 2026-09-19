# The scope launcher watch no longer mistakes a pre-exec child for the payload

Issue #3477, second cause.

`BoundCommand::spawn` watches the launcher's command name to tell whether the
payload is running yet: `systemd-run` means the manager has not created the
scope, and any other name means it has. `Command::spawn` returns as soon as the
child has switched address space, and the kernel sets the new command name a
little later. So the first read could still see the name the child inherited
from the spawning thread. That name is not `systemd-run`, so the watch returned
"exec'd" at once and the creation deadline never ran.

The watch now records the spawning thread's name (`/proc/thread-self/comm`)
before the spawn and reads it as still launching until `systemd-run` has been
seen. The detached-launcher path has no spawning thread to record and is
unchanged.

The effect is not confined to the test. In production the unresponsive-manager
guard was bypassed nondeterministically. When the test hit the race it also
leaked its fake launcher: `spawn` returned the child, the test panicked, and
nothing killed it.

#3486 fixed a different race in the same test (a launcher found through a
`PATH` another test was changing).

## Evidence

A/B on an 8-core x86_64 Linux host, running the cross-built `mvm-core` lib
test binary (the whole suite, 2028–2030 tests) 15 times per build, with 16
busy loops for load:

- `main`: the unresponsive-manager test failed in 3 of 15 runs. Each failure
  left an orphaned fake launcher spinning at about 40% CPU.
- this change: 0 of 15.

400 isolated runs of that one test passed on both builds, so the race needs the
load of a full parallel suite, as in CI.

## Witnesses

- `the_name_inherited_from_the_spawning_thread_is_still_launching`
- `without_a_recorded_name_only_systemd_run_is_launching`
- `an_unresponsive_manager_fails_the_launch_instead_of_hanging_it`, which now
  holds under load
