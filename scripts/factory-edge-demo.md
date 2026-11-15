# The factory-edge demo

Three small programs run side by side on one Mac, and each is allowed to reach
only its own destination. One of them asks for something it was not allowed, the
host refuses and records it, and the other two carry on. Then that program is
stopped and a fresh one takes its place.

## Run it

```sh
scripts/factory-edge-run.sh
```

It takes about 20 seconds. It starts the three programs, runs the demo against
them, and removes them again, even if the demo fails. Nothing is left running.

You need an Apple Silicon Mac on macOS 26 or later with the demo set up (see
"Set up a new Mac" below). Ari's Mac is already set up.

## What you will see

The demo prints one line for each thing it checks. A run that works ends with
`DEMO_RESULT=pass`.

1. The two inspection programs are working, each reaching only its own
   destination.
2. The maintenance program asks for a destination it was not allowed. The host
   refuses it, and the refusal can be read back afterwards.
3. The two inspection programs are not affected and keep working.
4. The audit record is checked and is intact.
5. The maintenance program is stopped and its session sealed.
6. A replacement starts as a fresh program and carries none of the old refusals.

## If it does not pass

The script stops at the first problem and prints a line starting `FAIL` or
`FINDING` that says what is missing. The usual causes:

- **Not set up.** `mvmctl` is not installed, or the demo home does not exist, or
  the test image is not in it. Follow "Set up a new Mac".
- **No network.** Every allowed destination is looked up when its program
  starts, so the demo needs working internet and DNS.
- **Something left over.** Run `scripts/factory-edge-stage.sh --down`, then run it
  again.

## Set up a new Mac

Do this once, from a checkout of this repository. It installs the release the
demo is verified against and prepares a home for it. The demo never installs or
prepares anything itself.

```sh
MVM_VERSION=v0.28.0-rc.2 MVM_SKIP_BOOTSTRAP=1 sh install.sh
export MVM_HOME="$HOME/.mvm-demo"
mvmctl image pull curlimages/curl:8.21.0
mvmctl run --image curlimages/curl:8.21.0 -- true
```

The last command builds the runtime the first time, which takes a few minutes.
The demo scripts use `~/.mvm-demo` by default, so nothing else needs setting.

## Presenting it

For a live presentation, start the programs ahead of time so the audience sees
only the demo itself:

1. `scripts/factory-edge-stage.sh` about ten minutes before. Staging earlier makes
   the audit record, and with it the readback, slower.
2. `scripts/factory-edge-demo-live.sh` for the live part, about 30 seconds.
3. `scripts/factory-edge-stage.sh --down` afterwards.

After a reboot the staged programs are gone, so stage again.

## What this does not show

- The Studio application's own view. The demo drives the command line, and Studio
  will do the same things through the `mvm-client` library.
- The real maintenance and inspection tasks. These are small scripted programs
  over synthetic traffic.
- Launches under one second. A launch takes a few seconds on this release, and
  the replacement in step 6 is a live launch.

More detail, including what was measured and why launches are slow, is in the
factory-edge section of
`specs/contracts/host-interface-distributed-execution.md`.
