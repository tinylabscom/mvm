# The factory-edge demo

Three small programs run side by side, each allowed to reach only its own
destination. Two do inspection work. The third, the maintenance program, asks
for a destination it was not given. The host refuses and records that, and the
other two carry on.

This is the demo described in "Proposed factory-edge presentation" in
`specs/contracts/host-interface-distributed-execution.md`. Everything is
synthetic traffic.

## Run it

```sh
scripts/factory-edge-demo.sh
```

About 15 seconds. It starts the three programs and prints:

1. All three are running.
2. What each is allowed to reach.
3. What the host refused for the maintenance program: `DNS lookup of example.com`,
   not in its allow-list.
4. That the two inspection programs have nothing refused.
5. Every entry the host signed for the maintenance program's session
   (`mvmctl trust audit show`), and that the whole chain verifies.

Every `mvmctl explain` ends with `audit chain verifies clean`, which is the
evidence line. `scripts/factory-edge-demo.sh --down` removes the programs again.

## The same thing from the library

The Studio UI does these same four things through the `mvm-client` library, not
the command line:

| Demo step | Command line | Library (`mvm-client`) |
| --- | --- | --- |
| Start a program with one allowed destination | `mvmctl machine run -d --image curlimages/curl:8.21.0 --name N --allow-host H:443 -- CMD` | `LaunchRequest::builder(LifecycleMode::Persistent, image).name(N).command(CMD).allow_egress(H, 443).build()?`, then `LocalBackend::new().launch(request)` |
| List them | `mvmctl machine ls` | `inventory::list_local_inventory` |
| What a program is allowed | `mvmctl machine inspect N` | not available: `inspect_machine` returns status, backend, memory and ports but not the allowed destinations ([#5521](https://github.com/tinylabscom/mvm/issues/5521)); the UI can show what it asked for at launch |
| What the host refused, and the audit result | `mvmctl explain N` | `explain::explain_local_run("local", N)`, which returns the events, `egress_denials` and `chain_verified` |

`crates/mvm-client/examples/factory_edge.rs` runs the whole demo through the
library: `MVM_HOME=$HOME/.mvm-demo cargo run -p mvm-client --example factory_edge`.
Run on a source build, it started the three programs, listed them as running,
read back the maintenance program's refusal (`DNS lookup of example.com`) and
`chain_verified: true`, and showed the other two with no refusals. The
"what a program is allowed" row has not been run, since the call is not in a
release yet.

A launch blocks the thread that calls it, so starting the three with `join!` on
one thread ran them one after another (about 36 s on a loaded host, against 7 s
for the script). Start them from separate threads to overlap them.

Use a new name for each run, because `explain` by name is ambiguous when a name
has been used before.

## Set up a new Mac, once

From a checkout of this repository:

```sh
export MVM_HOME="$HOME/.mvm-demo"
MVM_VERSION=v0.28.0-rc.2 sh install.sh
export MVMCTL="${MVMCTL:-mvmctl}"
"$MVMCTL" --version
```

Only the install is required; no separate `mvmctl bootstrap` command.
`install.sh` prewarms shared artifacts in the demo home, and the script pulls
its image on first use. That first image acquisition may still be slower than
a prepared launch.

The demo needs an Apple Silicon Mac on macOS 26 or later, and working
internet and DNS, because each allowed destination is looked up when its
program starts.

Keep `MVMCTL` and `MVM_HOME` exported in the same terminal when running the demo
or `--down`. `MVMCTL` selects the executable for the script; it does not change
which executable a bare `mvmctl` command resolves to. Use `"$MVMCTL"` for setup
commands too, so preparation and launches use the same binary and cache.

To use an already-built binary from this checkout instead of the installed
release, set `export MVMCTL="$PWD/target/release/mvmctl"` before the preparation
commands above, and skip the installer command.

## Known limits

- The three programs start at the same time. A release from before the
  volume-lock fix refuses some of them with `another local volume lifecycle
  operation is already in progress`, so the script retries them, and on such a
  release the demo is as slow as before.
- A launch takes about 4 seconds on this release, so the demo takes about 15.
  The cause and the fix are written up in the factory-edge section of the
  contract document.
- Not shown: Studio's own view, the real maintenance and inspection tasks, and
  stopping and replacing a program.
