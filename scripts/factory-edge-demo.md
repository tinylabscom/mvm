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
| Start a program with one allowed destination | `mvmctl run -d --name N --allow-host H:443 -- CMD` | `LaunchRequest::builder(LifecycleMode::Persistent, image).name(N).command(CMD).allow_egress(H, 443).build()?`, then `LocalBackend::new().launch(request)` |
| List them | `mvmctl machine ls` | `inventory::list_local_inventory` |
| What a program is allowed | `mvmctl machine inspect N` | not available: `inspect_machine` returns status, backend, memory and ports but not the allowed destinations ([#5521](https://github.com/tinylabscom/mvm/issues/5521)); the UI can show what it asked for at launch |
| What the host refused, and the audit result | `mvmctl explain N` | `explain::explain_local_run("local", N)`, which returns the events, `egress_denials` and `chain_verified` |

This table comes from reading the library's code and has not been run, so check
it against the library before building on it. Use a new name for each run,
because `explain` by name is ambiguous when a name has been used before.

## Set up a new Mac, once

From a checkout of this repository:

```sh
MVM_VERSION=v0.28.0-rc.2 MVM_SKIP_BOOTSTRAP=1 sh install.sh
export MVM_HOME="$HOME/.mvm-demo"
mvmctl image pull curlimages/curl:8.21.0
mvmctl run --image curlimages/curl:8.21.0 -- true
```

The last command builds the runtime the first time, which takes a few minutes.
It needs an Apple Silicon Mac on macOS 26 or later, and working internet and
DNS, because each allowed destination is looked up when its program starts.

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
