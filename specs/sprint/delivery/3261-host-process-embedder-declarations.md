# 3261 — the runtime knows whether it is `mvmctl` or a loaded library

Groundwork for the host library that replaces the SDK's argv transport. Before
the crate can exist, the runtime has to stop assuming the process it is running
in is `mvmctl`.

## What assumed it

Two families of call, both reached through `std::env::current_exe()`:

- **Sibling-binary resolution.** `mvm-hvf-supervisor`, `mvm-network-endpoint`,
  the builder agent and the rest are looked up beside the running executable,
  because an installed release puts them there. Inside a library that
  executable is the host program — `python3`, `node`, a test harness — and
  nothing useful sits beside it.
- **Re-running ourselves.** The builder-VM bootstrap ladder, the guest-agent
  build, the builder egress supervisor and the health probe's restart command
  all run the current executable again with a hidden internal subcommand. In a
  library that re-runs the interpreter.

Neither is wrong for the CLI. Both are wrong for a library, and the failure
mode is the one worth avoiding: resolution succeeds against the wrong
directory, or a spawn starts a process the caller never asked for.

## The shape

`HostProcess` (`crates/mvm-vmm/src/host/aux_bin/host_process.rs`) carries the
two facts those paths need: a declared helper directory, and whether the
process is a library embedder. `declare_host_binary_dir` and
`declare_library_embedder` set them, and `refuse_cli_spawn(CliSpawn::_)` is the
one refusal every would-be CLI spawn goes through, so a new spawn site cannot
quietly skip it.

Three decisions worth recording:

- **Set-once process globals, not environment variables.** Mutating the
  environment of a multithreaded process is unsound, and a library is loaded
  into one by definition. `declare_host_binary_dir` accepts a repeat of the
  same directory — a library initialiser that runs twice is harmless — and
  refuses a different one, because silently keeping the first leaves the second
  caller resolving against a directory it never named, and silently taking the
  second changes which binaries the already-resolved neighbours were paired
  with.
- **Resolution reads a value, not the globals.** Only `HostProcess::current()`
  touches the `OnceLock`s. Every other function takes a `&HostProcess`, so a
  test constructs the exact process it wants to describe and leaks nothing into
  another test — which a set-once global otherwise guarantees.
- **Refuse before the source-checkout test.** The bootstrap ladder declines
  (`Ok(false)`) when it is not in a checkout, and a decline reads to the caller
  as permission to carry on in-process. An embedder has to get a refusal
  instead, and get the same one whether or not the cache is cold.

## Deliberately unchanged

The remaining `current_exe()` callers are CLI-only — `mvm-cli`'s `bench` and
`update`, and `mvm-observability`'s log path. The host library links
`mvm-client`, not `mvm-cli`, so they are not reachable from it and converting
them would assert a boundary that does not exist.
