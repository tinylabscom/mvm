# A library embedder starts a machine through the CLI's start path

Issue #3261.

`mvm_client::launch::machine_start::start_machine_spec` is the lifecycle half of
`mvmctl machine start`. Everything that varies by process sits behind
`StartHost`, and until now the CLI's `CliStartHost` was its only implementation.
That host may build a kernel through the builder VM and reads the CLI's mount
cache, and a library loaded into someone else's process must do neither. So the
host library could not start a machine through the same admission as `mvmctl`.

`EmbedderStartHost` is the second implementation:

- **Kernel.** Only from the verified cache. A missing kernel is refused, and
  the error says how to fill the cache; nothing is built.
- **Image.** Resolved before the start, with the client's own resolver
  (`resolve_boot_image`), because resolution is async and the start is not.
  The host boots only the image it was given, and only for the reference it
  was given it for.
- **Volumes.** Leased from the local catalog. A spec carrying CLI-grammar
  volume strings is refused, because this side has no parser for them, and
  dropping them would boot a machine without the mounts its spec asked for.

`start_persistent_oci_machine` and `MachineStart` now also return the
`AdmittedPlan` the machine booted under. That lets a caller report the plan
without looking it up again.

## Witnesses

- `the_embedder_host_boots_only_the_image_it_was_given`
- `the_embedder_host_refuses_cli_grammar_volumes`
- `the_embedder_host_does_not_build_a_missing_kernel`
