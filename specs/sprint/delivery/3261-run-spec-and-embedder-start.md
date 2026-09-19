# One spec builder, one profile policy, and a start that never builds

Issue #3261, the last part of task 5. It stacks on the machine-start
extraction.

For the host library to admit an SDK machine exactly as `mvmctl` admits the
same request, two things have to be shared: the start path (done in the
previous step) and the spec the start is admitted from. This change shares the
spec, and gives the library a start host that never builds.

- **The spec builder.** `mvm_client::launch::run_spec::RunSpec` is the part of
  a `machine run` both surfaces express: source (`RunSource`, exactly one),
  profile, sizing, ports, egress and peers, and the grant inputs.
  `into_machine_spec` resolves grants and the persisted network fields exactly
  as the CLI did. The CLI's `machine_run_spec` now builds a `RunSpec` from its
  flags and then sets only what it alone can express: volume strings, a
  healthcheck, agent verbs, a caller commitment.
- **The profile policy.** What each profile permits moves to
  `mvm_client::launch::profile`. The CLI keeps its `--profile` flag enum,
  including its per-value help, and converts it. Its `grants`, `from_name`,
  `as_str` and `summary` delegate, so there is one declaration of the policy.
  The three policy tests move with it.
- **The embedder's start host.** `EmbedderStartHost` takes the workload kernel
  only from the verified cache, boots an image resolved before the start
  (`resolve_boot_image`, using `mvm-client`'s resolver), and leases volumes
  from the local catalog. It refuses CLI-grammar volume strings rather than
  dropping them, and refuses a missing kernel with the command that fills the
  cache, rather than building one. The persistent start now returns the plan
  it admitted, for the library to report.

## Witnesses

- `machine_run_and_the_library_persist_the_same_spec_for_the_same_request`: the
  SDK's request (image, name, profile, port, egress), parsed as a real
  `machine run` invocation, persists the same spec as the library's `RunSpec`,
  apart from its creation time.
- `run_spec` tests: an image run, a manifest slot, an allow-list that becomes a
  grant, and refusals for a bad name, bad memory and a missing deployment.
- `the_embedder_host_boots_only_the_image_it_was_given`,
  `the_embedder_host_refuses_cli_grammar_volumes`,
  `the_embedder_host_does_not_build_a_missing_kernel`.

## Validation

- `cargo nextest run --no-fail-fast -p mvm-client -p mvm-cli`: 2465/2465
  passed.
- `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D
  warnings`, `xtask check-all` and `just check-gated`: pass.
