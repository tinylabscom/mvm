# Machine start's lifecycle half moves into mvm-client

Issue #3261, the third step of task 5. It stacks on the persistent-start move.

`mvmctl machine start`, which `machine run -d` reaches, mixed two things in
`machine::lifecycle::start_machine`: presentation (dry runs, JSON, prompts,
receipts, init commands) and the lifecycle itself. The lifecycle half is:
choose the backend, derive the enforced network policy from the spec's grants,
validate memory, resolve what to boot, and start it. That half is now
`mvm_client::launch::machine_start::start_machine_spec`. The CLI keeps the
presentation and calls it.

What differs between the processes that start machines comes through one
trait, `StartHost`, with the CLI's implementation in `CliStartHost`:

| `StartHost` method | CLI implementation | Why it is not in the core |
| --- | --- | --- |
| `workload_kernel` | the pinned kernel, else `ensure_workload_kernel` | may build a kernel through the builder VM |
| `resolve_image` | the CLI's OCI pipeline, plus its `ImageFetch` audit entry | ingest, trust and cosign, and a builder-VM materialization fallback |
| `prepare_volumes` | parse the spec's volumes, merge registered ones, lease | reaches the CLI's mount cache |

Deployments and built manifest slots are resolved in the core. They read and
verify files and never build. `resolve_effective_hypervisor`,
`resolve_local_deployment` and `LocalDeployment` move with it, and the CLI
re-exports them. `record_machine_started` replaces the CLI's
`mark_machine_started`. The caller still stamps the spec only after its
post-boot init commands succeed, as before.

Two orderings shift, and neither changes what is admitted or booted.
`require_hypervisor_selectable` now runs after the receipt input is computed,
rather than before. Volume declarations are parsed when volumes are prepared,
after the boot source is resolved.

Image acquisition behind `StartHost` is a seam, not a finished answer.
`mvm-client` has its own, simpler OCI resolution for `mvm_client::launch`, so
the two pull paths still differ. Converging them is a separate item on the
plan.

`mvm-client` also declares `mvm-fs`'s `test-support` for its own tests. A test
moved in the previous stage needs it, and it was only being enabled through the
CLI's dev-dependencies whenever the two crates built together.

## Witnesses

- `an_image_spec_boots_what_the_host_resolved`
- `a_spec_with_nothing_to_boot_is_refused`
- `a_missing_deployment_is_refused_before_the_host_is_asked`
- `direct_boot_takes_kernel_and_rootfs_from_the_environment`
- `recording_a_start_stamps_the_digest_and_time`
- The three hypervisor-resolution tests, moved from the CLI with the function.

## Validation

- `cargo nextest run --no-fail-fast -p mvm-client -p mvm-cli`: 2456/2456
  passed. `mvm-client` alone: 394/394.
- `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D
  warnings`, `xtask check-all` and `just check-gated`: pass.
