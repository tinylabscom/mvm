# The persistent start path moves from the CLI into mvm-client

Issue #3261, the second step of task 5. It stacks on the admission move
(`3261-admission-into-client.md`).

`mvmctl machine run` with `-d`, `--up-json`, `--ttl` or `--port` takes the
persistent path. The SDK's invocations always do. That path ends in
`mvm_client::start_prepared`, and everything in front of it lived in the CLI:
the start function itself, its runtime-source policy (runtime overlay,
universal initramfs, SDK sidecar), runtime-overlay acquisition, the
enforced-grants report, and the start-config builder. Those now live in
`mvm-client`:

| was (`crates/mvm-cli/src/commands/`) | now (`crates/mvm-client/src/launch/`) |
| --- | --- |
| `vm/up/oci_persist.rs` | `persistent.rs` |
| `vm/up/runtime_source.rs` | `runtime_source.rs` |
| `runtime_overlay.rs` | `runtime_overlay.rs` |
| `vm/up/grants_report.rs` | `grants_report.rs` |
| `shared/start.rs` (`VmStartParams`) | `start_params.rs` |

`preflight_network` and `parse_port_spec` move with them, and the CLI
re-exports `preflight_network`. `parse_port_spec`'s three tests move to the
function.

Two things stay on the CLI's side of the call, as parameters rather than as
calls inside the start:

- **The workload kernel.** The CLI's `ensure_workload_kernel` may build one
  through the builder VM, and a library embedder must never build. The start
  now takes a resolved `kernel_path`, and the CLI resolves it first.
- **Registered-volume merging.** It reaches the CLI's mount cache. The start
  now takes the prepared `LaunchPreparation` lease guard and commits it after a
  successful backend start, exactly as before.

Output goes through `mvm_runtime::ui`, which the CLI's `ui` module already
mirrored, so the CLI's output is unchanged. For a library,
`mvm_runtime::ui::set_chrome_to_stderr` keeps it off the host program's
stdout.

`mvm-client` gains a `release-channel` feature forwarding to `mvm-build`'s, and
the CLI's `release-channel` forwards to it, so the moved release-channel test
runs under the same condition as before.

The next change points `mvm_client::launch` at this path, so the library
launches with the plan the CLI gives the same request.

## Validation

- `cargo nextest run --no-fail-fast -p mvm-client -p mvm-cli`: 2451 run, 2450
  passed. The one failure,
  `the_readiness_probe_distinguishes_an_idle_pipe_from_a_written_one`, is a
  known load-sensitive test and passed when run alone.
- `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D
  warnings`, `just check-gated` and `scripts/check-crate-readmes.sh`: pass.
- `xtask check-all`: pass, after repointing the `report_enforced_grants`
  control in `xtask/dormant-controls.toml` to the file it moved to.
