# Guest process and file operations move into mvm-client

Issue #3261, task 6 of the order agreed on the issue.

`mvmctl machine proc`, `machine fs` and `machine cp` reached the guest agent
through code in `mvm-cli`: name validation, the transport probe (with the mock
agent's fast path under `test-support`), the RPC, the agent's error variant,
chunking, and the audit entries. That code is now `mvm_client::guest`. The CLI
verbs are formatters over it: they print tables, JSON, token and byte counts,
and map a wait's terminal event to an exit code. The host library will call the
same functions, so a guest operation is one implementation with one set of
audit entries, whoever asks.

| Operation | `mvm_client::guest` | Chain entries |
| --- | --- | --- |
| start, list, signal, kill a process | `start_process`, `list_processes`, `signal_process`, `kill_process` | RPC, plus `VmProcStart` / `VmProcSignal` / `Kill` |
| write a process's stdin | `send_process_input` | RPC per chunk, plus `VmProcStdin` |
| wait for a process | `wait_process` (streams events to a callback) | RPC |
| read, write a file | `read_file_chunks`, `write_file` (`write_file_chunks` for `cp`) | RPC per chunk, plus `VmFsMutate` for a write |
| list, stat, mkdir, remove, rename | `list_dir`, `stat`, `make_dir`, `remove`, `rename` | RPC, plus `VmFsMutate` for the three that change the guest |

`emit_vsock_rpc_audit` moves with them, and the CLI re-exports it for its
other guest verbs. `cp` keeps recording `VmFileCopy` itself and writes through
`write_file_chunks`, so a copy is not also recorded as a plain write, exactly
as before. `cp`'s private copy of `unwrap_fs` is gone.

These are DevOnly agent verbs: the agent refuses them on a sealed image. They
stay off `MvmClient`, which must remain answerable by a remote backend.

## Validation

- `cargo nextest run --no-fail-fast -p mvm-client -p mvm-cli --features
  mvm-cli/test-support` (the mock-agent path): 2514/2514 passed.
- `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D
  warnings`, `xtask check-all`, `just check-gated` and
  `scripts/check-crate-readmes.sh`: pass.
- New `guest` unit tests: the RPC entry for every common verb, an empty argv
  refused before any RPC, an invalid machine name refused before any RPC on
  each entry point, and the agent's error variant surfacing as an error. The
  read request's symlink policy test moved with its function.
