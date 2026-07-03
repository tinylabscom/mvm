# Task 3 Report: Auto-detect stdin at machine run dispatch + delete --stdin flag

## Status: DONE

## Commit

`8e9d9aa4` feat(run): auto-detect non-TTY stdin; remove the --stdin flag

## What was wired

### Flow: Args.stdin → guest Exec frame

`RunArgs.stdin` (Vec<u8>) populated at dispatch by `read_auto_stdin(stdin().is_terminal())`
→ `into_exec_args()` transfers it to `Args.stdin`
→ `build_exec_request()` transfers it to `ExecRequest.stdin`
→ `run_in_guest()` converts to `Option<String>` (empty Vec → None; non-empty → utf8_lossy)
→ `send_exec_streaming(stream, wrapper, stdin_str, ...)` → `GuestRequest::Exec { stdin, ... }`

### Files changed

- `crates/mvm-cli/src/commands/machine/mod.rs` — deleted `stdin: Option<String>` clap field; wired `read_auto_stdin` after `into_run_args()` in both `Transient` and `InteractiveTransient` arms; wired `read_auto_stdin` in `run_entrypoint_action` replacing `stdin: args.stdin.clone()`; removed `stdin: None` from `boot_persistent_by_name` literal.
- `crates/mvm-cli/src/commands/vm/invoke.rs` — changed `EntrypointCall.stdin: Option<String>` → `Vec<u8>`; replaced `read_stdin_payload(call.stdin.as_deref())?` calls with direct bytes handling (`is_empty() → default payload`).
- `crates/mvm-cli/src/commands/vm/exec.rs` — removed `#[allow(dead_code)]` from `Args.stdin`; added `stdin: args.stdin` to `build_exec_request`'s `ExecRequest` construction.
- `crates/mvm-cli/src/exec.rs` — added `pub stdin: Vec<u8>` to `ExecRequest`; in `run_in_guest` converted to `Option<String>` and passed to `send_exec_streaming`; added `stdin: Vec::new()` to all 10 inline `ExecRequest` construction sites.
- `crates/mvm-cli/src/commands/ops/mcp.rs` — added `stdin: Vec::new()` to cold-run `ExecRequest`.
- `crates/mvm-cli/src/commands/tests.rs` — updated `machine_run_entrypoint_flag_parses` (removed `--stdin` test arm); updated `machine_run_entrypoint_flags_require_entrypoint` (removed `--stdin` case).
- `crates/mvm-cli/tests/cli.rs` — new file; `machine_run_rejects_removed_stdin_flag` integration test.

## Dead_code allow removed

`#[allow(dead_code)]` on `Args.stdin` in `crates/mvm-cli/src/commands/vm/exec.rs` is gone. The field is consumed by `build_exec_request` → `ExecRequest.stdin`.

## TDD RED → GREEN

RED: test ran and panicked on `assert!(!out.status.success())` (flag still existed, command used to succeed or exit 0 on help check).
GREEN: `mvm-cli::cli machine_run_rejects_removed_stdin_flag PASS [1.529s]`

## Gate results

- `cargo fmt --all -- --check`: PASS
- `cargo clippy -p mvm -p mvm-cli -- -D warnings`: PASS
- `cargo build --bin mvmctl`: PASS
- `cargo nextest run -p mvm -p mvm-cli`: 1453 PASS / 1 pre-existing FAIL (`each_embedded_binary_starts_with_elf_magic` fails under `MVM_SKIP_EMBED_BINARIES=1` — zero-byte stubs aren't ELF; unrelated to this task)

## Concerns

None blocking. Note: because `MachineRunArgs.argv` has `trailing_var_arg = true` + `allow_hyphen_values = true`, clap absorbs unknown flags before `--` into argv rather than rejecting them. So `machine run --image alpine --stdin - -- /bin/cat` does NOT produce a clap "unexpected argument" error — it runs the command with `--stdin` as the first argv element (and the shell rejects it). The test checks that (a) `--help` output has no `--stdin` and (b) the command still exits non-zero.
