# Exclusive machine create

`save_machine_spec` checked `path.exists()` and then renamed a temp file over
the target unconditionally. Two `machine create`s (or two persistent
`machine run -d`/`launch()` calls) racing the same name could both pass the
check, and the second rename silently replaced the first machine's
definition — the loser's launch had already committed to the config it
observed, so nothing downstream noticed the swap.

The non-force path no longer checks-then-writes. `save_machine_spec` now
writes through a new `atomic_write_new` (`mvm-core::util::atomic_io`): a
no-clobber rename — `renameat2(..., RENAME_NOREPLACE)` on Linux, the macOS
equivalent, or a `link`+`unlink` fallback where neither is available — so the
filesystem itself admits exactly one writer. The loser's temp file is cleaned
up automatically and its error carries an `AlreadyExists` `io::Error`
(`is_already_exists`, chain-aware via `anyhow::Error::downcast_ref`) rather
than a generic write failure. `mvm-client`'s `persist_definition` maps that
signal to `MvmError::Conflict` instead of the generic backend error it used
to surface. `--force` and `overwrite_machine_spec` are untouched — both still
go through the unconditional `atomic_write`.

Every other `machine create`/`machine run -d` code path in `mvm-cli`
(`spec_ops::create_machine`, `lifecycle::start_machine`,
`runtime::persist_and_boot_machine`) calls the same `save_machine_spec`, so
they inherit the fix without their own change; none of them had a
separate check-then-write of their own to remove. The `machine.create` audit
entry was already gated behind the `save_machine_spec` call by `?`, so a
losing writer never gets one.

## Tests

- `atomic_write_new` unit tests (`mvm-core`): creates when absent, refuses
  and leaves the winner's bytes untouched when the target exists, leaves no
  orphaned temp file behind, and `is_already_exists` sees through an
  `anyhow` context wrapper.
- `concurrent_saves_of_one_name_produce_exactly_one_success` (`mvm-runtime`):
  16 threads call `save_machine_spec` for the same name against one isolated
  `MVM_HOME`; exactly one succeeds and the rest see the "already exists"
  message. This one races on the exclusive rename itself, so the result is
  deterministic rather than a timing bet.
- `concurrent_persistent_creates_of_one_name_produce_exactly_one_success`
  (`mvm-client`): the same race through `LocalBackend::create_from_request`,
  asserting the losers surface `MvmError::Conflict`.
- The existing reconcile tests (reuse, recreate, force) still pass unchanged.
