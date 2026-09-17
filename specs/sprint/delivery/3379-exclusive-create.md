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
equivalent, or a `link`+`unlink` fallback when the kernel supports neither
(`tempfile` picks between these) — so the filesystem itself admits exactly
one writer. If even the no-clobber *flag* is unsupported on the filesystem
(`EOPNOTSUPP`/`ENOTSUP`, seen on some FUSE mounts and non-APFS macOS
volumes), `atomic_write_new` falls back to a bare `link(2)`, which POSIX
defines as exclusive outright and has no such flag to be unsupported.

The loser's temp file is cleaned up automatically. Its error carries a
private marker type (`LostCreateRace`, wrapping the original `io::Error`
unmodified) rather than a bare `AlreadyExists` `io::Error` — a generic
`AlreadyExists` can also come from an earlier step (`create_dir_all` finding
a stray non-directory file where a parent directory belongs), and that must
not be misread as a lost race. `is_already_exists` checks for the marker
specifically, walking the `anyhow` context chain via `downcast_ref` so it
sees through any context a caller layered on top. `mvm-client`'s
`persist_definition` maps that signal to `MvmError::Conflict` instead of the
generic backend error it used to surface. `--force` and
`overwrite_machine_spec` are untouched — both still go through the
unconditional `atomic_write`.

Every other `machine create`/`machine run -d` code path in `mvm-cli`
(`spec_ops::create_machine`, `lifecycle::start_machine`,
`runtime::persist_and_boot_machine`) calls the same `save_machine_spec`, so
they inherit the fix without their own change; none of them had a
separate check-then-write of their own to remove. The `machine.create` audit
entry was already gated behind the `save_machine_spec` call by `?`, so a
losing writer never gets one.

The lost-race message no longer says only "pass --force to overwrite": every
caller reaching that arm already believed nothing was there when it decided
to create, so a caller that had already passed `--force` and still lost the
race would be told to do something it already did. It now names both real
fixes — the spec may have been created concurrently by another caller
(retry), or it was already there under a stale assumption (force) — so
neither reading is misled.

## Tests

- `atomic_write_new` / `is_already_exists` / `is_rename_flag_unsupported`
  unit tests (`mvm-core`): creates when absent; refuses and leaves the
  winner's bytes untouched when the target exists; leaves no orphaned temp
  file behind; `is_already_exists` sees through an `anyhow` context wrapper
  but is false for an unrelated `AlreadyExists` I/O error that isn't the
  marker type; `is_rename_flag_unsupported` recognizes `Unsupported` and
  nothing else. The `Unsupported`-triggered `link(2)` fallback path itself
  has no test double at the syscall boundary — there is no seam to inject an
  `ENOTSUP` from `persist_noclobber` without contorting the function — so
  only the pure classifier is unit-tested directly; the fallback logic
  mirrors the already-tested primary path's error classification.
- `concurrent_saves_of_one_name_produce_exactly_one_success` (`mvm-runtime`):
  16 threads call `save_machine_spec` for the same name against one isolated
  `MVM_HOME`; exactly one succeeds and the rest see the "already exists"
  message. This one races on the exclusive rename itself, so the result is
  deterministic rather than a timing bet.
- `concurrent_persistent_creates_of_one_name_produce_exactly_one_success`
  (`mvm-client`): the same race through `LocalBackend::create_from_request`,
  asserting the losers surface `MvmError::Conflict`. Each thread now carries
  a distinct config (`cpus`): with an identical config, a thread that loses
  the write race but then observes the winner's spec afterward would take
  the `Reuse` branch and return `Ok` too, which made `successes == 1` a
  timing bet rather than a proof. A different config routes every loser
  through a refusal (still `Conflict`) regardless of which step it loses at.
- The existing reconcile tests (reuse, recreate, force) still pass unchanged.
