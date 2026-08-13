# 2400 — check-vsock-only-egress was scanning zero files

The claim-10 witness `xtask check-vsock-only-egress` had been passing
vacuously. `GUARDED_PATHS` still named the pre-driver-seam locations under
`crates/mvm-runtime/src/{vmm,hvf,driver/fc.rs,libkrun.rs,vsock_egress_bridge}`,
all of which moved to `mvm-vmm` and `mvm-backends` during the driver-seam
convergence. `collect_rs_files` no-ops on a path that is neither a file nor a
directory, so every entry resolved to nothing and the gate printed
`clean (0 files; …)` — reporting a security claim as verified after reading no
source at all.

The claim itself was never violated: the production drivers are NIC-free, and
that was confirmed by hand. What was broken was the evidence.

## Delivered

- `GUARDED_PATHS` repointed at the six paths that implement a workload guest's
  device model and production launch paths today: `mvm-vmm`'s `vmm/` and
  `vsock_egress_bridge/`, plus the `driver/{fc,hvf,hvf_restore,libkrun}`
  `VmmDriver` impls in `mvm-backends`.
- `driver/qemu.rs` and everything under `legacy/` excluded, with the reason
  recorded in the module docs: QEMU is a Tier-2 dev/test backend ADR-001
  deliberately keeps outside claim-10 egress enforcement, and the legacy shims
  are bench/example-only, unreached from `AnyBackend`'s production dispatch.
  `fc/snapshot.rs` is excluded too — it parses the `network-interfaces`
  snapshot field in order to assert it is empty, so guarding it would flag its
  own fail-closed check.
- Two backstops against silent rot: `check_guarded_paths_exist` turns a missing
  guarded path into a hard error naming the stale entry, and
  `check_scanned_file_floor` fails closed when the scan covers fewer files than
  the guard list should hold, rather than reporting a suspiciously small
  "clean".

Files scanned: **0 → 24** across 6 guarded paths.

## Witnesses

`xtask/src/check_vsock_only_egress.rs` tests, all in `cargo nextest run -p xtask`:

- `every_guarded_path_exists_in_this_workspace` — goes red the next time one of
  these paths moves, instead of the gate going quiet.
- `check_guarded_paths_exist_names_every_stale_entry` — the error names each
  missing entry.
- `check_scanned_file_floor_rejects_a_near_empty_scan` — the exact old failure
  mode (zero files reading as clean) now fails.
- `scan_files_forbidden_skips_comments_and_flags_code_tokens` — the gate still
  catches a real forbidden token and still ignores prose.
