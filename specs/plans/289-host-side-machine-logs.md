# Host-side machine logs

**Status:** COMPLETE

## Goal

Make `mvmctl machine logs` read the console capture owned by the selected
workload backend from the host VM state directory. Reading logs must not
connect to, start, or otherwise depend on the retired interactive dev VM or
the headless Linux builder VM.

## Security and compatibility constraints

- Resolve VM state only through `mvm_core::config` so `MVM_HOME` isolation is
  preserved.
- Pass paths as process arguments; do not interpolate VM names or paths into a
  shell command.
- Preserve `--lines`, `--follow`, `--hypervisor`, and the pre-split
  `firecracker.log` fallback.
- Keep missing logs as an explicit error rather than silently returning empty
  output.

## Delivery checklist

- [x] Reproduce the macOS failure with a real-CLI regression test that disables
      dev-VM auto-start.
- [x] Resolve the backend-captured log from the host VM state directory and
      invoke host `tail` without a shell.
- [x] Cover console resolution, legacy fallback, missing streams, and the final
      CLI output.
- [x] Run formatting, workspace tests/checks, and zero-warning clippy.
- [x] Synchronize `specs/SPRINT.md` and `specs/REFACTOR-STATUS.md` with the
      validated result.
- [x] Make follow mode honor `--lines`/`-n` via `tail -n <lines> -f` and cover
      the exact host-process arguments.
