# Host-side machine logs

**Status:** COMPLETE, mechanism superseded by plan 283

The goal below — read the console capture host-side, never through a VM — was
met here and is still met. The `mvm_runtime::microvm::logs` implementation that
met it no longer exists: plan 283's stream plane replaced the whole reader with
`mvm_core::stream_client` (broker, then durable transcript, then the same
host-side console capture), and `--hypervisor` became its own reader over
`config::vm_hypervisor_log`. Two constraints below still hold in the
replacement; one does not:

- Host-side resolution through `mvm_core::config`: held. The explicit-root
  `vms_dir_at` / `vm_state_dir_at` helpers this plan added are what the
  replacement resolves through.
- No shell interpolation of names or paths: held, and strengthened — the
  replacement spawns no `tail` at all and reads the files in-process.
- Missing logs as an explicit error: held. A VM with no broker, no transcript
  and no console capture fails with `StreamError::NoCapture`, naming every
  path it looked in.
- `--lines` / `--follow` / `--hypervisor`: held.
- The pre-split `firecracker.log` fallback: **not held**. Plan 283 treats the
  hypervisor log as a separate artifact from workload output, so the workload
  reader no longer substitutes it when `console.log` is absent; the same bytes
  are reachable with `machine logs --hypervisor`, and the substitution is not
  performed silently in its place — the reader errors and names what it looked
  for. A pre-split VM state directory therefore needs the explicit flag.

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
- [x] Route isolated test state through an explicit-root `mvm_core::config`
      helper, isolate the CLI subprocess home, and pass both home policy gates.
