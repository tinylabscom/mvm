# Environment hygiene: one denylist for guest env and host helper spawns

Issue #3722, PS-12 of `specs/plans/2026-09-25-agent-sandbox-product-surface.md`.

Nothing kept loader, shell, interpreter, or password-manager session variables
out of a guest workload's environment, or out of the host helpers `mvmctl`
starts. A caller could pass `--env LD_PRELOAD=...` straight to a guest, and a
supervisor or network endpoint inherited `BASH_ENV`, `NODE_OPTIONS`, or an
`OP_SESSION_*` token from whoever ran `mvmctl`.

## What landed

- `mvm_core::env_hygiene` is the one filter. It covers four families: loader
  (`LD_*`, `DYLD_*`), shell (`BASH_ENV`, `ENV`, `BASH_FUNC_*`, `PROMPT_COMMAND`,
  `IFS`, `CDPATH`, `GLOBIGNORE`, `SHELLOPTS`, `PS4`), interpreter
  (`PYTHONSTARTUP`, `PYTHONPATH`, `PYTHONHOME`, `NODE_OPTIONS`, `NODE_PATH`,
  `PERL5LIB`, `PERL5OPT`, `PERLLIB`, `RUBYOPT`, `RUBYLIB`, `GEM_*`, the three
  Java option variables, `DOTNET_STARTUP_HOOKS`, `GOFLAGS`), and
  password-manager session (`OP_SERVICE_ACCOUNT_TOKEN`, `OP_CONNECT_*`,
  `OP_SESSION_*`, `BW_SESSION`). Matching is case-sensitive.
- `EnvReadmit` re-admits by exact name only. It refuses a glob pattern and a
  bare family prefix (`LD_`), so no single re-admission can reopen a family.
- **Guest seam: refuse.** Each of these paths names the variable and its
  family, never the value, and re-admits by exact name with `--allow-env NAME`:
  - `run` / `machine run --env` and a `--launch-plan` document's env
    (`commands/vm/exec/env_args.rs`, also applied by `--dry-run`)
  - `machine proc start --env` (`commands/vm/proc.rs`)
  - `mvm_client::guest::start_process`, which backs the host library's
    `guest.proc.start`. The host library has no re-admission field.
- **Host seam: drop.** `helper_command(program)` builds a helper's `Command`
  with every inherited denied variable removed, and logs each removed name at
  debug level. It is wired into these spawn sites:
  - the libkrun, HVF, HVF-restore, and QEMU supervisors
  - the QEMU vsock bridge and Firecracker's `sudo` signal
  - the network, GPU, broker, and audit-signer endpoints
  - hostd's service spawner, the host agent's worker, and its signer helper
  - the builder egress endpoint, the libkrun builder supervisor, the three
    QEMU builder launches, and the builder bootstrap helper
  - the builder-VM binary injector
  - the host `bash -c` runners that launch Firecracker
- `xtask check-helper-env-hygiene` runs in `check-all`. It pins those 26 spawn
  bodies by file and header. Each body must call `helper_command(` and must not
  call `Command::new(`, with comments, strings, and `#[cfg(test)]` items
  blanked first.
- A launch plan's env keys must now be plain shell names. The guest wrapper
  exports each key unquoted, so a key like `A;cmd` would have run `cmd`.

## Deliberately not filtered

- An OCI image's declared `Env`. It is the workload, not passthrough.
- Secret placeholder names. Their values are host-minted placeholders, and a
  placeholder is the sanctioned way to hand a guest a vault token.

No admission path audits env today (the `ExecutionPlan` has no env field), so
there is no audit entry to record denied names in. Refusals happen before plan
synthesis.

## What the gate does not do

It cannot discover a new helper spawn written somewhere else. Telling "starts a
helper" from "runs `codesign`" needs to know what the program is, which a text
gate cannot. A new helper spawn joins `HELPER_SPAWNS` in the change that adds
it.
