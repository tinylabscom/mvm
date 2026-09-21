# Persistent environment refusal

Delivered 2026-09-21 for issue #3470.

## Problem

`mvmctl machine run --env KEY=VALUE` shares the transient run argument parser,
but `-d`, `--up-json`, `--ttl`, a health check, or `--port` selects a persistent
machine. The persistent `MachineSpec` has no environment field, so the accepted
value disappeared before boot. Python and TypeScript live
`Sandbox.create(env=...)` emitted that exact persistent command and inherited
the same silent loss.

## Resolution

- `MachineRunArgs` validates environment delivery immediately after the
  double-dash flag guard and before source resolution, image/flake work, or
  runtime selection. Every persistence trigger refuses `--env`; transient
  runs retain the existing environment override.
- The refusal names the supported declarative path: put persistent workload
  environment in the image or workload manifest.
- Python and TypeScript live `Sandbox.create` refuse every non-empty `env`
  before invoking `mvmctl`. Their error also names
  `Sandbox.commands.start(..., env=...)` for command-scoped environment.
- SDK record mode is unchanged: `Sandbox.create(env=...)` remains part of the
  recorded workload declaration and continues through the single workload
  environment resolver.

No environment value is included in an error, log, or persistent machine
record.

## Evidence

- Rust unit coverage proves all persistence triggers refuse and a transient
  run still accepts `--env`.
- The root CLI integration test executes `machine run -d --env K=V` and proves
  the supported-path error is returned before boot.
- The hermetic CLI BDD suite owns the same user-visible refusal and error.
- Python live SDK tests prove refusal occurs without any CLI invocation.
- TypeScript live SDK tests prove the same refusal and pass type checking.
- Record-mode environment tests remain unchanged in both SDKs.

The full validation commands and counts are recorded in the pull request.
