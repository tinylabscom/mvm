# Trust gradient ledger

Machine-checked by `xtask check-trust-gradient`. Authority and resident weight
decrease monotonically host → builder → workload. No daemon may hold authority
below its tier; `signing-key`, `plan-admission`, and `audit-writer` never exist
below the host. The builder row is added once the resident builder daemon binary
exists.

| Tier | Layer | Daemon | Forbidden authorities | Witnesses |
| --- | --- | --- | --- | --- |
| 2 | host | control-daemon | (none — holds all authority) | fn:per_tenant_daemon_paths_are_isolated |
| 0 | workload | guest-agent | signing-key, plan-admission, audit-writer, do-exec, console | ci:prod-agent-no-authority, ci:prod-agent-runentry-contract, ci:prod-agent-no-console |
