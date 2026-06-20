---
claim: trust-gradient
status: Shipped
gated_phrases: []
exempt_paths: []
---

# Trust gradient ledger

Machine-checked by `xtask check-trust-gradient`. Authority and resident weight
decrease monotonically host → builder → workload. No daemon may hold authority
below its tier; `signing-key`, `plan-admission`, and `audit-writer` never exist
below the host. All three daemon tiers are covered: the builder row joined once the
`mvm-builderd` binary existed.

| Tier | Layer | Daemon | Forbidden authorities | Witnesses |
| --- | --- | --- | --- | --- |
| 2 | host | control-daemon | (none — holds all authority) | fn:per_tenant_daemon_paths_are_isolated |
| 1 | builder | mvm-builderd | signing-key, plan-admission, audit-writer | ci:builderd-no-authority |
| 0 | workload | guest-agent | signing-key, plan-admission, audit-writer, do-exec, console | ci:prod-agent-no-authority, ci:prod-agent-runentry-contract, ci:prod-agent-no-console |
