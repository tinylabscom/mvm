# Scheduled security-lane repair

## Outcome

The scheduled Security workflow's supply-chain, no-SSH, and newly expanded
mutation surfaces are green again without weakening their policies.

## Changes

- Pin workspace `async-trait` to 0.1.89 so the dependency graph uses one
  reviewed `syn` major version.
- Treat capture's private-key filename patterns as denylist evidence rather
  than installed SSH capability.
- Exclude generated dependency and build directories from the recursive
  no-SSH source scan.
- Add a regression fixture proving generated content is ignored and a real
  source token is rejected.
- Add mutation-sensitive witnesses for AI metering constructors and FlowMux
  ingress generation teardown, readiness signaling, and bounded accept-error
  handling.
- Keep only the provably identical `AiPolicy::disabled`-to-`Default` mutation
  in the accepted baseline; the fail-open FlowMux confinement mutation is
  killed by an invalid-marker test that refuses before altering the test
  process.

## Evidence

- `cargo deny check`
- `./scripts/check-no-ssh.sh`
- `bash scripts/check-no-ssh.test.sh`
- focused `mvm-contract` and `mvm-hostd` tests
- static mutation-surface validation
