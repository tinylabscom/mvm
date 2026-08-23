# Scheduled security-lane repair

## Outcome

The scheduled Security workflow's supply-chain and no-SSH lanes are green
again without weakening either policy.

## Changes

- Pin workspace `async-trait` to 0.1.89 so the dependency graph uses one
  reviewed `syn` major version.
- Treat capture's private-key filename patterns as denylist evidence rather
  than installed SSH capability.
- Exclude generated dependency and build directories from the recursive
  no-SSH source scan.
- Add a regression fixture proving generated content is ignored and a real
  source token is rejected.

## Evidence

- `cargo deny check`
- `./scripts/check-no-ssh.sh`
- `bash scripts/check-no-ssh.test.sh`
