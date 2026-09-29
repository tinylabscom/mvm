# Denial feedback and policy explanations

Delivered 2026-09-28 for issue #3714.

## Problem

Typed egress refusals were visible live and in the signed audit history, but an
operator still had to translate a safe refusal into policy by hand. There was
also no local command for asking why a host, path, tool, or secret would be
allowed or denied before starting a workload.

## Resolution

- Foreground runs offer each grantable denial as Grant or Skip when a
  controlling terminal exists. A grant only enters an in-memory draft; the
  operator sees the exact `[network].allow_hosts` additions and confirms the
  write separately.
- `mvmctl explain RUN --review [--project DIR]` reuses that candidate and
  writer path for detached and background runs after the signed local audit
  chain verifies.
- The writer preserves unrelated TOML content and comments, deduplicates
  destinations, rejects symlinks and concurrent changes, and publishes the
  result atomically and durably. It adds to the existing project policy shape;
  no new configuration section or second policy file exists.
- Metadata, loopback, link-local, SSH, rate-limit, route-edit, and other
  non-grant remedies cannot become review candidates.
- `mvmctl why` resolves the discovered project policy by default and accepts
  an explicit profile or resolved manifest. Exactly one of `--host`, `--path`,
  `--tool`, or `--secret` produces a human or JSON answer without booting a
  workload. Tool answers identify that authored tool policy is not yet
  runtime-enforced.

## Evidence

- Pure policy-query tests cover allow, deny, wildcard/prefix, default-deny,
  malformed input, absolute runtime denials, shares, tools, and secrets.
- Review tests prove Grant plus a distinct confirmation is required, unsafe
  refusals are excluded, unrelated TOML survives, additions deduplicate, and a
  concurrent edit is refused.
- CLI unit, integration, and BDD coverage owns selector conflicts, help text,
  JSON output, project discovery, and the no-boot metadata refusal.
- Host workspace check and zero-warning Clippy passed. The full workspace test
  run's sole contention-sensitive image-lock failure passed as a complete
  serial target rerun. Linux all-target Clippy for the changed packages and
  the BDD feature-gated conformance compile passed in the project builder VM.
- Formatting, generated-stub drift, IR parity, and all 75 repository gates
  passed.
