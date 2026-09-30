# Plan: Denial feedback completion (#3714)

Backing: preview
Validation: check-doc-links

## Goal

Finish PS-04 on top of the authored-policy surface from PS-05:

- turn grantable, chain-audited egress denials into an explicitly reviewed
  update to the project's existing `mvm.toml`;
- make the same review available after a detached/background run; and
- answer `mvmctl why --host|--path|--tool|--secret` from a resolved policy
  without booting a workload.

The endpoint remains the only egress decision point. Review code consumes the
typed denial records already read from the signed audit chain; it never learns
policy from workload stderr. Metadata, loopback, link-local, SSH, and every
other denial whose remedy is not a grant are never offered as grants.

## User decisions

- Keep one project-policy file. Selected grants are staged in memory, rendered
  as an exact diff, and written to `mvm.toml` only after a second explicit
  confirmation. Cancelling leaves the file byte-for-byte unchanged.
- Foreground runs may open the review prompt when an operator has a controlling
  terminal. Detached/background runs retain their audited denials and expose
  the same prompt through an explicit after-the-fact review command.
- `why` defaults to the current project's resolved policy and also accepts an
  explicit profile or resolved-manifest file.

## Scope

- Network denials are the only observed runtime denial type currently emitted
  by PS-04, so the draft selector adds only `[network].allow_hosts` entries.
- `why --path`, `--tool`, and `--secret` query the authored policy even where a
  later roadmap item has not wired runtime enforcement yet; the answer names
  that distinction rather than claiming an unenforced control ran.
- No runtime approval, daemon prompt transport, or policy-pack mutation is
  added here. Background means reviewing the durable audit record from a later
  interactive `mvmctl` invocation.

## Tasks

- [x] Add a pure resolved-policy query API in `mvm-client`, with structured
      allow/deny answers and positive, negative, wildcard/prefix, default-deny,
      and malformed-host tests.
- [x] Add `mvmctl why` with exactly one query selector, project/profile/plan
      policy selection, human output, JSON output, and parser/integration tests.
- [x] Add a denial-review model that exposes only remedies which can safely
      become `allow_hosts`; prove absolute metadata/SSRF and SSH refusals can
      never enter the candidate set.
- [x] Add a controlling-terminal Grant/Skip selector plus final diff/apply
      confirmation; update `mvm.toml` atomically while preserving unrelated
      content and deduplicating grants.
- [x] Invoke review after eligible foreground runs and from
      `mvmctl explain RUN --review`; machine-readable output and no-TTY paths
      remain non-interactive and print a usable follow-up command.
- [x] Update CLI and policy documentation, PS-04 checkboxes,
      `specs/SPRINT.md`, and `specs/REFACTOR-STATUS.md` after tests pass.
- [x] Run focused tests, `cargo test --workspace`, host workspace Clippy,
      builder-VM all-target Clippy and gated checks, formatting, and repository
      gates required by the working agreement.

## Acceptance

- [x] No denial changes policy without two explicit operator choices.
- [x] No non-grantable denial is shown as grantable or written to policy.
- [x] Foreground and after-the-fact review share one candidate and writer path.
- [x] `why` returns a deterministic structured reason without starting a VM.
- [x] Every granted destination reaches the signed `ExecutionPlan` only through
      the normal PS-05 resolve, synthesize, sign, and admit path.

## Validation

- Focused policy-query, denial-review, parser, CLI integration, BDD, and docs
  coverage passed, including upward project discovery for `mvmctl why`.
- `cargo check --workspace` and `cargo clippy --workspace -- -D warnings`
  passed on the macOS host. The full workspace test run passed except for one
  image-lock holder timing failure under parallel contention; its complete
  four-test target passed immediately when rerun serially.
- Builder-VM `cargo clippy -p mvm-client -p mvm-cli --all-targets -- -D
  warnings` and `cargo check -p mvm-conformance --all-targets --features bdd`
  passed. Cargo caches stayed off the builder's fixed 4 GiB artifact-export
  disk so the completed checks, rather than compiler artifacts, crossed the
  output boundary.
- Formatting, generated-stub drift, IR parity, and all 75 repository gates
  passed. The first aggregate gate invocation lacked `uvx` and `npx` on PATH;
  those two gates passed with the repository's pinned generators, and the one
  reported HOME-isolation fixture was corrected and passed on rerun.
