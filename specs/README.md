# Specifications

GitHub issues are the source of truth for work status, remaining scope,
dependencies, ownership, and acceptance criteria. Pull requests record what
landed and how it was verified. Do not duplicate those changing facts in a
shared sprint, refactor, delivery, or progress dashboard under `specs/`.

## What belongs here

- `adrs/` contains durable architectural decisions. Supersede an ADR rather
  than rewriting the history of a decision.
- `contracts/` contains stable behavioral or protocol contracts that are not
  expressed more clearly by types, schemas, or executable tests.
- Technical plans and design notes may remain while they add implementation
  detail that would make an issue unwieldy. Every new plan must link to one
  open tracking issue. The issue, not plan checkboxes, owns progress.
- Machine-consumed registries, conformance inputs, and committed evidence stay
  until their owning code moves them deliberately; they are product inputs,
  not work dashboards.

## Lifecycle

When work closes, keep its issue and pull requests as the delivery record.
Extract enduring decisions into ADRs and user-facing guidance into the public
documentation. Historical research and plans may be removed once their useful
content has been captured; git history remains available when needed.

Legacy plans and notes are retained for now so this policy change does not
discard useful context. Any instruction in them to update `SPRINT.md`,
`REFACTOR-STATUS.md`, plan checkboxes, or a delivery note is obsolete.

## Archived status documents

The final hand-maintained sprint and refactor dashboards are preserved as
dated, immutable snapshots under `archive/status/`. They must not be revived as
live tracking surfaces.
