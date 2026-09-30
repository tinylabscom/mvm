# Specifications

GitHub issues are the source of truth for work status, remaining scope,
dependencies, ownership, and acceptance criteria. Pull requests record what
landed and how it was verified. Do not duplicate those changing facts in a
shared sprint, refactor, delivery, or progress dashboard under `specs/`.

## Agent read order

Do not recursively read this directory to understand a task. That mixes current
contracts with historical research and superseded implementation plans.

1. Start from the open GitHub issue. It owns the outcome, scope, dependencies,
   priority, and acceptance evidence.
2. Read only the ADRs and contracts linked by that issue. They own durable
   decisions and interfaces.
3. Use Graft to locate the implementation and determine its blast radius.
4. Use the pull request to record the implementation and verification, and let
   its `Closes #N` linkage close the issue.

`just maint::task-context <issue>` generates a read-only briefing from those
sources. The briefing is disposable output, never another work ledger.

## What belongs here

- `adrs/` contains durable architectural decisions. Supersede an ADR rather
  than rewriting the history of a decision.
- `contracts/` contains stable behavioral or protocol contracts that are not
  expressed more clearly by types, schemas, or executable tests.
- An exceptional, implementation-heavy design may live in `plans/` when putting
  it in an issue would make the issue unusable. It must link one open issue and
  remain an immutable design attachment: no task checkboxes, progress,
  ownership, dependencies, branch names, or delivery status.
- Machine-consumed registries, conformance inputs, and committed evidence stay
  until their owning code moves them deliberately; they are product inputs,
  not work dashboards.

## Lifecycle

When work closes, keep its issue and pull requests as the delivery record.
Extract enduring decisions into ADRs and user-facing guidance into the public
documentation. Historical research and plans are removed once their useful
content has been captured; git history remains available when needed.

The pre-migration plans are frozen historical inputs while their durable content
is extracted. `check-spec-hygiene` prevents that legacy set from growing. Do
not edit or follow a legacy plan as current work; open its referenced issue or
create a current issue instead.
