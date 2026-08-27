# Drop name-keyed template slots

`~/.mvm/templates/` held two kinds of entry: manifest-keyed slots named by
`sha256(canonical_manifest_path)`, and name-keyed slots named by a template id.
The name-keyed half was kept "only to resolve any pre-existing name-keyed
slots". It is gone.

## The user-visible change

`--manifest` is now always a path — a manifest file or the directory containing
one. A bare name (`mvmctl up --manifest openclaw`) is an error naming the
missing path, rather than falling through to a registry lookup. `resolve_manifest_arg`
lost the five-signal "does this look like a path" heuristic along with the
`ManifestArgRef::Name` variant it fed.

The `<template>@<alias>` form also loses its landing place. It resolved the
alias and then returned `Name(template_id)` with a comment saying the boot
"still loads `current`; pinning to `revision_hash` is a follow-up" — so the
alias was validated and then ignored. It now fails with that stated plainly
instead of silently booting the wrong revision.

## What was already dead

`template_list_legacy_names` had no callers. Its doc said it "Powers the
migration banner / `template list --legacy`" — there is no migration banner and
no `--legacy` flag anywhere in the CLI. Same shape as the fabricated witness
names in CLAUDE.md: prose describing a feature nothing implements.

## The chain that fell out

Each of the four `*_dispatched` helpers had an `else` arm calling a name-keyed
sibling, and each sibling had exactly one caller — that arm. Collapsing them
made `template_artifacts`, `template_snapshot_info`, `template_has_snapshot`,
`template_load` and the whole of `lifecycle/crud.rs` unreachable.

The four now share `require_slot_key`, which rejects a non-hex key with the
shape it failed rather than letting it become a missing-directory error further
down. The bundle-sha256 fallthrough is untouched — that is not legacy, it is how
an installed bundle resolves.

`classify_template_dir_entries` split entries into hash and name buckets; it is
now `slot_hash_dirnames`, a filter. Its six tests moved with it.

## Gates

`fmt --all`, `clippy --workspace --all-targets` (zero warnings),
`nextest --workspace` against an empty `MVM_HOME` (12,246 pass), the
test-support lane (3,836 pass), `xtask check-all` (61 gates), `just check-gated`.
