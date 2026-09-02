# The pre-commit hook said "clippy failed" when clippy was fine

## What was wrong

The hook narrows `cargo clippy` to the packages owning the staged files. It
finds them with `owning_package`, which walks up to the nearest `Cargo.toml`
and reads its `name`. Several real packages in this tree are not workspace
members, so `cargo -p` cannot address them:

- `web/mvm-demo/` declares `mvm-demo-web`
- each detached fuzz crate declares its own name (`mvm-agentd-fuzz`, …)
- `mvm-hostd-ebpf`

For any of those, clippy exits with `error: package ID specification
'mvm-demo-web' did not match any packages`, and the hook reported it as:

```
  clippy failed. CI gates on the same '-D warnings' rule, so
  this commit will fail on push.
```

Clippy had not failed. The commit was refused, and the advice — fix your lints
— pointed at nothing. Any merge commit carrying main's changes under `web/`
hits it; it blocked three separate merges during one afternoon of queue work
(#3072, #3075, #3096), each time costing a manual verification of the scope the
hook wanted, by hand, before using its own `MVM_SKIP_CLIPPY=1` escape.

A lint hook that cries wolf gets bypassed, and a bypassed hook gates nothing.

## The fix

`workspace_members` derives the addressable set from the root manifest — the
root package plus every path in its `members` list — and `is_workspace_member`
checks against it. A staged file owned by anything else takes the widen-to
`--workspace` path the hook already had for unresolvable files, with a reason
that says what happened:

```
pre-commit: clippy covering the whole workspace — mvm-demo-web is not a
workspace member, so -p cannot address it
```

Deliberately **not** "every `Cargo.toml` under the tree". That glob also
matches the fuzz crates and `mvm-hostd-ebpf`, which is the same mistake
relocated: it would accept `-p mvm-agentd-fuzz` and fail exactly as before.

## Tests

`.githooks/pre-commit.test.sh`, in the established `*.test.sh` shape: a fixture
workspace with a member, a non-member sibling, and a detached fuzz crate under
a member. It pins the scoping decision, not the clippy run.

Verified to bite: against `main`'s hook the suite fails rather than passing.
Verified not to over-widen: a staged `xtask` file still produces
`--workspace, then -p xtask --all-targets`, and a staged `web/` file now widens
end-to-end instead of failing.

Wired into `ci.yml` alongside the other shell-tool tests, and shellchecked with
them.
