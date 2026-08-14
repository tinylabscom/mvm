# 2508 — the workflow files are now linted

23 workflow files, 6,712 lines, previously unchecked until a run failed. The
failure mode that matters is silent: a wrong `if:`, a typo'd `needs:` job name,
or a bad `${{ }}` reference does not fail a PR — it disables the lane, which
still reads as covered to anyone auditing the file.

## Baseline

The first full run surfaced 8 findings, all shellcheck `info` inside `run:`
blocks, and **zero** workflow-syntax, expression, or `needs:` errors. The class
the issue is most concerned about was already clean; what existed was shell
nits, three of which were false positives whose suggested fix is a bug.

| Finding | Disposition |
| --- | --- |
| `kernel-build.yml` ×2 SC2086 | Fixed — quote the variable, keep the glob unquoted so it still expands |
| `release.yml:713` SC2035 | Fixed — `./*.sha256`, so a file named like an option stays a filename |
| `release.yml` ×2 SC2086 on `$FILES` | Fixed by converting the accumulator to an array |
| `security-lane-watch.yml` ×3 SC2016 | Suppressed per line, with the reason |

The `$FILES` pair relied on word splitting to turn a space-joined string into
arguments, so a filename containing a space would have split into two paths
that do not exist. An array removes the class rather than silencing it.

The three SC2016 hits are `printf` *format* strings whose values arrive as
`%s` arguments; the literal backticks are markdown for a GitHub issue body.
Double-quoting them — shellcheck's suggestion — would make the shell run
command substitution on the backticks, and one would try to execute a path
under `specs/adrs/`. Suppressed per line with that reason rather than fixed.

A file-wide `# shellcheck disable=` directive is not honoured by actionlint's
shellcheck integration; per-line directives are.

## The gate

`actionlint` runs in `lint-policy`, which is the only lint job with no
`if: needs.scope.outputs.code == 'true'` condition — so it runs on every PR,
including a workflow-only change that the scope filter might otherwise classify
as non-code. It is placed after the step that installs `shellcheck` (actionlint
shells out to it, and without it the eight findings above would not have been
seen) but before the uv/Node/zigbuild/cache steps, so a workflow error fails
fast.

It runs over `.github/workflows/*.yml`, not changed files: a changed job can
break a `needs:` reference in a file it did not touch.

The CI scope filter entry widened from `\.github/workflows/ci\.yml$` to
`\.github/workflows/`, so a change to any workflow keeps the full matrix. A
workflow defines what every lane does, so editing one can change any result.

## Witnesses

Both failure modes named in the issue were injected and confirmed caught:

- typo'd `needs:` → `job "lint" needs job "lint-polcy" which does not exist in
  this workflow [job-needs]`, plus a second error on the dependent expression.
- bad `${{ }}` property → `property "kode" is not defined in object type
  {code: string} [expression]`.

Both restored afterwards; all 23 files lint clean.

## Out of scope

`actionlint` cannot tell that a lane asserts nothing — the `runtime_boot_bench`
instance in the issue would still pass it. That class needs separate thinking
and is not addressed here.
