# mvmctl's own output no longer names commands that do not exist

Backing: shipped-source
Validation: just bdd

The documentation harness reads Markdown. It cannot see the other place a reader
is told what to run: mvmctl's own strings — hints, error messages, "Run with:"
lines. Those drift exactly like docs do, and nothing checked them.

`mvmctl bundle install` finished by printing:

```
  launch with:   mvmctl up --manifest 830c330a…
```

`up` has not been a dispatched verb for a long time. A reader who followed the
instruction the tool had just given them got `error: unrecognized subcommand`.

## What was wrong

56 command-shaped strings did not resolve against the real clap tree. About
thirty were genuine, and they cluster by refactor:

- **`mvmctl up`** (3) — the verb has no dispatch path at all.
- **`mvmctl compile`** (21 occurrences across 4 files) — now `build compile`.
  This is the string the doc-examples delivery note flagged as a known gap; it
  turned out not to be one string.
- **`mvmctl audit …`** (6) — now `trust audit …`.
- **Verbs re-parented under `machine`** — `start`, `stop`, `logs`, `exec`,
  `cp`, `session …`, `vm pause` / `vm resume`, `fs mv`.
- **`mvmctl setup`** (2) — never existed; the hint meant `bootstrap`.
- **`mvmctl shell init`** — the verb is spelled `shell-init`.
- **`mvmctl template build`** — `template` is a read-only registry browser now;
  the hint meant `machine build --update-hash`.

One string was removed rather than repointed: `build_mvmfile` printed
`Run with: mvmctl start <elf>`, and nothing in the CLI boots an mvmfile ELF.
Substituting a different wrong verb would have been worse than saying nothing.

A unit test was pinning the defect in place: `run_prod_alias_redirects_to_mvmctl_compile`
asserted the redirect names `mvmctl compile`, so the wrong spelling was the
thing under test. It now asserts `mvmctl build compile`.

## The gate

`features/suites/s29_doc_examples/cli_output_commands.feature` extracts every
`mvmctl …` phrase from string literals in `crates/mvm-cli/src` and resolves it
against `mvm_cli::commands::cli_command()`.

**Only the leading verb chain is judged.** Trailing words are arguments, and
demanding they parse lets prose through: `machine cp` takes positionals, so
"mvmctl cp supports exactly one" *parses*, with "supports exactly one" absorbed
as arguments. A check built on "does the whole thing parse" calls that healthy.

**Prose is declared, not detected.** Every heuristic for telling English from an
invocation was wrong in one direction or the other, and the most natural one is
catastrophically wrong: filtering on "is the first word a real verb" drops
exactly the strings that name a *removed* verb. I wrote that filter first, and it
reported one finding where there were fifty-six. So `[[prose]]` entries in
`tiers.toml` carry the phrase and a reason, and anything undeclared must resolve.

### Two extractor bugs worth recording

Both made the extractor silently return fewer items, which is the failure mode
that matters: every downstream assertion still passes.

1. **Escapes.** A literal body matched as `[^"\\]*` cannot contain `\n`, so
   `"\nRun with: mvmctl up {}"` — and most "Run with:" hints, which open with a
   newline — were invisible. Fixing it took the corpus from 94 to 100.
2. **Multi-line literals.** A line-at-a-time scan needs the closing quote on the
   same line, so `\`-continued error messages were dropped whole. That is where
   the `mvmctl compile` cluster lived. Fixing it took the corpus from 100 to 200
   and the findings from 24 to 56.

Both have regression tests naming the failure, alongside raw strings, nested
block comments, and punctuation trimming — a message writes `` `mvmctl compile` ``
far more often than bare, and a scanner that chokes on the backtick drops the
occurrence rather than reporting it.

## Evidence

The gate was mutation-tested against the defect it was built for: restoring
`mvmctl up --manifest` in `bundle/install.rs` turns it red naming that file and
line; reverting turns it green.

`just bdd`, macOS 26 / Apple Silicon: 240 scenarios, 232 passed, 7 failed — the
same 7 that fail on main (TypeScript SDK `dist/` unbuilt, SDK codegen binary
absent). Workspace: 12514 tests, 12513 passed.

Two clippy findings in `mvm-fs` and `mvm-core` (`#[must_use]` on an
`#[async_trait]` method) reproduce at HEAD without this change and are not
addressed here.
