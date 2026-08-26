# Every documented `mvmctl` command is now a checked assertion

Backing: shipped-source
Validation: just bdd

The README and the website docs printed roughly 640 `mvmctl` invocations. The
existing `s8_readme_contract` suite checked a slice of them — README only, and
only by asking whether the flag *string* appeared somewhere in `--help` output.
Nothing checked the website docs at all, which is where the drift had gone.

A reader following the docs hit a broken command about one time in five.

## What was wrong

142 of 612 extracted README + website examples did not parse against the real
CLI. The failures were not exotic:

- **~90 occurrences of a moved verb.** `volume`, `cp`, `pause`, `resume`,
  `checkpoint`, `wait`, `boot-report`, `proc`, `diff`, `snapshot` and `sandbox`
  were re-parented under `machine` (`MachineAction::Vm` is a
  `#[command(flatten)]`), and the docs still spelled them top-level. They stayed
  broken and invisible because all eleven are `hide = true`, so no help-text
  check could ever have caught them.
- **`build` became a command group.** `mvmctl build --flake .` and `mvmctl build
  ./my-app` used to build an image; image builds are `machine build`. 40+
  occurrences.
- **Namespace moves.** `audit` → `trust audit`, `receipt verify` → `trust
  receipt verify`, `cleanup` → `env cleanup`, `metrics` → `ops metrics`.
- **Flags that no longer exist.** `machine exec --timeout`, `manifest ls
  --legacy`, `build --vcpus/--mem/--data-disk/--snapshot`, `checkpoint restore
  --name`, `pack download --kind` (now a positional).
- **Commands that never existed on this branch.** `mvmctl update` was documented
  under a "Self-Update" heading; `mvmctl detach` and `mvmctl run --attached`
  were documented in a lifecycle table that also had the default backwards (the
  default is attached; `-d` detaches).
- **`mvmctl up`** in both language-SDK READMEs. `up::Args` is not a `Commands`
  variant, so the verb has no dispatch path at all.
- **A prematurely closed code fence in the README** left an `mvmctl machine run`
  example stranded in the prose. It rendered as broken Markdown *and* dropped
  out of extraction — the example stopped being checked at the same moment it
  stopped being readable, which is why it survived.

### Tables were the bigger hole

The CLI reference documents most of its surface in Markdown **tables**, where a
command is an inline `` `code span` `` rather than a fenced block. A
fenced-block-only gate is green while an entire reference page rots. Adding
inline spans nearly doubled the corpus (641 → 1185) and found 35 more stale
spellings, including `mvmctl compile`, `mvmctl validate`, `mvmctl exec`,
`mvmctl info`, `mvmctl rm`, `mvmctl status`, `mvmctl update`, `mvmctl bundle
verify`, `mvmctl template show`, and `mvmctl session attach`.

Inline spans are checked at the verb level rather than parsed whole: a table
cell or a sentence names a command without supplying its arguments
("see `mvmctl machine exec`"), so demanding a complete parse there produces
noise, not signal. A fenced block is a recipe and still must parse completely.

## The gate

`features/suites/s29_doc_examples/` extracts every invocation with `file:line`
provenance and verifies each at one of three tiers:

| Tier | Proves | Runs |
| --- | --- | --- |
| `parse` | the real clap tree parses it, with full argument validation | every PR |
| `exec` | additionally executed against an isolated `MVM_HOME` | every PR |
| `live` | additionally boots a real microVM | `MVM_BDD_LIVE=1` |

Parsing goes through `try_get_matches_from`, not string matching, so the
resolved command path comes from clap itself — a flag *value* that happens to
spell a subcommand (`--image run`) cannot be mistaken for one.

The design decision worth keeping: **the tier assignment is keyed by command
path, not by example.** The CLI surface is finite and reviewable; the set of
examples is neither. `tier_for` returning `None` fails the suite and names the
path, so the assignment is total and a newly documented verb cannot ship without
someone deciding how it is proven.

### The holes that were closed deliberately

Each of these was a way the gate could have been green while lying:

- **Notation read as commands.** `mvmctl manifest *`, `mvmctl machine
  pause/resume` and `mvmctl machine exec ...` name a *family*, not a command.
  Wildcards, ellipsis and slash-alternation are treated as notation — but a
  slash-containing token that looks like a path (`/work/app:/w`) is not, so a
  real mount argument is still checked.
- **Docs that correctly describe absence.** "The former `mvmctl dev
  import-image`", "the dropped `mvmctl security` verb", "not exposed by a
  public `mvmctl policy` command" are accurate documentation about a command
  that is gone or was never public. Rewriting those would have made the docs
  wrong. They are declared under `[[absent]]` with a reason, and the same
  shipped-check applies: if one becomes real, the suite fails.
- **Placeholder evasion.** Templates (`mvmctl <verb> …`) are exempt from
  parsing, which would make `<angle brackets>` an escape hatch for documenting a
  command that never existed. Their concrete verb prefix is resolved anyway.
  `manifest push` / `manifest pull` are genuinely unimplemented, so they are
  declared under `[[planned]]` with a reason — and a second scenario fails if a
  planned command ever ships, so the docs get updated when it does.
- **`live` as a label.** A `live` tier claims a real guest runs the command.
  The suite reads the `@live` scenarios back and fails if nothing runs it. This
  caught `machine build`, which was marked `live` with no witness;
  `documented_build_live.feature` now provides one.
- **Stranded commands.** A fence-balance check cannot see a fence closed one
  block early. The check looks for command-shaped lines outside any fence,
  filtered by the real top-level verb list so prose like "mvmctl uses Nix
  flakes" is not a false positive.
- **Extractor blindness.** If extraction silently returned nothing, every
  downstream assertion would pass vacuously. A corpus-size floor guards that.

`doctor` carries `exit_reports_host_state`: it exits nonzero precisely because
it found something to report, so the exec tier asserts it ran to completion
rather than that it exited 0.

## Scope note

The corpus is the README, the website content root, both language-SDK READMEs,
the `examples/` READMEs, and `AGENTS.md` — everything a reader is pointed at.
The SDK and example READMEs were added after an initial pass missed them; they
contributed 6 of the findings, including both `mvmctl up` occurrences.

## Evidence

`just bdd`, macOS 26 / Apple Silicon, no `/dev/kvm`:

- Baseline (`origin/main`): 197 scenarios, 188 passed, 8 failed.
- With this change: 206 scenarios, 198 passed, 7 failed.

1185 documented invocations are now extracted and checked, up from the 0 the
website docs had before.

The failing scenarios are identical on both sides and all pre-existing — the
TypeScript SDK `dist/` is not built in a fresh worktree and the SDK codegen
binary is absent. This branch adds 9 scenarios, all passing, and introduces no
new failures. 28 `@live` scenarios were skipped for want of a hypervisor, as
designed; the live tier is proven on a KVM host, not here.

## The gap this left, since closed

`mvmctl build compile --dev`'s own help text still said "Refused on `mvmctl
compile`", naming the pre-`build` spelling. That string lives in the CLI source,
not the docs, so this gate could not see it — the harness reads documentation,
and help text is the CLI describing itself.

The follow-up sweep found the gap was not one string but fifty-six, and is
covered now by `cli_output_commands.feature`. See
`specs/sprint/delivery/cli-output-names-real-commands.md`.
