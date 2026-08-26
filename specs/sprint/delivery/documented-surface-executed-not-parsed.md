# Execute the documented surface instead of parsing it

The doc-examples suite already extracted every `mvmctl` command the README and
the website docs print, and assigned each a verification tier. What it could not
do was run them: 86 of 111 command paths sat at tier `parse`, proven to the
depth of "clap accepts these arguments".

That depth cannot see the defect that matters. `machine forward` parses cleanly
against the real clap tree and then refuses at runtime — it was retired — while
`examples/obscura/README.md` still told a reader to run it. The verb was in the
tree, so every hermetic gate stayed green.

## What executing found

Four defects, none of which a parse tier can reach:

- `machine forward` retired but documented (#2901). Fixing it exposed the larger
  problem: the replacement the CLI itself names, `machine run --port`, is
  `conflicts_with` `--detach`, and `machine create` takes no `--port`. A
  detached guest with declared ingress has no expressible form.
- `mvm.local_path` is exported by the Python SDK and taught in the README's
  flagship decorator example, but absent from the decorator compiler's
  `HELPER_ALLOWLIST` (#2902) — so `mvmctl build compile`, printed directly
  beneath that example, fails on it.
- crates.io began rejecting User-Agents starting with `curl/`, which is what Nix
  sends (#2904). Every Rust derivation in the builder VM image fails to fetch,
  so a source-checkout Stage 0 build cannot complete on any host.
- A default-features `mvmctl` cannot verify a signature, so it refuses the
  published builder image — and the remedy printed elsewhere in the CLI,
  `--features release-artifact-bootstrap,manifest-verify`, names a root feature
  that no longer exists and does not compile (#2906).

The last two blocked the suite's own first real-host runs, which is how they
were found.

## Tier movement

| tier | before | after |
| --- | --- | --- |
| `parse` | 86 | 61 |
| `exec` | 16 | 35 |
| `live` | 9 | 15 |

Exec-tier examples actually executed: 16 → 35.

`parse` now has to justify itself. It is the rung a path reaches by nobody
deciding anything, so an entry there without a written reason fails the suite.
Two new manifest keys let a runnable-but-unstaged command be promoted instead of
excused: `fixture` stages the files an example names, and `env` supplies
per-path environment.

`env` earned its place immediately. `env uninstall` can `sudo rm -rf
/var/lib/mvm` and delete `/usr/local/bin/mvmctl`; without its
`MVM_UNINSTALL_PATH_PREFIX` sandbox hook it "passes" only by being cancelled at
its confirmation prompt — proving nothing while leaving that path untested.

Promoting the tier also revealed that exec-tier examples had been writing into
the working copy: documented scaffolds like `init ./agent-tool` ran at the repo
root. They now run from a scratch directory.

## One guest, many verbs

`features/suites/s32_documented_surface/machine_journey.feature` boots a single
guest and drives the documented `machine` verbs against it, so verb coverage
costs one boot rather than twenty.

It is `@live` and deliberately **not** `@firecracker`. Every pre-existing
guest-booting scenario carries that tag, so all of them are skipped on macOS —
where HVF is the default backend. The backend most users run booted nothing.

Two traps encoded in the feature, both of which cost real time:

- The machine-name positional has a `value_parser` that rejects braces, so a
  `{machine}` placeholder fails to parse and drops out of the live-witness gate
  silently: the scenario runs while the tier it backs stays unproven. The guest
  is named literally.
- Scenarios are split by verb family rather than written as one long journey.
  Cucumber abandons a scenario at its first failing step, so one scenario per
  family means a broken verb reports itself instead of hiding every verb after
  it.

## Running it

`just e2e-docs`. Nightly lanes `e2e-docs-linux` (Firecracker) and
`e2e-docs-macos` (HVF).

The runner is bounded by its own watchdog rather than `timeout(1)`, which stock
macOS does not ship. A live scenario can hang instead of failing, and a release
gate that hangs is a gate nobody runs. A bootstrap failure is loud but not
fatal: it warms the builder image, which the flake-build scenarios need and the
OCI-image ones do not, so aborting discarded every result that did not depend on
it.
