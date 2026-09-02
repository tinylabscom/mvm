# Documented surface, executed end to end

Backing: shipped-source
Validation: check-claim-catalog

**Status:** IN PROGRESS

Every command the README and the website docs print is a promise to a reader
who will paste it into a shell. `features/suites/s29_doc_examples/` already
extracted those commands and assigned each a verification tier. What it could
not do was run most of them: 86 of 111 documented command paths sat at tier
`parse`, verified to the depth of "clap accepts these arguments".

Parsing cannot see the defect that matters. `mvmctl machine forward` parses
cleanly against the real clap tree and then refuses at runtime — it was
retired — while `examples/obscura/README.md` still told a reader to run it.
The same shape hid a second one: the README's flagship decorator example uses
`mvm.local_path(...)`, which the Python SDK defines and the decorator
compiler's `HELPER_ALLOWLIST` does not, so `mvmctl build compile` fails on the
example printed directly above that command.

## What changed

### The tier ladder now carries its own honesty gate

`parse` is the rung a path reaches by nobody deciding anything — it is where a
newly documented verb lands by default. A path may still sit there, but the
manifest now requires it to say why, and
`every parse-tier command path explains why it is only parsed` fails the suite
when one does not. "We could not run this" stays distinguishable from "nobody
tried".

Two further manifest keys let a runnable-but-unstaged command be promoted
rather than excused:

- `fixture` stages the files a documented example names before running it.
- `env` supplies per-path environment. `env uninstall` is the motivating case:
  it rewrites its system paths under `MVM_UNINSTALL_PATH_PREFIX`, and without
  that hook it "passes" only by being cancelled at its confirmation prompt —
  proving nothing while leaving a `sudo rm -rf` path untested.

### Tier movement

| tier | before | after |
| --- | --- | --- |
| `parse` | 86 | 61 |
| `exec` | 16 | 35 |
| `live` | 9 | 15 |

Exec-tier examples actually executed went from 16 to 35.

### One guest, many verbs

`features/suites/s32_documented_surface/machine_journey.feature` boots a single
guest and drives the documented `machine` verbs against it — `inspect`, `logs`,
`boot-report`, `exec`, `fs ls`, `cp`, `pause`, `resume`, `checkpoint
create|ls`, `ls`, then teardown. Verb coverage costs one boot rather than
twenty.

It is tagged `@live` and deliberately **not** `@firecracker`. The pre-existing
live lifecycle witness carries that tag, so it is skipped on macOS — where HVF
is the default backend. That is how the backend most users run ended up with no
lane that booted anything.

Two traps this feature encodes, both of which cost real time to find:

- The machine-name positional carries a `value_parser` that rejects braces, so
  a `{machine}` placeholder fails to parse and drops out of the live-witness
  gate silently: the scenario runs while the tier it backs stays unproven. The
  guest is named literally.
- Scenarios are split by verb family rather than written as one long journey.
  Cucumber abandons a scenario at its first failing step, so one scenario per
  family means a broken verb reports itself instead of hiding every verb after
  it.

### Running it

`just e2e-docs` → `scripts/e2e-documented-surface.sh`: builds `mvmctl` and the
TypeScript SDK `dist/`, warms one shared artifact home, reports host posture,
then runs the suite with `MVM_BDD_LIVE=1`. It does **not** set
`MVM_BDD_CI_LIVE_ONLY` — that selector narrows to the merge-queue subset, and
narrowing is what let the macOS backend go uncovered.

Nightly lanes `e2e-docs-linux` (Firecracker, `/dev/kvm`) and `e2e-docs-macos`
(HVF) in `ci-full.yml`.

## Defects this surfaced

- [ ] `examples/obscura/README.md` documented the retired `machine forward`.
      Fixed here — but its replacement, `machine run --port`, is
      `conflicts_with` `--detach`, and `machine create` takes no `--port`. A
      detached guest with declared ingress has no expressible form (#2901); the
      example now shows the foreground shape and says so.
- [ ] `mvm.local_path` is exported by the Python SDK and taught in the README,
      but absent from `mvm_sdk::decorator::value::HELPER_ALLOWLIST`, so
      `mvmctl build compile` rejects the README's own example (#2902). The exec
      fixture omits the kwarg to prove the command; the mismatch is unresolved.

## What running it on real hosts found

The suite's first real-host runs did not reach the scenarios — they were
blocked in `bootstrap`, twice, for two unrelated reasons. Both are recorded
because both block a release independently of this work.

- **crates.io now 403s Nix's User-Agent** (#2904). It rejects any `User-Agent`
  beginning with `curl/`, and Nix sends `curl/<ver> Nix/<ver>`. Every Rust
  derivation in the builder VM image fails to fetch, so the source-checkout
  Stage 0 build cannot complete on any host. `static.crates.io` is unaffected.
- **A default build cannot verify a signature** (#2906). On Linux the builder
  image resolves to a verified fetch, which refuses with "manifest-verify
  feature is disabled in this build". The refusal is right; building without
  the feature was the bug. `user` carries it. The remedy printed elsewhere in
  the CLI — `--features release-artifact-bootstrap,manifest-verify` — names a
  root feature that no longer exists and does not compile.

Both changed the runner: it builds with `--features user`, defaults
`MVM_BOOT_IMAGE=fetch`, and treats a bootstrap failure as loud rather than
fatal. Aborting there discarded every result that did not depend on the builder
image; the flake-build scenarios now fail naming themselves while the
OCI-image ones still run, and the run repeats the warning at the end so the
difference is not misread as a regression.

## Follow-on

- [ ] Stage the bundle fixture (`scripts/make-bundle-fixture.sh`) so `bundle
      fetch|install|gc` leave `parse`.
- [ ] Stage a sealed deps volume (`mvm-app-deps-fixture-tool`) for `deps
      inspect|audit`.
- [ ] Extend the journey to `machine fork|restore|diff|wait|reconfigure|proc
      start` and the local `machine volume` verbs.
- [ ] `manifest info|rm|verify` need a manifest with a *built* slot; reachable
      once the journey performs a real build.
