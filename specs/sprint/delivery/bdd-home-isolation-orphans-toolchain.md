# The BDD suite's HOME isolation was hiding the Rust toolchain

Backing: shipped-source
Validation: cargo nextest run -p mvm-conformance --lib

Every conformance step that spawns `mvmctl` replaces `HOME` so a run cannot
touch the developer's real `~/.mvm`. That isolation is correct and gated
(`xtask check-test-home-isolation`). What nobody accounted for is that `rustup`
locates its toolchains through `$HOME/.rustup` unless `RUSTUP_HOME` says
otherwise — so replacing `HOME` also hid every installed toolchain and target
from any spawned command that compiles.

On a source checkout `mvmctl` cross-compiles the embedded host-vm binaries to
musl. Under a bare isolated `HOME` that build fails with:

```
error[E0463]: can't find crate for `core`
  = note: the `x86_64-unknown-linux-musl` target may not be installed
```

on a host where the target *is* installed — or silently downloads a fresh
toolchain into the scenario's temporary directory, which is then deleted, once
per scenario, for as long as the suite runs.

## How it was found, and the wrong turn on the way

A live run on the KVM box crawled: 192 scenarios at 57 minutes, 196 at 90.
Four scenarios in thirty-three minutes.

The first diagnosis was wrong in the direction that matters. Reproducing
`HOME=$(mktemp -d) rustup target list --installed` showed rustup syncing a
channel, which looked like the answer — but the run's own log contained zero
occurrences of `syncing channel updates`, so the evidence did not support the
claim. The mechanism was only established by a controlled comparison:

| Environment | Resolves musl std to |
| --- | --- |
| real `HOME` | `/root/.rustup/…`, `libcore` present |
| `HOME` replaced | downloads 6 components into `/tmp/tmp.XXXX/.rustup` |
| `HOME` replaced, `RUSTUP_HOME`/`CARGO_HOME` preserved | `/root/.rustup/…` |

## The fix

`IsolatedHome::isolated_home` replaces the hand-written
`.env("HOME", …).env("MVM_HOME", …)` pair at all 12 sites. `MVM_HOME` still
points at the scenario's directory — the isolation the suite wants is
unchanged; only rustup's and cargo's own roots survive, and neither is state
the suite is isolating. A root that does not exist is *not* forwarded, since
pointing rustup at a missing directory trades one misleading failure for
another.

`check-single-home` correctly flagged the `$HOME` read. It is exempted for the
`HomeRead` rule only, with the reason: this reads the real home to locate
rustup, not to locate mvm state.

## Guard

`no_step_sets_home_without_the_isolation_helper` fails on any raw
`.env("HOME"` under `tests/`, naming file and line. It lives in the **lib**
target, not with the steps: the cucumber target is `harness = false`, so a
`#[test]` there is never executed — the first version of this guard was written
in `steps/mod.rs` and would have silently never run.

It also asserts it scanned more than five files, because a walk that returns
nothing passes a "no offenders" assertion perfectly.

Mutation-verified: reintroducing one raw site turns it red naming `cli.rs:106`;
restoring turns it green.
