# xtask

`xtask` is the repository-maintenance crate for mvm. It packages generation,
validation, release, documentation, supply-chain, and test-orchestration tasks
as versioned Rust code that is reviewed with the product.

## Who uses it

Contributors invoke it through `cargo xtask ...` and higher-level `just`
recipes. CI calls the same commands, and a small number of integration tests use
its reusable schemas. No shipped product binary depends on `xtask`.

## How it works

`src/main.rs` parses a task name and dispatches to a focused module. Most check
modules inspect the workspace and return structured failures; generators write
canonical artifacts and have matching drift checks. `check-all` composes the
fast repository gates so local and CI policy do not diverge.

Major task families include:

- workspace architecture and forbidden-dependency checks;
- security claim, witness, mutation, and policy checks;
- generated SDK/schema, protocol, fixture, and documentation drift checks;
- binary closure, feature closure, ABI, and artifact-size checks;
- sprint, plan, ADR, source-comment, and honesty checks;
- release manifests, man pages, test images, and developer artifact generation;
- network performance evidence and other typed test reports.

The library target contains report schemas shared with probe programs. The
optional `man` feature pulls in `mvm-cli` and clap only when generating manual
pages, keeping the normal tooling closure smaller.

## Adding a task

1. Put one responsibility in its own `src/<task>.rs` module.
2. Expose a command in the dispatcher and include it in the appropriate
   aggregate check.
3. Write unit tests for parsing and failure diagnostics using temporary
   workspaces rather than the developer's checkout.
4. Document generated files and make the drift check deterministic.
5. Add the matching CI or `just` entry only when it needs a dedicated lane.

Checks should report every actionable finding in one run, use repository-root
relative paths, and avoid shelling out when a small deterministic Rust parser
is sufficient.

## Developing

Run `cargo test -p xtask`. Use `cargo run -p xtask -- <command>` while editing
a task. Commands that evaluate Nix or operate microVMs remain subject to the
builder-VM rules even though dispatch originates in this crate.
