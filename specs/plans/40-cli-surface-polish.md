# Plan 40 — post-plan-38 CLI surface polish

> Spun out of the top-level command audit done at the close of plan 38.
> 29 top-level subcommands → 21. Each removal is justifiable in
> isolation (redundancy with another verb, alias proliferation, or an
> implementation noun leaking into user-facing surface). Bundled here
> so the polish lands as a coherent "we cleaned up the CLI" slice
> instead of nine atomized PRs.

## Context

Plan 38 added the manifest surface (`init`, `build`, `manifest *`)
and removed `template *`. The audit afterwards showed several
pre-existing top-level commands that are redundant, ambiguous, or
just noise. Per the user's no-back-compat directive, none of these
get aliases — the verbs go away outright; clap returns
"unrecognized subcommand" for old invocations.

## Approach

Each change is small and independent. The order below minimizes
intermediate compile breakage but is otherwise mechanical.

### 1. Drop `mvmctl completions` — fold into `shell-init`

`shell-init` already outputs completions plus dev aliases. The
standalone `completions` verb is a strict subset; users hitting it
got the same output minus the aliases. Remove the variant +
module.

### 2. Drop `mvmctl setup` — fold into `bootstrap`

`bootstrap` does the full first-run setup (Homebrew + Lima +
Firecracker + kernel/rootfs). `setup` is the Lima+Firecracker
subset. Drop `setup`; tell users to run `bootstrap` (it handles
already-installed steps idempotently). The implementation in
`commands/env/setup.rs` has helpers (`run_setup_steps`) that
`bootstrap` already imports — keep the helpers, drop the
standalone subcommand.

### 3. Drop `mvmctl init`'s env-wizard branch

Slice 7a smart-dispatched `mvmctl init` between project-scaffold
mode (with `<DIR>`) and env-wizard mode (bare). The wizard branch
is redundant with `bootstrap`; keeping it confuses the verb's
identity. Drop the wizard branch; bare `mvmctl init` either
defaults to scaffolding cwd or errors with a clear "use
`bootstrap` for environment setup" hint. Recommendation: error
out — bare `init` should not silently overwrite the user's cwd
with a scaffold.

### 4. Drop `mvmctl image` — fold catalog into `init --catalog <name>`

After plan 38 slice 7b, `image fetch` doesn't auto-build; it
prints a recipe. The catalog itself (curated `flake_ref` +
profile + sizing tuples) is still useful, but as a *scaffold
source*, not as a runtime concept. Fold it into `init`:

- `mvmctl init <DIR> --catalog openclaw` writes a `mvm.toml` +
  `flake.nix` shim that points at the catalog entry's flake_ref
  with the catalog's recommended sizing.
- `mvmctl image list` / `info` / `search` move under
  `mvmctl init --catalog list` (or maybe `mvmctl catalog list` as
  a thin metadata-only namespace).

This eliminates the standalone `image` namespace. The catalog
data (`mvm-core/src/catalog.rs`) stays.

Recommendation: introduce `mvmctl catalog` as a tiny new
namespace for `list`/`info`/`search` (catalog browsing is
distinct enough from project scaffolding to warrant its own
verb), and delete `mvmctl image` entirely.

### 5. Rename `mvmctl flake` → `mvmctl validate`

Today's `flake` verb is validate-only (it doesn't build). The
verb-as-noun "flake" reads oddly; "validate" reads like what it
does. Rename the variant + module. No flag changes.

### 6. Drop `mvmctl up` aliases `start` and `run`

The `Up` variant has `#[command(alias = "start", alias = "run")]`.
Three names for one verb is alias proliferation. Keep `up`; drop
the others. Anyone scripting against the old names breaks
immediately rather than silently doing the wrong thing later.

### 7. Make `mvmctl ls` the primary; drop `ps` and `status` aliases

`Ps` has `alias = "ls", alias = "status"`. Rename the variant to
`Ls` (or just rename the documented verb to `ls` while keeping
the variant name `Ps` in code), drop the aliases. `ps` implies
unix process semantics we don't fake; `status` is too generic.

### 8. Fold `mvmctl security` into `mvmctl doctor`

`security` runs a security-posture report. `doctor` runs
diagnostics + dependency checks. Security posture is one of many
diagnostic queries. Fold: `doctor` gains a security section in
its default output (or a `doctor security` subcommand if
sectioned). Drop the standalone `security` verb.

Recommendation: doctor outputs a unified report with sections;
security goes into that report. The standalone `security` verb
is removed.

## Critical files to modify

| File | Change |
|---|---|
| `crates/mvm-cli/src/commands/mod.rs` | Drop `Completions`, `Setup`, `Image`, `Flake`, `Security` enum variants + dispatch arms. Rename `Ps` → `Ls`. Drop `Up` aliases. Add `Catalog` (new) + rename `Flake` → `Validate`. |
| `crates/mvm-cli/src/commands/env/init.rs` | Drop env-wizard branch (the `dir.is_none() && preset.is_none() && prompt.is_none()` path). Bare `init` errors with a `bootstrap` pointer. |
| `crates/mvm-cli/src/commands/env/completions.rs` | DELETED. `shell-init` already does this. |
| `crates/mvm-cli/src/commands/env/setup.rs` | Demote from a public subcommand (`Args` + `run`) to private helpers used by `bootstrap`. |
| `crates/mvm-cli/src/commands/env/mod.rs` | Drop `pub(super) mod completions;`. Reshape the `setup` module to expose only the helpers `bootstrap` needs. |
| `crates/mvm-cli/src/commands/build/image.rs` | DELETED. Catalog-browsing moves to `commands/catalog.rs`; catalog scaffold flow moves to `init --catalog`. |
| `crates/mvm-cli/src/commands/build/flake.rs` | RENAMED to `validate.rs`. Variant + dispatch arm renamed. |
| `crates/mvm-cli/src/commands/build/mod.rs` | Drop `pub(super) mod image;`. Rename `pub(super) mod flake;` → `validate;`. |
| `crates/mvm-cli/src/commands/catalog.rs` (new) | Tiny module: `list`, `info`, `search` actions over the bundled catalog. |
| `crates/mvm-cli/src/commands/env/init.rs` | Add `--catalog <name>` flag to scaffold from a catalog entry. |
| `crates/mvm-cli/src/commands/ops/security.rs` | DELETED (or kept as a private helper module that `doctor` imports). |
| `crates/mvm-cli/src/commands/env/doctor.rs` | Absorb security posture queries into the doctor report. |
| `crates/mvm-cli/src/commands/vm/up.rs` | Drop `#[command(alias = "start", alias = "run")]`. |
| `crates/mvm-cli/src/commands/vm/ps.rs` | Drop `#[command(alias = "ls", alias = "status")]`. Rename file/variant to `ls.rs`/`Ls`. |
| `crates/mvm-cli/src/commands/tests.rs` | Update parser tests that reference removed/renamed verbs (`completions`, `setup`, `image`, `flake`, `security`, `up start/run`, `ps ls/status`). |
| `tests/cli.rs` | Same updates for integration-level CLI parser tests. |
| `public/src/content/docs/reference/cli-commands.md` | Strike removed verbs; document renames; new `catalog` namespace. |
| `public/src/content/docs/getting-started/first-microvm.md` | Replace any `mvmctl run`/`start` invocations with `mvmctl up`. |
| `public/src/content/docs/...` | Sweep for stale references. |

## Verification

1. `cargo test --workspace` — workspace green; old verbs return
   "unrecognized subcommand". A new test in `tests/cli.rs`
   asserts each dropped verb errors cleanly.
2. `cargo clippy --workspace -- -D warnings` clean.
3. Manual `mvmctl --help` shows the trimmed surface (21 verbs).
4. Manual `mvmctl up --help` doesn't show `start`/`run` aliases.
5. Manual `mvmctl doctor` output includes a security section.
6. Manual `mvmctl init my-app --catalog openclaw` writes a
   `mvm.toml` + `flake.nix` aligned with the catalog entry.

## Out of scope

- Deeper restructuring (e.g. moving `logs`/`forward`/`diff`/
  `console` under a `vm` namespace). That's a larger ergonomic
  change with real breakage; deferred.
- Adding a `--quiet`/`--verbose` global flag. Separate concern.
- Documentation site re-organization beyond the cli-commands.md
  table updates.
