---
title: AI Coding Workflow
description: How issues move from claim to merged PR when an AI coding agent does the work — worktrees, tooling, feedback ladder, and CI scope.
---

This is the operator manual for AI-assisted development in this repository: how an
issue moves from claim to merged pull request when an agent (or a human driving an
agent) does the work. The always-loaded rules every agent must follow live in
`AGENTS.md` at the repo root; this page is the fuller playbook behind them. The
human environment setup is in the [Development Guide](/contributing/development/).

## Issue claim and status ownership

An issue has exactly one owner at a time, and the owner is whoever is driving the
agent, not the agent itself.

1. **Claim before you start.** Self-assign the issue (GitHub UI or
   `gh issue edit <n> --add-assignee @me`) and drop a one-line comment saying you
   are picking it up and in which worktree branch it will land
   (`feat/<slug>` / `fix/<slug>` / `docs/<slug>` / `chore/<slug>`). There is no
   claim label in this repo — assignment plus the comment *is* the claim. If the
   issue is already assigned, coordinate with the assignee before starting.
2. **Own the status end to end.** The assignee keeps the issue current: a short
   comment when work starts, when it stalls, and when the PR is up. Agents do not
   update issues on their own initiative beyond what the operator asks — the
   operator remains accountable for the issue state.
3. **Close through the PR, not by hand.** The PR body must contain a
   `Closes #<n>` (or `Refs #<n>` for partial work) linkage so the issue closes
   automatically on merge. Never close an issue manually while a linked PR is
   still open.

## The required worktree workflow

Every change — code, docs, dependency bumps, refactors, typo fixes — is developed
in a git worktree. Full detail is in `AGENTS.md`; the short version:

```bash
cd mvm    # the main checkout — stays on main, always clean
git fetch origin && git pull --ff-only origin main
mkdir -p ../.worktrees
git worktree add ../.worktrees/mvm-<slug> -b feat/<slug>
cd ../.worktrees/mvm-<slug>
```

- The main checkout is the **single git operator**. All `git` commands (status,
  add, commit, push, rebase) run from the main checkout with
  `git -C ../.worktrees/mvm-<slug> <cmd>`, never from inside the worktree and
  never from inside the builder VM. This serializes access to the shared
  `.git/objects`, packed refs, and hooks.
- **Never commit directly to `main`.** Main only advances through merged PRs,
  even for one-line docs fixes. The convention is the only thing keeping main
  clean — the branch is not protected.
- **Never attribute the work to a tool.** No AI-assistant mentions, no
  `Co-authored-by` trailers for agents in PR titles, bodies, or commits.
- Isolate per-worktree state with `source scripts/dev-env.sh` (or `bin/dev` for
  one-off `mvmctl` calls); it redirects `MVM_HOME`, `CARGO_TARGET_DIR`, and
  `CARGO_HOME` under the worktree.

## Graft and Serena: division of responsibility

Both tools answer "where does this live and who calls it", but at different
granularity. Reach for each where it is strongest instead of duplicating the
question in both.

- **Graft** (`graft/` in this repo, MCP server `graft mcp`, also wired into
  `.cursor/mcp.json` and `.zed/settings.json`) is the repository orientation
  graph: prose nodes with exact `file:line` spans plus a who-calls-what wiring
  graph. Use it first for cross-cutting questions — "how does X work", "what
  breaks if I change Y", "where does behavior Z live". Its tools are ranked
  retrieval (`graft ask`), exhaustive search (`graft grep`), per-file API
  skeletons (`graft skeleton`), and call-graph edges (`graft callers`). It is
  cheap (no API key, sub-second) and always describes the code as it is right
  now, including uncommitted edits. See the graft contract
  (`.cursor/rules/graft.mdc`) for the tool-by-tool usage contract.
- **Serena** is a symbol-level semantic toolset over language servers (installed
  separately; see below). Use it inside the editor/agent for precise symbol
  operations: find symbol, find referencing symbols, rename, replace symbol
  body, insert before/after symbol, diagnostics, and project onboarding checks.

The split in practice: **graft for orientation and blast radius, Serena for
symbol surgery.** When you already know the symbol you are touching, Serena's
find-referencing-symbols is the exhaustive answer; when you are learning an area
or judging what a change breaks, graft's ranked graph is the faster answer. If a
graft node lacks a detail, read source at the exact span it cites rather than
re-deriving the map yourself.

## Editor configuration for Serena

The repo's shared MCP files (`.cursor/mcp.json`, `.zed/settings.json`) carry only
the graft server, and that is deliberate: Serena's project root must point at the
**worktree you currently have open**. An absolute `--project` path committed to a
shared file would silently name someone else's (or no one's) checkout, so Serena
is a per-developer, user-level installation.

Setup (Serena is distributed as `serena-agent` and managed by `uv`):

```bash
uv tool install -p 3.13 serena-agent
serena init        # language-server backend; verify it reports success
```

Launch the server **without** a fixed `--project` and let each session activate
the project at its currently open worktree — that is what keeps one config valid
across worktrees:

```json
{
  "mcpServers": {
    "serena": {
      "command": "serena",
      "args": ["start-mcp-server", "--context", "ide-assistant"],
      "env": {}
    }
  }
}
```

- **Cursor** — paste that block into user settings (`~/.cursor/mcp.json`) or the
  project `.cursor/mcp.json`. Serena activates its project per session, so the
  same block works in both scopes; the repo's committed `.cursor/mcp.json`
  intentionally keeps only graft.
- **Zed** — same server under Zed's `context_servers` key (not `mcpServers`), in
  `~/.config/zed/settings.json` for user scope:

  ```json
  {
    "context_servers": {
      "serena": {
        "command": "serena",
        "args": ["start-mcp-server", "--context", "ide-assistant"],
        "env": {}
      }
    }
  }
  ```

  On macOS, GUI apps inherit a minimal `PATH`; if `serena` is not found, use the
  absolute path from `which serena` in the `command` field. The committed
  `.zed/settings.json` already shows the graft entry in the same shape.

The agent then runs Serena's project onboarding/activation for the open
worktree before symbol work, and points activation at a different worktree
directory whenever you switch branches.

## The fast feedback ladder

Run the cheapest check that can falsify the change, in order. Do not jump to the
full gate while a cheaper run is still failing — but do not call a task done
until the whole ladder is green.

| Rung | Command | What it proves | Cost |
|------|---------|----------------|------|
| 1 | `cargo fmt --all` (or `just fmt`) | Formatting matches rustfmt across the workspace | seconds |
| 2 | `cargo check -p <crate>` (optional first: `just check-fast-cargo`) | The touched crate compiles (`check-fast-cargo` only validates pinned toolchain/config wiring) | seconds–a minute |
| 3 | `just test-crate <crate>` (or `cargo test -p <crate> <filter>`) | New/changed behavior passes, including the failure path | a minute |
| 4 | `just clippy` | Zero warnings (`-D warnings`) across the workspace | a few minutes cold |
| 5 | `cargo test --workspace` | Nothing else regressed | longer |
| 6 | `just check-gated` | Linux-gated `cfg(target_os = "linux")` files compile (macOS `--all-targets` silently skips them) | minutes |
| 7 | `just ci` (`lint test test-doc bdd`) | The local approximation of the full CI gate | longest |

Two notes from experience:

- **Clippy is a gate, not a suggestion.** Never suppress with `#[allow(...)]`;
  fix the underlying issue. `#[allow(clippy::too_many_arguments)]` is banned
  outright — build a params struct with a builder instead.
- **Shape changes need rung 6.** Adding a field/variant/method to a shared type
  breaks Linux-gated test files that `cargo check --workspace` on macOS cannot
  even see; skipping rung 6 surfaces later as a CI
  `check-nextest-groups` failure that names neither the file nor the field.

## What CI covers, and what it doesn't

- `ci.yml` runs on pull requests, merge-queue (`merge_group` with
  `checks_requested`), and manual dispatch — not on ordinary branch pushes.
  It covers check/fmt/clippy/nextest and related gates used for merge readiness.
- `security.yml` runs on release tags, nightly schedule, and manual dispatch —
  it does not run on pull requests.
- Website/docs changes under `public/` are built and validated on PRs by
  `website.yml` and deploy to Cloudflare Workers Static Assets only after merge.
- The merge queue is maintained by `merge-queue-requeue.yml`; once a PR is
  queued, further pushes restart its checks. Wait for green checks plus queue
  merge before considering the work landed, and sync the main checkout
  (`git fetch origin && git pull --ff-only origin main`) immediately after.

Treat CI as the outer loop of the ladder above: everything through rung 7 should
already be green locally before a PR is opened, so CI failures mean a
platform-specific or environment-specific gap (Linux-only code paths, the
builder VM, self-hosted runner lanes), not a surprise formatting error.

## Opening and landing the PR

1. Push the worktree branch: `git -C ../.worktrees/mvm-<slug> push -u origin feat/<slug>`.
2. Open the PR against `main` with: a title in the conventional style used by
   the repo (`feat(area): …`, `fix(area): …`, `docs(area): …`), a summary of
   what changed and why, the validation you ran (ladder rungs), and
   `Closes #<n>` linkage. No assistant/tool attribution anywhere.
3. Respond to review by pushing fixup commits to the same branch; keep the
   issue status comment current.
4. After merge: sync main, remove the worktree
   (`git worktree remove ../.worktrees/mvm-<slug>`), and update
   `specs/SPRINT.md` / the plan checkboxes / `specs/REFACTOR-STATUS.md` per the
   Definition of Done in `AGENTS.md`.

## Safe parallelism

Multiple agents and humans routinely work this repo at once. The design keeps
that safe as long as the boundaries are respected:

- **One git operator.** All git traffic serializes through the main checkout;
  agents never run `git` inside a worktree.
- **Per-worktree state.** `scripts/dev-env.sh` isolates `MVM_HOME`, cargo
  target, and cargo registry; two worktrees can `cargo test` concurrently.
- **Shared by design:** the builder VM, the Nix store, `~/.cargo`, `~/.rustup`.
  Never fork a second builder VM — vary microVM and TAP names instead if two
  worktrees run microVMs concurrently.
- **Still shared, so still careful:** `.git/objects` (the serialization rule
  above), the builder VM's `/var/lib/mvm/` and `br-mvm` bridge (name your VMs
  distinctly), and anything published to a registry.
