# Refresh the CLI grammar doctrine and gate the surface mechanically

Backing: preview
Validation: none

**Date:** 2026-08-15
**Status:** Proposed
**Relates to:** ADR-027 (`machine` is the sole CLI surface for workload microVMs, Accepted)
**Consumed by:** mvmd `specs/adrs/0028-cli-surface-consolidation.md`, which adopts mvm's grammar verbatim

---

## Why

mvmd is adopting mvm's CLI grammar wholesale (mvmd ADR-0028). Its 130
top-level nouns — 72 of whose modules reach no backend at all — go to 30,
under mvm's rules rather than a second invented set. That makes mvm's
doctrine load-bearing for two repos instead of one, and surfaces two
problems on this side.

### Problem 1: `GROUPING.md` is stale and is marked LOCKED

`crates/mvm-cli/src/commands/GROUPING.md` describes the Plan 178 target:

> **Daily verbs / entry points:**
> `up` · `run` · `exec` · `invoke` · `ls` · `console` · `down` · `logs` · `dev` · `doctor` · `init`
>
> **`vm/`** — act on an existing/running VM: `vm pause` · `resume` · …

ADR-027 then superseded exactly that shape:

> There is no separate `vm` noun; its verbs are `machine`'s verbs. There is
> no `up`, `down`, `run` (as a top-level verb), `console`, or `invoke`
> command — those names do not exist at the top level.

The code followed ADR-027, not `GROUPING.md`:
`crates/mvm-cli/src/commands/mod.rs:116` is `Machine(machine::Args)`, and
`Commands` has no `Up`, `Down`, `Ls`, `Console`, or `Invoke` variant.

So the file a new contributor is most likely to read — the one physically
next to the code, headed **LOCKED** — documents a surface that does not
exist and contradicts the Accepted ADR that replaced it. mvmd's ADR-0028
currently cites it as live doctrine.

### Problem 2: the surface is held by convention, not by CI

ADR-027's "hidden internals, visible daily drivers" decision **is**
implemented — `Commands` carries 26 `#[command(hide = true)]` attributes
against 41 variants, leaving ~15 visible, which matches the ADR's stated
visible set.

Nothing enforces that. mvm runs 62 `xtask check-*` gates, and
`check_cli_runtime_surface` polices CLI *layering* (mvm-cli must not reach
into mvm-runtime internals), but no gate polices CLI *surface*. A 16th
visible noun lands on a green CI. The 130-noun outcome on the mvmd side is
what that looks like after two years.

## What this plan does

1. Rewrite `GROUPING.md` to describe the surface that actually exists, and
   mark it as derived from ADR-027 rather than from the superseded Plan 178.
2. Add `xtask check-cli-surface`, holding the top-level noun set and each
   noun's visibility in a lock file, in the same allowlist-with-a-reason
   style as `check_cli_runtime_surface`.
3. Extract the four grammar principles into a section both repos cite, so
   mvmd ADR-0028's reference points at something that stays true.

Out of scope: changing any command. This plan documents and gates the
surface as it is. If the audit in Task 1 finds a noun that violates
ADR-027, it is recorded, not fixed here.

---

## Task 1: Audit the real surface

**Files:**
- Create: `specs/notes/338-cli-surface-audit.md`

- [ ] **Step 1: Dump the top-level surface with visibility**

```bash
cd crates/mvm-cli
cargo run -q --bin mvmctl -- --help
```

Then the authoritative version, straight from the enum:

```bash
awk '/pub\(in crate::commands\) enum Commands/,/^}/' src/commands/mod.rs \
  | grep -B3 -E '^\s{4}[A-Z][A-Za-z]+\(' \
  | grep -E 'hide = true|^\s{4}[A-Z][A-Za-z]+\('
```

- [ ] **Step 2: Record it**

Write `specs/notes/338-cli-surface-audit.md` with one row per variant:
`name`, `visible|hidden`, and — for each visible one — the ADR-027 clause
that authorizes it. ADR-027 names the visible set as `machine`, `build`,
`kernel`, `init`, `doctor`, plus `explain`, `prepare`, `pack`, and
`bootstrap`.

- [ ] **Step 3: Flag any divergence**

Any visible noun not in ADR-027's list is a divergence. Record it in a
"Divergences" section with a one-line note on whether it looks like drift
or like an intentional post-ADR addition. **Do not change it.** Task 3's
lock file records reality; closing a divergence is separate work with its
own ADR amendment.

- [ ] **Step 4: Commit**

```bash
git add specs/notes/338-cli-surface-audit.md
git commit -m "docs(cli): audit mvm's real top-level surface against ADR-027"
```

---

## Task 2: Rewrite `GROUPING.md` against ADR-027

**Files:**
- Rewrite: `crates/mvm-cli/src/commands/GROUPING.md`

**Interfaces:**
- Consumes: the audit from Task 1.
- Produces: the "Grammar principles" section, cited by mvmd ADR-0028 and by
  Task 3's lock-file header.

- [ ] **Step 1: Replace the header and the stale sections**

The new file keeps the useful parts of the old one — the directory
convention, the settled decisions that survived — and drops everything
ADR-027 superseded. Structure:

```markdown
# CLI command grouping — derived from ADR-027

**Authority:** `specs/adrs/027-cli-surface-consolidation.md` (Accepted).
This file describes how that ADR is realised in the tree. Where the two
disagree, the ADR wins and this file is the bug.

**Superseded:** Plan 178's target surface (`up` · `run` · `exec` ·
`invoke` · `ls` · `console` · `down` top-level, plus a `vm/` group) was
replaced by ADR-027's single `machine` noun. That shape never shipped.

## Grammar principles

These four rules govern the CLI surface. mvmd adopts them verbatim
(mvmd `specs/adrs/0028-cli-surface-consolidation.md`); keep them stable.

1. **One object, one noun.** Never a second top-level name for the same
   underlying thing.
2. **Daily-driver verbs and primary entry points stay visible; everything
   else is `#[command(hide = true)]`** — out of `--help`, not deleted,
   still working when named explicitly.
3. **A new capability is a flag or a subcommand on an existing noun, not a
   new top-level noun.** Image source is `--image` / `--flake` on
   `machine run`, not a command tree per source. Persistence is `--name` /
   `--detach`, not separate verbs.
4. **No single-member and no semantically-forced groups.** A group exists
   because several verbs share an object.

Corollary, from ADR-027's pre-1.0 stance: **renamed and removed verbs get
no alias.** A shim preserves the confusion the consolidation removes.

## Layout convention

Clap group = `commands/<group>/` directory, one file per subaction.

## Visible surface

One row per noun, verbatim from `specs/notes/338-cli-surface-audit.md`.
Generate the list with:

    cargo run -q --bin mvmctl -- --help \
      | sed -n '/^Commands:/,/^Options:/p' \
      | grep -E '^  [a-z]' | awk '{print "- `" $1 "` — " substr($0, index($0,$2))}'

## Hidden surface

Every noun in the audit marked `hidden`, in two groups: **operator
surfaces** (`env`, `manifest`, `image`, `storage`, `ops`, `network`,
`catalog`, `cache`, `pool`, `secret`, `bundle`, `trust`, `deps`,
`artifact`, `reconcile`) and **internal subprocess transports** (the
`__`-prefixed ones, `shell-init`, `persistent-builder`, `seccomp-audit`).
Take the exact membership from the audit, not from this list — ADR-027's
enumeration and the tree may have diverged, which is what Task 1 Step 3
records.

## Note on `commands/vm/`

The `vm/` directory survives as an internal implementation namespace —
`crate::commands::vm::up::…` is called from `exec.rs` — not as a CLI noun.
ADR-027 removed the `vm` *command*; the module path is a leftover and
renaming it is unfinished cleanup, not a surface question.
```

- [ ] **Step 2: Verify no claim in the new file is false**

For every noun the file lists as visible, confirm it appears in
`mvmctl --help`. For every one listed as hidden, confirm it does **not**
appear there but does respond to `mvmctl <noun> --help`.

```bash
cargo run -q --bin mvmctl -- --help | sed -n '/^Commands:/,/^Options:/p'
```

- [ ] **Step 3: Commit**

```bash
git add crates/mvm-cli/src/commands/GROUPING.md
git commit -m "docs(cli): rewrite GROUPING.md against ADR-027

The file was marked LOCKED while describing Plan 178's superseded target
(up/run/exec/invoke/ls/console/down, a vm/ group) — a shape ADR-027
replaced with the single \`machine\` noun and which never shipped. It now
describes the surface that exists, and carries the four grammar
principles mvmd ADR-0028 adopts."
```

---

## Task 3: `xtask check-cli-surface`

**Files:**
- Create: `xtask/src/check_cli_surface.rs`
- Create: `crates/mvm-cli/cli-surface.lock`
- Modify: `xtask/src/main.rs` (`mod` declaration + dispatch arm)
- Modify: the CI workflow that runs the other `xtask check-*` gates

**Interfaces:**
- Consumes: the audit from Task 1 as the lock file's initial content.
- Produces: `xtask check-cli-surface`, run in CI beside the other 62 checks.

- [ ] **Step 1: Write the lock file from the audit**

`crates/mvm-cli/cli-surface.lock`, `<name> <visible|hidden>` one per line,
seeded from Task 1's audit. Header:

```
# mvm top-level CLI surface — LOCKED
# Authority: specs/adrs/027-cli-surface-consolidation.md
# Grammar:   crates/mvm-cli/src/commands/GROUPING.md
#
# `xtask check-cli-surface` asserts the rendered clap tree matches this file
# exactly. Adding a top-level noun, or flipping one from hidden to visible,
# requires editing this file in the same commit — which makes it a reviewable
# event. A new capability is a flag or a subcommand on an existing noun
# (GROUPING.md principle 3) and does not belong here.
```

- [ ] **Step 2: Write the check**

`xtask/src/check_cli_surface.rs`, following `check_cli_runtime_surface`'s
shape — a doc comment stating the rule, then `pub fn run(workspace: &Path) -> Result<()>`
that `bail!`s with an actionable message.

The check reads the lock file and compares it to the rendered tree. mvm's
`Commands` enum is `pub(in crate::commands)`, so xtask cannot use
`CommandFactory` across the crate boundary. Shell out to the built binary
instead and parse `--help`, which has the additional virtue of testing what
users actually see:

```rust
//! `xtask check-cli-surface`
//!
//! The top-level CLI noun set is locked by `crates/mvm-cli/cli-surface.lock`.
//! ADR-027 fixed the visible surface to the daily drivers and hid the rest;
//! nothing but this check keeps a 16th visible noun off a green CI.
//!
//! A new capability is a flag or a subcommand on an existing noun
//! (GROUPING.md principle 3). If it genuinely needs a new top-level noun,
//! amend ADR-027 and edit the lock file in the same commit.

use anyhow::{Result, bail};
use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

pub fn run(workspace: &Path) -> Result<()> {
    let lock_path = workspace.join("crates/mvm-cli/cli-surface.lock");
    let locked = parse_lock(&std::fs::read_to_string(&lock_path)?)?;
    let visible = visible_from_help(workspace)?;

    let mut problems = Vec::new();

    for name in &visible {
        match locked.get(name.as_str()) {
            None => problems.push(format!(
                "  `{name}` is visible in --help but absent from the lock file"
            )),
            Some(false) => problems.push(format!(
                "  `{name}` is locked as hidden but is visible in --help"
            )),
            Some(true) => {}
        }
    }

    for (name, want_visible) in &locked {
        if *want_visible && !visible.iter().any(|v| v == name) {
            problems.push(format!(
                "  `{name}` is locked as visible but is absent from --help"
            ));
        }
    }

    if !problems.is_empty() {
        bail!(
            "mvm's top-level CLI surface drifted from {}:\n{}\n\n\
             A new capability is a flag or a subcommand on an existing noun\n\
             (GROUPING.md principle 3). If it truly needs a new top-level noun,\n\
             amend ADR-027 and edit the lock file in the same commit.",
            lock_path.display(),
            problems.join("\n"),
        );
    }

    println!("cli-surface: {} nouns locked, surface matches", locked.len());
    Ok(())
}

/// `<name> <visible|hidden>` per line; `#` comments and blanks ignored.
fn parse_lock(raw: &str) -> Result<BTreeMap<String, bool>> {
    let mut out = BTreeMap::new();
    for (i, line) in raw.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let (Some(name), Some(vis)) = (parts.next(), parts.next()) else {
            bail!("cli-surface.lock line {}: expected `<name> <visible|hidden>`", i + 1);
        };
        let visible = match vis {
            "visible" => true,
            "hidden" => false,
            other => bail!("cli-surface.lock line {}: bad visibility `{other}`", i + 1),
        };
        out.insert(name.to_string(), visible);
    }
    Ok(out)
}

/// The nouns a user actually sees. Parses the `Commands:` block of `--help`,
/// which is the surface ADR-027 is about.
fn visible_from_help(workspace: &Path) -> Result<Vec<String>> {
    let out = Command::new("cargo")
        .current_dir(workspace)
        .args(["run", "-q", "--bin", "mvmctl", "--", "--help"])
        .output()?;

    if !out.status.success() {
        bail!(
            "`mvmctl --help` failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    let help = String::from_utf8_lossy(&out.stdout);
    let mut names = Vec::new();
    let mut in_commands = false;

    for line in help.lines() {
        if line.starts_with("Commands:") {
            in_commands = true;
            continue;
        }
        if in_commands {
            // The block ends at the next unindented section header.
            if !line.starts_with(' ') && !line.trim().is_empty() {
                break;
            }
            if let Some(first) = line.split_whitespace().next() {
                // Skip continuation lines of a wrapped description.
                if line.starts_with("  ") && !line.starts_with("      ") {
                    names.push(first.to_string());
                }
            }
        }
    }

    if names.is_empty() {
        bail!("parsed no commands out of `mvmctl --help` — the format changed");
    }

    names.sort_unstable();
    names.dedup();
    Ok(names)
}
```

- [ ] **Step 3: Register it**

In `xtask/src/main.rs`, add `mod check_cli_surface;` beside the other `mod`
declarations, and a dispatch arm matching the existing pattern:

```rust
        Some("check-cli-surface") => {
            let workspace = workspace_root();
            check_cli_surface::run(&workspace)
        }
```

- [ ] **Step 4: Run it and verify it passes**

Run: `cargo run -p xtask -- check-cli-surface`
Expected: `cli-surface: N nouns locked, surface matches`.

If it reports drift, the lock file disagrees with reality — fix the lock
file, not the CLI. Task 1's audit is the source; a mismatch means the audit
missed a row or the `--help` parser needs adjusting for a wrapped
description line.

- [ ] **Step 5: Verify the gate actually bites**

Temporarily flip one hidden noun to visible in the lock file, re-run:

Run: `cargo run -p xtask -- check-cli-surface`
Expected: FAIL, naming that noun as "locked as visible but absent from --help".

Restore the lock file, re-run, expect PASS.

- [ ] **Step 6: Add it to CI**

Add `check-cli-surface` to whichever workflow step runs the other
`xtask check-*` gates. Find it with:

```bash
grep -rn "check-cli-runtime-surface" .github/workflows/
```

Add the new check beside it, in the same style.

- [ ] **Step 7: Commit**

```bash
git add xtask/src/check_cli_surface.rs xtask/src/main.rs \
        crates/mvm-cli/cli-surface.lock .github/workflows
git commit -m "feat(xtask): gate the top-level CLI surface

ADR-027 fixed the visible noun set and hid the rest; nothing enforced it,
so a 16th visible noun landed on a green CI. check-cli-surface locks the
set and each noun's visibility, in the same allowlist style as
check-cli-runtime-surface."
```

---

## Task 4: Point the two repos at each other

**Files:**
- Modify: `specs/adrs/027-cli-surface-consolidation.md` (add a References section)
- Modify: `crates/mvm-cli/src/commands/GROUPING.md` (cross-reference)

- [ ] **Step 1: Add references to ADR-027**

Append to `specs/adrs/027-cli-surface-consolidation.md`:

```markdown
## References

- `crates/mvm-cli/src/commands/GROUPING.md` — how this ADR is realised in
  the tree, and the four grammar principles in their citable form.
- `crates/mvm-cli/cli-surface.lock` + `xtask check-cli-surface` — the
  mechanical gate. Amending this ADR's visible set means editing the lock.
- mvmd `specs/adrs/0028-cli-surface-consolidation.md` — mvmd adopts these
  principles verbatim. Changing them here changes them for two binaries;
  say so in the commit.
```

- [ ] **Step 2: Verify every referenced path exists**

```bash
for p in crates/mvm-cli/src/commands/GROUPING.md \
         crates/mvm-cli/cli-surface.lock \
         xtask/src/check_cli_surface.rs; do
  [ -f "$p" ] || echo "MISSING $p"
done
ls ../mvmd/specs/adrs/0028-cli-surface-consolidation.md
```

Expected: no `MISSING` lines, and the mvmd ADR resolves. If mvmd's ADR is
not present, the cross-reference is still correct — it lands with mvmd's
own plan — but note that in the commit message rather than deleting it.

- [ ] **Step 3: Commit**

```bash
git add specs/adrs/027-cli-surface-consolidation.md \
        crates/mvm-cli/src/commands/GROUPING.md
git commit -m "docs(cli): cross-reference the CLI grammar across mvm and mvmd

ADR-027's principles now govern two binaries; changing them here changes
mvmd's surface too."
```

---

## Notes for the executor

- **`#[command(hide = true)]`, not `#[command(hidden)]`.** `hidden` is clap 3
  syntax and does not compile under clap 4. mvm already uses `hide = true`
  in 26 places; match that.
- **The audit records reality; it does not fix it.** If Task 1 finds a
  visible noun ADR-027 does not authorize, that is a finding for the
  Divergences section and a follow-on issue. Locking reality and then
  arguing about it in review is the right order — locking an aspiration
  gives you a red CI and no leverage.
- **`check_cli_surface` shells out to `cargo run`,** so it is slower than
  the source-scanning checks. Put it wherever the workflow already tolerates
  a build, not in a fast pre-commit path.
- **`commands/vm/` is a module path, not a CLI noun.** Do not "fix" it as
  part of this plan; ADR-027 removed the command, and renaming the module
  is unrelated cleanup.
