# `mvmctl plugin install` — telling an agent mvm exists

**Plan:** `specs/plans/329-run-first-cli-and-upstream-adoption.md` Phase 6.

## The MCP question, answered by not building one

Phase 6 asked for a revived MCP server plus a plugin installer.
[ADR-002](../../adrs/002-local-mcp-server.md) already shipped that server and
withdrew it:

> It was a surface nobody drove: it shipped behind an opt-in feature composed
> only into `user`, had no consumer, and duplicated authority that the CLI's
> JSON output and the SDKs already expose.

That reasoning still holds. Rebuilding it identically would fail identically,
so ADR-002 stays withdrawn and `removed_mcp_server_stays_out_of_ci` stays in
force.

The reason to want an agent surface *now* is different from ADR-002's: not
"LLM clients need structured tool calls" — they shell out fine, and
`mvmctl run --json` already emits a redacted structured summary with the exit
code preserved — but **distribution**. Getting an agent to reach for mvm is a
matter of it having been told mvm exists. That is a file, not a protocol.

## What shipped

`mvmctl plugin list` and `mvmctl plugin install claude`, which writes
`.claude/skills/mvm-sandbox/SKILL.md`. Claude Code only: emitting a config for
an agent whose schema was guessed at produces a file that looks installed and
does nothing, so only a verifiable format is offered.

The install refuses to clobber an existing file — these land in a directory the
user curates by hand, and silently replacing something they wrote would be the
worst way for this to fail. `--dry-run` and `--force` are there.

## The interesting test

A skill that names a flag the CLI does not have is worse than no skill, because
the agent will type it. So the tests extract every `--flag` and every
`mvmctl <verb>` from the skill text and resolve them against the real clap tree.

The first version of the flag test compared against a **hardcoded list** rather
than the skill text. It passed, and it kept passing when `--timeout` in the
skill was renamed to `--deadline` — a test of a list I had written, not of the
artifact. Caught by mutation and rewritten to extract from the text; the
mutation is now red with a message naming the bad flag.

The skill is also written against the CLI as it now is rather than as the docs
once described it: `run` is the flagship one-shot, inference picks the image,
egress is deny-all, and the profile default is `standard`.
