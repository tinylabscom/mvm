# AI coding workflow docs

Backing: shipped-source
Validation: check-sprint-append

**Status: IMPLEMENTED — PR #3815 open, merge pending.**

## Scope

Make the AI coding workflow reliable and keep `AGENTS.md` concise: move the
issue-to-PR playbook into the docs site as a full guide, and reduce the root
`AGENTS.md` from a 588-line manual to a short, always-applicable rule index
that keeps every normative rule and points at the guide for detail.

- [x] Add `public/src/content/docs/contributing/ai-coding-workflow.md`
      covering issue claim/status ownership, the required worktree workflow,
      the Graft/Serena division of responsibility, per-developer Zed/Cursor
      Serena configuration, the fast feedback ladder, CI/merge-queue scope,
      PR linkage, and safe parallelism.
- [x] Verify the editor examples against the current official Zed MCP
      documentation, Cursor MCP documentation, and Serena client
      documentation.
- [x] Link the guide from
      `public/src/content/docs/contributing/development.md` and register it in
      `public/src/sidebar.ts`.
- [x] Condense `AGENTS.md` (588 → 281 lines) into a rule index preserving
      every always-applicable rule: builder-VM boundaries and owner-approved
      exceptions, cargo-on-host default, single git operator, worktree
      workflow, definition of done, test expectations, waiting model,
      privacy/security, clippy zero-warnings (including the
      `too_many_arguments` builder rule), no `unwrap()`, no spec references in
      comments, reuse-first, and Rust best practices.
- [x] Leave the shared MCP files (`.cursor/mcp.json`, `.zed/settings.json`)
      unchanged — a committed absolute Serena `--project` path would point at
      one developer's worktree and mislead the team; Serena stays a
      per-developer, user-level installation with per-session project
      activation.
- [x] Validate with `pnpm install --frozen-lockfile && pnpm build` in
      `public/` (150 pages built, including `/contributing/ai-coding-workflow/`).
