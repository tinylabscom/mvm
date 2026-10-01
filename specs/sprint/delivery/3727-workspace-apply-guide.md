# Workspace apply guide (PS-18, #3727)

## What landed

`guides/workspace-apply.md` — "Bring agent changes home" — the capability
page for the reviewed workspace loop: the private-copy model, `machine
diff` (content), the reviewed apply (`--dry-run`, the `Apply to working
tree? [y/N]` prompt, `--yes` for non-interactive use, `--exclude`,
protected-path gate), undo/redo semantics (including redo's
nothing-newer-since guard), and `machine replay` from a checkpoint with
per-step restore points. Sidebar entry beside Persistent Workspaces; the
page closes with what apply does not do (external effects already left
the guest), matching the lineage-recovery guide's evidence-boundary
framing.

Doc-example discipline held: the four new command paths carry parse
tiers with reasons (the pin moves 70 → 74 deliberately, each entry
explaining itself), and the four commands hermetically exercised by the
s26 scenarios moved from `uncovered` to `covered` in the ledger — the
ratchet's own direction.

## Tests

The s29 doc-examples suite passes every gate this touches: tier
coverage, the parse-tier pin, the coverage ratchet, placeholder
templates, and prose command existence. (The suite's one local failure,
`env verify-release`, is environment-dependent and predates this
change; CI runs it with its fixture.)
