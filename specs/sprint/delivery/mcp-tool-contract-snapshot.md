# The MCP tool surface is pinned before it grows

Backing: shipped-source
Validation: cargo nextest run -p mvm-mcp

`mvm-mcp` described its tools in one function and decided which to offer in
another. The second was a `match` on the tool name ending in `_ => false`, so a
tool added to the first and forgotten in the second was never offered and
nothing said so. Nothing pinned the names or input schemas either: a rename, a
dropped `required` field, or a loosened schema shipped as an ordinary diff,
never read as a change to what an agent is offered. The drive-plane plan's WS3
is about to add six tools to this surface.

## One row per tool

Each tool is now one `ToolSpec` row: name, description, input schema, and the
client operation that gates it (`ToolSpec::always` or `ToolSpec::gated`).
`tools/list` filters the table and `tools/call` checks the same row, so there is
no second list of names to fall out of step with the first.

Two unit tests hold the rows honest. `every_specified_tool_is_offered_by_a_real_gate`
reads the operation fields off `ClientOperationCapabilities`' wire form rather
than a hand-kept list, then requires every row to be offered when every
operation is served, requires every gated row to be hidden when none is, and
requires each gated row to be enabled by exactly one operation.
`every_specified_tool_has_a_handler` calls every row against the mock client and
refuses a tool that `call_tool` does not handle. That is the same drift one step
later: offered, but answered with "unknown tool".

## The contract fixture

`crates/mvm-mcp/tests/fixtures/tool-contract.json` holds what a fully capable
client is advertised, built from `tools/list` responses rather than read out of
the table. For each tool it records the name, description, input schema, and the
operation that gates it (`null` when every client gets the tool). Tools are
sorted by name, object keys are sorted at every depth whatever map ordering
`serde_json` was built with, and the file is pretty-printed with a trailing
newline. `tool_surface_matches_the_pinned_contract` rebuilds that form and
fails on any byte of difference. The failure lists which tools were added,
removed, or changed, and prints the re-bless command:

```sh
MVM_UPDATE_MCP_TOOL_CONTRACT=1 cargo test -p mvm-mcp --test protocol tool_surface_matches_the_pinned_contract
```

The variable follows the repository's existing `MVM_UPDATE_DOCS_COVERAGE`
convention: the test rewrites the committed file, and the reviewer reads the
diff.

**Descriptions are in the contract.** An agent reads them as prompt text when it
decides which tool to call, so rewording one changes behaviour as surely as
renaming a field does. **The gating operation is in it too.** A tool that moves
from exec-gated to offered by every client is a change to what an agent is
allowed to do, and it deserves a reviewer as much as a schema change does.

`required` arrays keep their declared order. JSON Schema treats them as sets,
so reordering one fails the gate without changing meaning. That is a cheap
false positive, and one fixed order is what makes the file byte-stable.

This is a crate test, not an `xtask check-*`. The repository's other
frozen-output gates (`audit_chain_frozen_bytes`, `mvmev_archive_vectors`) are
crate tests beside the code they pin, so this one runs under
`cargo nextest run --workspace` locally and in CI without a separate lane.

## Evidence

The gate was checked against deliberate breakage, reverted each time:

- Loosening `mvm.machine.pause`'s `primed_timeout_secs` minimum from 1 to 0
  fails the contract test with `changed: mvm.machine.pause`.
- Renaming `mvm.machine.set_ttl` in the table fails the contract test with
  `added: mvm.machine.set_expiry` / `removed: mvm.machine.set_ttl`, and the
  handler test with "is advertised but `call_tool` has no arm for it".
- A gate that can never fire (`mvm.machine.exec` gated by `|_| false`, the
  table's version of a forgotten `match` arm) fails the gate test with "is
  specified but no client ever offers it".
- Gating `mvm.machine.start` on the `stop` operation passes the gate test,
  because it is still one real operation, and fails the contract test, which
  records the gating operation.
