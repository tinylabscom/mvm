# Per-tool privileges in authored policy (PS-13 slice A)

`[tools]` grew from a recorded-only allow/deny pair into the per-tool policy
enforcement will consume, with composition rules that only ever narrow:

- **Whole-tool decisions**: `allow`, `ask`, `deny` lists. They union across
  layers; `deny` beats `ask` beats `allow`.
- **Per-tool detail** under `[tools.detail.<name>]`: `argv` (glob patterns
  permitted, e.g. `git *`), per-tool `deny` argv patterns, `routes`
  (`HOST[:PORT]` destinations), and `secrets` (names bound to the tool).
  The first layer to define a tool's `argv`/`routes`/`secrets` sets the
  grant; later layers may repeat or restrict it, never extend it — the same
  subset rule secret destinations use. Per-tool `deny` unions, since
  refusing more only narrows. An empty incoming list never clears.
- **Validation names the layer, file and key**: tool-name alphabet
  (lowercase, digits, `-`, `_`, `.`), argv patterns are single-line and
  bounded, routes go through the one `--allow-host` canonicalizer, secrets
  through the secret-name validator.
- `mvmctl policy show/diff` render `tools.ask` and every detail field, and
  `mvmctl why --tool` answers with ask and detail context. The JSON Schema
  and the published schema page are regenerated from the types.

Still recorded-only: `policy validate --strict` keeps refusing a policy that
relies on `[tools]` until the enforcement slice (host-mediated tool gate +
approval `ask` + MCP wiring) lands. Nothing in the merge gives a layer a way
to widen another layer's tool grant.

## Testing

Eleven merge tests (union/ask/deny precedence, detail narrowing and the
widening refusal with layer+key, first-definition semantics, invalid names
and detail entries, serde round trip), `why --tool` ask/detail answers, and
the schema drift tests under `--features schema`.
