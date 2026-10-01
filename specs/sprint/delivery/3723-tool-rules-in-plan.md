# Tool rules ride the signed plan (PS-13 slice C, part 1)

Enforcement needs the resolved tool rules where decisions happen — the
per-VM endpoint, the MCP surface, and (next) the in-guest mediation — so
the rules now travel inside the signed `ExecutionPlan`, never a bundle:

- `mvm_contract::policy::tool_rules` defines `ToolRules` /
  `ToolRuleDetail` (allow / ask / deny plus per-tool argv, deny-argv,
  routes, secrets). Empty fields serialize away, and an empty section is
  the default: the dimension stays opt-in and an unused dimension does
  not change plan bytes.
- `ExecutionPlan.tools` carries the section inline, next to `redaction`
  and `secrets`; the host signature covers it, and the content address
  changes exactly when the rules change.
- `SynthesisInput` accepts the rules (`.tools(...)` builder, empty
  default), and the transient-run admission path feeds them from the
  resolved authored policy (`RunArgs.applied_policy.tools`), so a
  `run --policy` launch's plan carries the same rules `policy resolve`
  showed.
- `mvm_client::policy_profiles` maps `ToolsSection` to `ToolRules` in
  `fold`, so there is one conversion and every consumer reads the
  contract shape.

## Testing

Contract serde tests (empty serializes away, round trip with detail,
unknown fields refused), two fold tests (mapping and the empty default),
and the plan/synthesis/admission suites.

## Next in slice C

The consumers: a host-side `ToolRules` evaluator (argv glob matching,
deny/ask/allow precedence, `ApprovalSubject::ToolCall` asks through the
supervisor, chain-signed audit per decision), the guest mediation verb
on the agent protocol, and the endpoint wiring that answers it.
