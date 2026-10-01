# MCP tool-call gate (PS-13 slice B)

The resolved `[tools]` section is now enforced at one live seam, with the
rest of the program's machinery reused rather than rebuilt:

- `mvm-mcp` gains a `ToolCallGate` trait and a `ToolGateDenial`, consulted
  after the static catalog check and before any backend work in `tools/call`.
  The crate still holds no policy: the embedding surface supplies the gate,
  keeping JSON-RPC framing and DTO translation the only concerns here. A
  refusal renders as a normal MCP tool result with `isError` and a
  `policy_gate_denied` `_meta.code`.
- `mvmctl ops mcp stdio` binds `McpToolGate` over the project's resolved
  policy (the same resolution `mvmctl why` performs). Whole-tool decisions
  enforce: `deny` refuses with the policy reason, `ask` builds an
  `ApprovalSubject::ToolCall` prompt for the terminal approver and fails
  closed when nothing answers, `allow` admits, and an unlisted tool fails
  closed. Every non-allow decision emits a `ToolGateDecision` local audit
  entry (`tool= outcome= reason=`).
- The dimension stays opt-in: no `[tools]` section anywhere means no gate.
  A policy that exists but does not resolve refuses to start the server —
  half-applied policy must never silently widen to "no gate".
- Per-tool `argv`/`routes`/`secrets` detail is not enforced at this seam:
  MCP arguments are tool-specific JSON, not command lines or destinations.
  That binding needs the in-guest mediation (slice C) that carries tool
  identity to the endpoint. `policy validate --strict` keeps refusing a
  policy that relies on `[tools]` until then.

## Testing

Six gate-unit tests (allow/deny/unlisted-fail-closed/precedence/unanswered
ask/detail-is-not-an-allow), three mvm-mcp wiring tests (bound gate refuses
before backend work, admitted call passes, ungated server unchanged), and an
end-to-end `ops mcp stdio` integration test in `tests/cli.rs` driving two
`tools/call` frames against an isolated project whose group denies
`mvm.machine.stop` and allows `mvm.machine.list`.

## Remaining for #3723

Slice C: in-guest command mediation for declared tools — the guest agent
reports each invocation over vsock, the host checks argv/detail against the
resolved policy, asks through the approval supervisor where configured, and
every decision lands in the chain-signed audit log. That seam is also where
per-tool `routes`/`secrets` binding and the `ToolRegistry` host-mediated
tools gain their live caller.
