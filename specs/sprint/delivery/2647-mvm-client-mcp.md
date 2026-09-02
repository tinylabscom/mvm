- **Revived MCP as a facade adapter (#2647).** `mvm-mcp` now serves the current
  stateless MCP protocol over bounded stdio, derives its deterministic tool
  catalog from each `MvmClient` implementation's serialized operation report,
  and routes every tool through that facade. Mock-only protocol tests cover all
  operations, strict failures, legacy initialize compatibility, and frame
  recovery. `mvmctl ops mcp stdio` and the named no-boot roundtrip consumer make
  the surface usable without adding a dedicated CI lane; ADR-048 supersedes the
  withdrawn bespoke server decision in ADR-002. Ten protocol tests, 209 passing
  BDD scenarios, host workspace clippy, gated-target checks, and a static ARM64
  Linux roundtrip in the libkrun builder cover the delivered surface.
