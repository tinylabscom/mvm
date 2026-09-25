# MCP drive tools, grant-gated and fail-closed (issue #3262)

WS3 of `specs/plans/2026-09-15-agent-sandbox-drive-plane.md`.

- `mvm_hostd::drive::DriveAuthority` reloads a running machine's drive grant
  from its persisted admitted plan and accepts it only when the host-signed
  `verb-grant.json` verifies under the host key, names the same plan nonce, and
  carries the identical `DriveGrant`. No drive grant in the plan is the ordinary
  `Ok(None)`; a grant with a missing or mismatched signed record fails closed.
  `DriveSession` now delegates its path, size and refusal-audit checks to it,
  and the drive input lease rides the ordered `InputRoute` rather than a bare
  `InputSession`.
- `mvm_client::drive::LocalDrive` is the one controller over that authority:
  open the grant-selected program, write ordered input frames, poll events,
  and run bounded file operations. Its error codes come from
  `mvm_core::error_codes`.
- `mvm-mcp` adds `mvm.drive.{open,write,events}` and
  `mvm.drive.files.{read,write,list}`. Each tool row carries a `ToolGate`
  (always, a client operation, or the drive grant); drive tools are neither
  listed nor callable without a bound grant. A separate risk table classifies
  every tool as read-only, mutating or interactive, and a tool it does not name
  is denied whatever its gate says.
- `mvmctl ops mcp stdio --machine <name>` binds the drive tools to that
  machine when its plan grants them.
- The guest agent's request classification is untouched: claim 4's DevOnly set
  does not move.

Witnesses: `mcp_tool_absent_when_grant_absent` and
`mcp_unclassified_tool_is_denied` (both revert-checked: removing the grant
gate or the risk-table check fails exactly the matching test), plus
`every_drive_tool_routes_through_the_shared_controller`,
`existing_drive_authority_requires_the_matching_host_signed_grant`, and
`existing_drive_authority_fails_closed_when_the_sidecar_is_missing`. The tool
contract fixture records the six new tools as gated by `drive_grant`.
