# mvm-jailer-lite Landlock ruleset

`ConfinementSpec::firecracker_bridge()` permits:

- **Read** on the passt binary (`Execute | ReadFile | ReadDir`, the
  `from_read(ABI::V2)` bit-set — passt is the bridge's child process).
- **Read** on `~/.mvm/keys/host-signer.ed25519` (chain signing key —
  the bridge needs to read it once at startup, no write).
- **Bounded read-write** on `~/.mvm/audit/` (chain file append +
  atomic rename). The grant is **not** `from_all(V2)`; it's the
  minimum bit-set that supports append + atomic-rename:

  | Bit          | Why it's granted                                                       |
  | ------------ | ---------------------------------------------------------------------- |
  | `ReadFile`   | Verify the existing chain head before appending (signing requires it). |
  | `ReadDir`    | Enumerate `.tmp` files to clean up after a crashed writer.             |
  | `WriteFile`  | Append the new audit entry.                                            |
  | `MakeReg`    | Create the `.tmp` file used for atomic write-then-rename.              |
  | `Refer`      | Rename `.tmp` → final path (atomicity).                                |
  | `RemoveFile` | Unlink stale `.tmp` files.                                             |

  Notably **absent** (would be granted by `from_all`):
  `Execute` (no exec inside audit dir), `MakeChar` / `MakeBlock` /
  `MakeSock` / `MakeFifo` / `MakeSym` (device-style nodes have no
  place in an audit-log directory), `MakeDir` (audit subdirectories
  are not allowed; chain files live flat under the tenant dir).

  The `rw_bridge_access_does_not_include_dangerous_bits` unit test
  asserts these absences as defense-in-depth against a future
  contributor swapping back to `from_all`.

Everything else returns EACCES at the kernel level. passt's sockets
are inherited fds, not opened by name, so no network paths appear in
the ruleset.

ABI v2 (Linux 5.19+) required for the file-execute permission split —
v1 collapses read + exec into a single bit, which would force us to
choose between letting the bridge exec into other binaries or
preventing it from reading its own passt binary at all.

## Refusal posture

`apply()` only returns `Ok(())` when the kernel reports
`RulesetStatus::FullyEnforced`. `PartiallyEnforced` / `NotEnforced`
return `JailerError::LandlockApply` so the caller can decide to abort
(the `mvm-firecracker-bridge` sidecar aborts in that case — partial
confinement is no confinement). See the partial-confinement contract
doc on `confine_self` in `lib.rs` for the hard-exit requirement when
seccomp fails *after* Landlock succeeds.

`RulesetError::CreateRuleset(_)` at the `handle_access(AccessFs::from_all(V2))`
step maps to `JailerError::LandlockUnavailable` so the bridge can
print an actionable error on hosts older than Linux 5.19.

## Path errors

A missing path in `ConfinementSpec::{readable_paths, read_write_paths}`
surfaces as `JailerError::PathNotFound { path, source }` carrying the
exact failing path. The most common cause is `~/.mvm/audit/` not
existing — the supervisor's bootstrap is expected to create it mode
0700 before spawning the bridge. The operator sees:

```
landlock path missing: /Users/.../.mvm/audit: No such file or directory
```

rather than the bare `io: No such file or directory` we used to emit.
