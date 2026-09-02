# Jailer Landlock ruleset

`ConfinementSpec::network_endpoint()` permits:

- **Read** on an allowlisted helper binary (`Execute | ReadFile |
  ReadDir`, the `from_read(ABI::V2)` bit-set).
- **Read** on `~/.mvm/keys/host-signer.ed25519` (chain signing key —
  the role needs to read it once at startup, no write).
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

Everything else returns EACCES at the kernel level. Sockets are
inherited fds or opened by the endpoint itself, not opened by name from
the ruleset, so no network paths appear in it.

## `mvm-network-endpoint` — resolver UDS (M3)

`ConfinementSpec::network_endpoint(..., resolver_uds)` additionally
grants `read_write_paths` on the fleet-secrets daemon's UDS path when
the endpoint's `ResolverBackend` is `Remote { uds_path, .. }` — `Local`
(`resolver_uds: None`) leaves the ruleset unchanged. Unlike every other
entry in `read_write_paths` (which are directories), the resolver UDS
is a socket special file, so it gets the narrower `rw_file_access()`
bit-set (`ReadFile | WriteFile` only) rather than `rw_bridge_access()`'s
directory rights — `ReadDir` / `MakeReg` / `Refer` / `RemoveFile` are
meaningless on a non-directory target and downgrade the whole ruleset
to `PartiallyEnforced` if requested there (`landlock.rs::apply()`
branches on `path.is_dir()` for exactly this reason). `MakeSock` is
deliberately absent — the resolver daemon creates the socket; this
process only ever `connect()`s to it.

This grant is also, deliberately, **not** filtered through
`existing_paths()` the way the readable TLS/DNS paths are. `Remote`
mode is useless without the resolver reachable, so a missing socket
path should surface as Landlock's own `PathNotFound` (fail-closed) —
not silently vanish into an empty grant that lets confinement
"succeed" while `Remote` can never resolve anything.

No seccomp change accompanies this grant: `socket` / `connect` / `read`
/ `write` / `setsockopt` are already unconditionally in the endpoint's
`allowed_syscalls` (the TLS forward leg's TCP egress already needs
them), and seccomp here filters by syscall number only — there is no
per-call AF_UNIX-vs-AF_INET argument predicate to narrow. The
confinement narrowing for `Remote` is entirely a Landlock (path)
concern; see `SECCOMP.md` for the syscall table.

## Authenticated-session marker

Endpoints configured to publish authenticated-session launch readiness also
receive bounded read-write access to the marker's already-existing per-VM
parent directory. The opt-in grant lets the endpoint create and verify the
durable marker after authentication; endpoints without a marker retain the
narrower default ruleset.

ABI v2 (Linux 5.19+) required for the file-execute permission split —
v1 collapses read + exec into a single bit, which would force us to
choose between letting the confined role exec into other binaries or
preventing it from reading its own helper binary at all.

## Refusal posture

`apply()` only returns `Ok(())` when the kernel reports
`RulesetStatus::FullyEnforced`. `PartiallyEnforced` / `NotEnforced`
return `JailerError::LandlockApply` so the caller can decide to abort
(the confined role aborts in that case — partial
confinement is no confinement). See the partial-confinement contract
doc on `confine_self` in `lib.rs` for the hard-exit requirement when
seccomp fails *after* Landlock succeeds.

`RulesetError::CreateRuleset(_)` at the `handle_access(AccessFs::from_all(V2))`
step maps to `JailerError::LandlockUnavailable` so the role can
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
