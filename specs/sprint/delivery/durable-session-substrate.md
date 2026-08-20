# Durable session substrate: checkpoint session binding + filesystem store

`specs/plans/2026-08-18-durable-agent-sessions.md` frames the problem: a
long-running agent task outlives the disposable sandbox that runs it, and
today there is no verifiable resume point between a live checkpoint and a
sealed archive. This branch delivers the substrate that later park/resume/
retention work builds on — `specs/plans/2026-08-18-durable-session-substrate.md`
Tasks 1–5 — with no VM, backend, or async surface involved.

## Delivered

- `mvm_core::config::agent_sessions_dir()` — `<mvm_home>/agent-sessions/`,
  sibling to `checkpoints_dir()`. Named `agent-sessions` rather than
  `sessions` to stay distinct from the unrelated warm-VM-across-`invoke`
  session directory `domain::session` already owns.
- `mvm_core::checkpoint::SessionBinding` — `session_id`, `generation`,
  `journal_cursor`, `approval_head` — carried as `Option<SessionBinding>` on
  `CheckpointMeta` and folded into `meta_digest` the same way `grants`
  already is (`skip_serializing_if` on the digest input, so a checkpoint
  sealed before the field existed still hashes exactly as it did then —
  `sealing_no_grant_leaves_a_records_digest_where_it_was` pins the sibling
  case for `grants` and stays green). A direct, non-session workload sets
  `None`.
- `mvm_core::checkpoint::ApprovalHead` — a dedicated `sha256:<64-hex>`
  newtype for the approval-ledger head `SessionBinding.approval_head` names.
  Not `CheckpointDigest` reused: an approval-ledger head and a checkpoint
  content-address are different hash chains, and `CheckpointDigest`'s own doc
  explains it carries no conversion to any other prefixed digest type on
  purpose, so the type boundary has to be a second type, not a shared one.
  `from_bytes(&[u8; 32])` bridges the `[u8; 32]` shape
  `PolicySet::digest`/the approval ledger produce.
- `mvm_runtime::agent_session::{AgentSessionRecord, SandboxResidency,
  AgentSessionStore}` — a filesystem store mirroring `checkpoint::
CheckpointStore`: one `<id>/session.json` per session, `write`/`load`/`list`,
  `#[serde(deny_unknown_fields)]`. `AgentSessionRecord.parent_checkpoint` is
  typed `CheckpointDigest`, not `CheckpointId` — a content-address, not a
  mutable name, matching `CheckpointMeta.parent`'s own rule so a resume can
  detect a post-seal edit of the checkpoint it names, and getting
  deserialize-time shape validation for the on-disk field for free.
- `fork_checkpoint` / `fork_vm_full` explicitly set `.session(None)` on the
  child. Without it the omission was accidental rather than deliberate: a
  fork starts a new sandbox lineage, while a resume continues the same
  session at `generation + 1`, so a forked child inheriting the parent's
  binding would claim to be the same session, at the same generation and
  journal cursor, as a parent checkpoint that may still be backing a running
  sandbox. Regression tests pin `None` on both fork paths, verified against a
  `.session(parent.session.clone())` mutation that makes each fail.

## Deliberately not covered

Everything past the substrate: WS3 park path (`ParkReason`, quiesce
sequencing), WS4 resume path (`resume_session`, incremental ledger-head
verification, fresh-plan synthesis), WS5 retention ladder + teaching the
existing `checkpoints_dir()` sweep about sessions (that sweep,
`sweep_untagged_checkpoints`, already existed — this branch does not add the
first GC, only the session-awareness it lacked), WS6 CLI (`mvmctl session
...`), WS7 chain records (`session.opened`, `sandbox.parked`, ...), WS8 BDD
scenarios. `SessionBinding` and `parent_checkpoint` are what that GC reads to
refuse reaping a checkpoint a live or hibernated session still names as its
parent, but nothing enforced that refusal at the time this was written.
`specs/plans/2026-08-18-session-retention.md` has since delivered the refusal
(both the sweep and a manual `mvmctl vm checkpoint rm`) plus a one-way
`demote` transition; retention classes, expiry, and a scheduler that calls
`demote` remain undelivered.
