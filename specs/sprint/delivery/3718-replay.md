# Replay from a checkpoint with recorded input (PS-08, #3718)

Builds on the replay foundations that landed with the workspace-apply slice
(#3843): the encrypted, content-addressed session input artifacts
(`mvm-runtime::agent_session::replay_input`), the chain-verified ordered
planner/dispatcher (`agent_session::replay`), and session-bound `vm_full`
step checkpoints. This slice is the operator replay command for the channel
that is already exposed — `machine exec` argv — which the plan records as
the remaining gap (agent-prompt step orchestration stays blocked on the
general agent prompt transport reaching `mvmctl`).

## What landed

The last PS-08 item. `machine exec` now records every executed argv as an
encrypted, content-addressed artifact. Its per-machine JSONL journal contains
only start/finish sequencing, an encrypted artifact reference, and a success
bit — never argv, errors, or output. A shared per-machine lock serializes exec
with checkpoint capture; an unfinished exec fails closed, while a torn final
line from a crash is dropped on read. `mvmctl machine replay
<checkpoint>`:

1. reads the exact input-journal cursor sealed into the checkpoint and selects
   later entries from the machine that created it — no wall-clock ordering or
   same-second ambiguity;
2. fork-boots the checkpoint exactly like `machine revert` — a fresh,
   re-admitted VM whose workspace images are the checkpoint's frozen
   copies, so the re-run starts from byte-identical state (no host-dir
   refresh hazard: the fork path materializes checkpoint bytes, it does
   not re-snapshot source dirs);
3. re-executes each selected entry against the restored VM and takes a
   vm-full checkpoint after each one (`replay-step-<n>` tag), so every
   replayed step is a first-class restore point under `checkpoint ls` —
   diffable with `machine diff --to` and forkable. Backends without
   save/restore support fall back to a workspace-image copy under the
   machine's state dir, and say so;
4. leaves the restored VM running at the final step.

`--dry-run` reports the plan (selected entries, step count) without
restoring; `--as NAME` names the restored machine (default auto-named);
`--no-step-checkpoints` skips the per-step captures. Replay never touches
the original machine, its journal, or any host directory — it is a fork.
A mid-replay failure leaves the restored VM at the last good step.

## Tests

unit tests cover encrypted-at-rest journal roundtrips, torn lines, unfinished
exec refusal, exact-cursor selection, and replay planning; 2 BDD
scenarios on the fail-closed surface; audit kind `machine_replay` with
pinned wire string and posture row.

## Deliberate scope

The input journal records `machine exec` argv only. Stdin payloads,
console sessions, and SDK-dispatched calls are not recorded — extending
the journal to those channels is follow-up work once a caller needs it.
