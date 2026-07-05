# Verb-grant default eligibility gated on the image's sealed state

**Status:** Design (approved). Follow-on to ADR-103 / Plan 215, issue #1381 item 2.
**Date:** 2026-07-04
**Scope:** `mvm-cli` grant-decision sites only. No protocol/schema change.

## Problem

Plan-bound agent-verb enforcement mints a *default* `VerbGrant` (all `ProdSafe`
verbs, minus volume verbs when the workload declares no shares) for any
baked-entrypoint, non-interactive, non-ad-hoc, **non-dev-*profile*** run. The
`grant_eligible(pty, has_ad_hoc_argv, is_dev_profile)` predicate keys on the
**run's `--profile`**, not the **image's baked capability**.

But the host already records the image's real capability in the `mvm-meta.json`
`GuestSidecar` written next to every rootfs:

- `accessible: true` / `sealed: false` — dev-shell agent (console + `do_exec`
  symbols present).
- `accessible: false` / `sealed: true` — sealed prod agent (dm-verity, no
  console/`do_exec` — claim 4/15).

OCI-image workloads are **always** materialized with the dev-shell agent
(`GuestSidecar::for_oci_run` → `accessible: true, sealed: false`). So a plain
`machine run --image X -d` mints a `ProdSafe`-only default grant that then
**refuses `machine exec` / `machine console`** — even though the guest agent
can serve them. This was observed live on the KVM box (`ocica`: `machine exec`
→ `verb exec not authorized by the session's verb grant`). It is surprising
(docker-like `run -d` then `exec` is expected to work) and the grant bought no
real security there — the image has the dev symbols regardless of the run
profile.

Because minting a grant is the **restrictive** direction, this residual can
only *over*-restrict (break a legitimate later `exec`/`console` on a dev/OCI
image); it can never *under*-restrict. So it is a correctness/DX defect, not a
security hole.

## Design

Align the **default** grant with the image's actual sealed state, which the
host can read at admit time. Keep run mode as an additional gate. Leave
explicit `--agent-verb` overrides untouched (a user request is always honored).

### Change 1 — extend the pure predicate

`crates/mvm-cli/src/commands/vm/agent_verbs.rs`

```rust
pub(crate) fn grant_eligible(
    pty: bool,
    has_ad_hoc_argv: bool,
    is_dev_profile: bool,
    image_sealed: bool,
) -> bool {
    !pty && !has_ad_hoc_argv && !is_dev_profile && image_sealed
}
```

Still pure and truth-table testable. A grant is now eligible only for a
baked-entrypoint, non-dev-profile run **of a sealed image**.

### Change 2 — impure sidecar reader

`crates/mvm-cli/src/commands/vm/agent_verbs.rs`

```rust
/// Whether the image at `rootfs_path` is a sealed prod image, read from the
/// `mvm-meta.json` GuestSidecar the build/materialize pipeline writes next to
/// the rootfs. Absent/unreadable sidecar => `false` (treat as not sealed =>
/// no default grant), matching the `accessible: true` fallback convention and
/// pre-enforcement permissiveness. Backward-compatible for pre-sidecar artifacts.
pub(crate) fn image_is_sealed(rootfs_path: &std::path::Path) -> bool {
    rootfs_path
        .parent()
        .and_then(|dir| mvm_build::builder_vm::GuestSidecar::read_from_dir(dir).ok().flatten())
        .map(|s| s.sealed)
        .unwrap_or(false)
}
```

### Change 3 — the three production grant-decision sites pass `image_sealed`

- `crates/mvm-cli/src/commands/vm/up.rs` (persistent, ~:1190): the site already
  has `rootfs_path` in scope (used at ~:1198). Compute
  `image_is_sealed(&rootfs_path)` and pass it as the fourth arg.
- `crates/mvm-cli/src/commands/vm/exec.rs` (transient, ~:379): `rootfs` is in
  scope (used at ~:359). Same.
- `crates/mvm-cli/src/commands/vm/invoke.rs` (entrypoint invoke / `!keep_alive_dev`,
  ~:195): `rootfs: &std::path::Path` (closure param declared ~:165). Combines
  `!call.keep_alive_dev && image_is_sealed(rootfs)` — the dev-relay flag and the
  sealed-image check are both required for the attenuated grant to apply.

Test fixtures in `up.rs` `admit_plan_tests` (`restrict_agent_verbs: true`,
~:1716+) are unchanged — they set a scenario value deliberately.

### Explicit override is preserved

`synthesize_plan` computes `agent_verbs` as
`parse_agent_verb_override(...).or_else(|| default_agent_verbs(restrict_agent_verbs, ...))`
(up.rs:467-473). Only the `default_agent_verbs` branch is gated by
`restrict_agent_verbs`; an explicit `--agent-verb` returns `Some(..)` and wins
via `.or_else`, regardless of sealed state. No change needed there.

## Behavior after

| Run | Before | After |
|-----|--------|-------|
| Sealed prod flake entrypoint (`-d`, non-dev) | default grant | **default grant (unchanged)** |
| Dev-shell flake image entrypoint (non-dev profile) | default grant | class-gate-only |
| Any OCI image (`machine run --image X -d`) | default grant → `exec` denied | **class-gate-only → `exec` works** |
| Explicit `--agent-verb ping` (any image) | grant `{ping}` | grant `{ping}` (unchanged) |
| Interactive `-it` / ad-hoc `-- cmd` / dev profile | no grant | no grant (unchanged) |
| Absent sidecar (pre-enforcement artifact) | default grant | class-gate-only |

## Testing

- `grant_eligible`: extend the truth table with the `image_sealed` dimension —
  eligible **iff** `!pty && !argv && !dev && sealed`; every disqualifier
  (including `!sealed`) returns `false`.
- `image_is_sealed`: sealed sidecar → `true`; accessible sidecar → `false`;
  `GuestSidecar::for_oci_run` sidecar → `false`; absent dir/sidecar → `false`.
- Site behavior: a synthesized `SynthesisInput` with `restrict_agent_verbs`
  from an accessible-image site yields `agent_verbs: None`; a sealed-image site
  yields the default set; an explicit override yields the override on both.

## Live validation (Firecracker/KVM box)

- Re-run the exact `ocica` scenario (`machine run --image alpine -d` →
  `machine exec --name N -- echo ok`): `exec` now **succeeds** (no default grant
  minted; no `verb-grant.json` in the vm dir).
- Craft a sealed sidecar (`sealed: true`) next to a rootfs and confirm the
  default grant is still minted (`verb-grant.json` present) — proves the sealed
  path is unchanged.

## Non-goals

- Real cryptographic key separation (issue #1381 item 3 — separate ADR).
- Changing the sealed/accessible sidecar semantics or the `console`
  accessible-gate (`enforce_accessible_gate`) — reused as-is.
