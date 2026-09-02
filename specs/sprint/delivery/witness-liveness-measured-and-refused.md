# Witness reachability: measured, refused, and the doc comments it surfaced

Plan: `specs/plans/2026-09-01-committed-agent-notes-and-asserted-absence.md`

## Outcome

The two reachability follow-ons recorded in that plan were **measured before
being built, and both are refused.** No gate ships. The measurement and its
reasoning are recorded in
`.agent-memory/notes/witness-reachability-gate-measured-and-refuted.md` — the
first use of the committed-notes mechanism for the thing it exists for.

Method: `check-dormant-controls`' exact caller rule, applied to all 84 `fn:`
witnesses in the ADR-001 ledger.

| | count |
|---|---|
| Witness names not found anywhere | 0 |
| Production-defined witnesses with no production caller | 1 |
| Test-defined witnesses with ≥1 dead subject | 20 |
| Survivors after removing the two dominant noise classes | 4 |
| **Genuine findings after reading all six survivor symbols** | **0** |

The failure modes are structural rather than tunable. The defining-file
exclusion hides a caller twelve lines above the definition — `set_no_new_privs`
is claim 2's own witness and reads as dead. Trait dispatch is invisible to a
text rule (`teardown_paused`). Name collisions merge distinct symbols
(`tier_for_vm`). And a cross-crate test helper must be `pub` and outside
`#[cfg(test)]` to be visible at all, so `pretend_mechanism_present`,
`rendered_argv` and `CannedIO::with_network_interfaces` are correct as written
and all read as dead. `check-dormant-controls` escapes every one of these only
because a human hand-picks each control it tracks.

Blanking comments in that gate's haystack — its own documented limit, and the
same fix that closed the citation-resolver defect last week — changes **zero**
verdicts on this population. Not one symbol's only caller was a comment.

The hole `CLAUDE.md` names stays open, and `CLAUDE.md` continues to say so.
Closing it needs a real call graph, or the ledger declaring each witness's
subject the way `dormant-controls.toml` declares a control — 84 declarations
and an owner for them.

## Shipped

Six stale doc comments corrected. `download_dev_image` was named by five
comments across `mvm-core`, `mvm-cli`, `mvm-build` and `xtask` and defines
nothing; `crates/mvm-core/src/observability/metrics.rs` additionally named
`try_fetch_signed_manifest`, whose only occurrence in the whole tree was that
comment. Both now name the real pipeline —
`fetch_expected_hashes` / `verify_artifact_hash` in
`crates/mvm-cli/src/commands/env/artifact_verify.rs`, and
`download_builder_vm_image` where a sibling download path was meant.

`CLAUDE.md`'s claim-6 absence region keeps `download_dev_image` under gate; only
the sentence describing the stale comments changed, since they are no longer
stale.

## Gates

`check-all` 65 clean · `nextest --workspace` 12911 pass · workspace clippy,
`--doc`, `fmt --all --check`, `just check-gated` all clean.
