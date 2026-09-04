# Repair the ADR-001 ledger drift left by the v1 restructure

Backing: shipped-source
Validation: check-sprint-append

**Status: NOT STARTED — this is the repair plan, not the repair.**

Prerequisite for any work that hashes or versions claim statements. Hashing a
statement in a document that is already internally inconsistent freezes the
inconsistency into the baseline, so this lands first and alone.

## What is wrong

Measured on `origin/main` at `2eff78c623`. Every line number below was read, not
inferred.

### 1. ADR-001 carries two claim tables that disagree on what a number means

`specs/adrs/001-microvm-security-posture.md` holds:

- a **narrative table** at `:139–156` — 16 rows, columns `# | Claim | Layer | Enforcement`, parsed by nothing;
- a **machine-checked ledger** at `:746–766` inside `<!-- claims-catalog:begin/end -->` — 19 rows, columns `# | Claim | Witnesses | Authority | Status`, parsed by `xtask/src/claims_ledger.rs`.

Rows 1–15 agree. Then they diverge:

| # | Narrative table (`:141–156`) | Ledger (`:748–766`) |
|---|---|---|
| 16 | asset identity / share drift | egress-substitution leak-gate (`Preview`) |
| 17 | — | workload stdin (`Preview`) |
| 18 | — | resource bounding (`Preview`) |
| 19 | — | asset identity / share drift (`Shipped`) |

So "claim 16" names two different claims in one file. The narrative table has no
row for the three `Preview` claims, even though prose blocks at `:182`, `:209`
and `:218` discuss them as "Preview 17", "Preview 16" and "Preview 18" — using
the *ledger* numbering. The narrative table is the side that drifted.

`check-claim-catalog` cannot see this: `extract_ledger_section`
(`xtask/src/claims_ledger.rs:70–83`) deliberately scopes to the marker-delimited
region so that the ADR's other tables are never mistaken for catalog rows.

### 2. `CLAUDE.md` describes a 19-row ledger as 18 rows

`CLAUDE.md:252` — "parses that table (rows 1–18…)". The ledger has 19 rows and
has had since the asset-identity claim landed. `CLAUDE.md`'s §"Security model"
also documents Preview 16/17/18 and never mentions claim 19.

### 3. Four citations of ADRs deleted by the restructure

Cited at `specs/adrs/001-microvm-security-posture.md:750` (ledger row 3's
Authority cell), `:884`, `:886`, `:888`.

`specs/adrs/` holds 001–051 plus a lone 110. Both ADRs existed
(`106-in-process-rootfs-materialize.md`, `107-virtiofs-root-integrity.md`) and
were deleted by `d115fcebe3` ("v1 simplification restructure", #1720), which
removed the entire 002–111 range and renumbered a new 001–051 set in its place.
Those numbers were then reused for unrelated decisions, so the citations do not
merely dangle — **they resolve, in a reader's head, to the wrong ADRs.**

No surviving ADR covers either topic. Grepping `specs/adrs/` for `virtiofs`
returns only ADR-001 itself and `011-feature-flag-taxonomy.md`; nothing covers
in-process rootfs materialization as a decision.

`check-adr-coverage` cannot catch this by construction: it skips `specs/adrs/`
entirely (`xtask/src/check_adr_coverage.rs:119–123`) so that ADRs referring to
themselves do not inflate the reference count.

### 4. Duplicate ADR number `037` — resolved 2026-09-04

`037-mvmd-only-production-launch.md` and what was then
`037-userspace-socket-datapath.md`. Same failure mode `check-plan-names` exists
to stop for plans; ADRs have no equivalent gate. The datapath ADR is now
ADR-052 — see WS-E.

### 5. `specs/claims/` ghosts, including two in a public file

The directory was deleted by the same `d115fcebe3`. Still referenced:

- `specs/adrs/001-microvm-security-posture.md:761` — ledger row 14 Authority cell cites `specs/claims/claim-10-oci-image-provenance.md`
- `specs/adrs/001-microvm-security-posture.md:763` — ledger row 16 Authority cell cites `specs/claims/claim-egress-no-secret-to-guest.md`
- `SECURITY.md:49` — a markdown link to `specs/claims/claim-10-oci-image-provenance.md`
- `SECURITY.md:96` — a markdown link to `specs/claims/`

`CLAUDE.md:256–257` asserts the directory "has never existed on this branch".
That is false — it was deleted, not imagined. The correction itself needs
correcting.

### 6. `SECURITY.md` misdescribes the security surface, publicly

Beyond the two broken links:

- `:96` — "currently 1–10; ADR-020 proposes two more on merge". The ledger has 19 claims, 16 `Shipped`.
- `:46` and `:48` name four verbs that are not top-level commands. The `Commands` enum (`crates/mvm-cli/src/commands/mod.rs`) has no `Up`, `Audit`, `HostKey` or `Services`. Audit verification is `mvmctl trust audit verify`; `up` is not a dispatched verb at all, which `CLAUDE.md` already records.

This is the vulnerability-disclosure policy. It is the first file a reporter
reads, and it currently points them at a directory that does not exist and four
commands they cannot run.

## Root cause

One commit. `d115fcebe3` (#1720) deleted several hundred files under `specs/`
and renumbered the ADR set. Inbound references from surviving files were not
swept, and no gate covers the two reference classes involved — ADR-to-ADR
citations, and relative markdown links into `specs/`.

## Workstreams

Independent; land separately.

### WS-A — Reconcile the two ADR-001 tables

- [ ] Renumber narrative-table row 16 (asset identity) to 19
- [ ] Add narrative rows 16, 17, 18 for the three `Preview` claims, or replace the tail of the table with a pointer to the ledger
- [ ] Decide and record which table is canonical for a reader (proposal: the ledger; the narrative table becomes an index)
- [ ] Fix `CLAUDE.md:252` "rows 1–18" → 19, and add claim 19 to §"Security model"

### WS-B — Resolve the citations of the deleted ADRs

Needs a decision before it can be executed — see Open questions.

- [ ] Decide the disposition (new ADR / inline into ADR-001 / drop)
- [ ] Apply it at `:750`, `:884`, `:886`, `:888`
- [ ] Sweep for any other citation into the deleted 052–111 range

### WS-C — Retire the `specs/claims/` references

- [ ] Repoint ledger row 14's Authority cell (`:761`) to a surviving authority
- [ ] Repoint ledger row 16's Authority cell (`:763`)
- [ ] Fix `SECURITY.md:49` and `:96`
- [ ] Correct `CLAUDE.md:256–257` — the directory existed and was deleted by `d115fcebe3`; say that instead of "never existed"

### WS-D — Bring `SECURITY.md` back to true

- [ ] Replace "currently 1–10" with the live count, or a pointer to `CONFORMANCE.md` so it cannot go stale again
- [ ] Correct the four non-existent verbs
- [ ] Re-read the whole file against the current surface; the parts above were found by spot-check, not by audit

### WS-E — Rename one duplicate ADR-037

- [x] Renumbered the **superseded** side: `037-userspace-socket-datapath.md` is now `052-userspace-socket-datapath.md`. ADR-037 stays with `mvmd-only-production-launch`, which is `Accepted` and cited as current authority; renumbering a superseded document churns only backward-looking references.
- [x] Retargeted all 23 inbound citations that meant the datapath, classified line by line rather than by blanket replace. 15 that meant the launch-authority ADR were left alone. Two ambiguous ones — ADR-046's `Complements:` list and this plan's own `ADR-037/040/041 cross-repo ownership` line — were resolved to the launch-authority ADR: ADR-040 and ADR-041 are cross-node trust boundaries, and ADR-042 already covers the networking path, so listing the datapath there would be redundant.
- [x] `052` was verified free: sweeping every ADR number from 052 to 120, the only ones cited anywhere in the tree were 106, 107 (the dangling pair WS-B still owns) and 110 (which exists). A different ADR held 052 before the v1 restructure deleted it, which both files now record. Note the number cannot be named here in citation form without the coverage gate reading it as a reference — that gate caught exactly that mistake in an earlier draft of this line.
- [x] Updated `check_declared_backing.rs`'s `PENDING` entry, which named the old path and would have failed the gate on a rename alone.

## Why nothing caught this, and the minimum to stop it recurring

Not part of the repair. Recorded here so the decision is deliberate; the earlier
framing of this work was "cheap, no new machinery", and adding gates breaks that.

Three structural blind spots:

1. **ADR-to-ADR citations are unchecked.** `check-adr-coverage` skips `specs/adrs/` to avoid self-reference inflation. A narrow variant — resolve `ADR-NNN` tokens inside `specs/adrs/` while ignoring a file's citations of *itself* — would have caught items 3 and 4 on the commit that broke them.

   The blind spot is demonstrable, and this plan demonstrated it. An earlier
   draft named the two deleted ADRs by citation token while describing the
   problem, and `check-all` went red: `check-adr-coverage` counted 4 references
   to non-existent ADRs, all 4 from this file, and **zero** from the four live
   citations in `specs/adrs/001-microvm-security-posture.md` that the plan
   exists to fix. The gate works everywhere except the one directory where the
   drift lives. The draft was reworded to name the deleted files by path
   instead, which is why the prose below reads that way.
2. **Relative markdown links are unchecked anywhere.** Nothing resolves `[text](path)` against the tree, which is why two dead links sit in `SECURITY.md`.
3. **`SECURITY.md` is in no prose gate.** `check-witness-citations` and `check-asserted-absence` scan five files (`xtask/src/prose_citations.rs:33–39`) and `SECURITY.md` is not among them; `check-doc-claims` scans `public/` and the root `README.md`, not `SECURITY.md`.

- [ ] Decide whether to add a link-resolution gate and a narrow in-ADR reference check, or accept the exposure

## Out of scope

- Statement hashing on `model/claims.toml`. That is the follow-on, and it depends on this landing first.
- Any change to `model/claims.toml`, `CONFORMANCE.md`, or witness sets. The 19 register entries are correct; the drift is in the prose around them.
- The compliance-mapping gap. `specs/compliance/{soc2-controls,hipaa-mapping,pci-scope,gdpr-mapping}.md` were also deleted by `d115fcebe3`, but they were explicit stubs — `soc2-controls.md` was 71 lines of `(TBD)` bullets marked `**Status:** STUB` and never filled. Deleting them was right. Real control mapping is a separate piece of work and belongs with `mvm-assurance`, not here.

## Open questions

1. **What happens to the two deleted decisions?** They scope claim 3: dm-verity witnesses the claim on block+ext4 backends, and virtiofs-root is a dev tier with a weaker contract that does not witness it. That scoping is load-bearing for a `Shipped` claim and currently rests on two citations that resolve to nothing. Restoring the content as a new ADR in the 0xx range is the safer option; inlining it into ADR-001 is cheaper but grows a file that is already 1,080 lines. Needs a call.
2. **Is the 052–111 citation sweep bounded?** Item 3 was found by grepping two specific numbers. The full inbound-reference set for the deleted range has not been enumerated; WS-B's third box may be larger than it looks.
3. ~~**Which ADR-037 keeps the number?**~~ Resolved in WS-E: the live `Accepted` launch-authority ADR keeps 037; the superseded datapath ADR became 052. They were not both live — that was the wrong premise.
