# ADR-037 held two decisions; the superseded one is now ADR-052

Two files carried the number: `037-mvmd-only-production-launch.md` (`Accepted`)
and `037-userspace-socket-datapath.md` (`Superseded` by ADR-042). Forty
citations of "ADR-037" resolved to whichever a reader happened to open.

**Which one moved, and why.** The datapath ADR. It is superseded, so its inbound
citations are backward-looking and cheap to redirect; the launch-authority ADR is
`Accepted` and cited by ADR-006, ADR-045 and ADR-049 as current authority, where
a renumber would churn live references. Note the datapath ADR was the *older* of
the two (2026-08-02 vs 08-04) and so had the number first — that lost to the
live-versus-superseded criterion, which is about reader cost, not seniority.

**Why 052.** Sweeping every ADR number from 052 to 120, the only ones cited
anywhere were 106 and 107 (the dangling pair the ledger-drift plan still owns)
and 110 (which exists). A different ADR held 052 before the v1 restructure
deleted it; both files now record that, so a stale external reference is not
silently misread.

**The citations were classified by hand, not blanket-replaced.** 23 meant the
datapath and were retargeted line by line; 15 meant the launch authority and were
left alone. Two were genuinely ambiguous — ADR-046's `Complements:` list and the
secure-message-fabric plan's `ADR-037/040/041 cross-repo ownership` line. Both
resolved to the launch authority: ADR-040 and ADR-041 are cross-node trust
boundaries, and ADR-042 already covers the networking path, so naming the
datapath in either place would be redundant. Both ADRs now carry a note saying
which reading a pre-2026-09-04 citation takes.

**A rename alone would have failed the build.** `check_declared_backing.rs`
listed the old path in `PENDING`, and that list may only shrink — a `PENDING`
entry naming a file that no longer exists is a hard error. Updated with the move.

**`check-adr-coverage` caught a self-inflicted defect, twice.** A draft of the
plan's WS-E note wrote the swept range in citation form, so the upper bound
parsed as a reference to an ADR that does not exist and the gate went red. The
first draft of *this* note then made the same mistake while describing it. Both
reworded. Prose about ADR numbers has to avoid the citation form or it becomes a
citation — the gate cannot tell the difference, and should not try. It is doing
here exactly what WS-B of the ledger-drift plan records it cannot do inside
`specs/adrs/`.

Verified: `check-all` 67 gates clean, `cargo nextest run -p xtask` 705 passed,
`just bdd` 252 scenarios 251 passed 1 skipped, and no duplicate ADR number
remains.
