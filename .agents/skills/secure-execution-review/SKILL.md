---
name: secure-execution-review
description: Check MVM runtime, backend, policy, networking, package, or lifecycle changes against local authority and evidenced security guarantees. Use before designing or reviewing security-sensitive MVM work.
---

# Review a secure execution change

Read `AGENTS.md` first. Start from the governing issue and the ADRs and
contracts it links. Use Trail to locate the owning production path and its
callers. ADR-001's claims table and backend matrix govern shipped security
claims; proposals, fixtures, and tests for other backends do not extend them.
Do not use this skill to turn a small unrelated change into a repository-wide
audit. For a focused security review, use the security-audit skill in guidance
mode when available; a full codebase audit requires its own request. Rust
changes still follow the repository's Rust-skill rule.

1. **State the contract.** Identify the user-visible operation, selected
   backend, caller, signed plan or pack, trust boundary, and exact outcome.
   Classify each involved capability as shipped, preview, or proposed.
   If ownership, public API, authorization, or the security model changes,
   obtain the required design/ADR review before implementation.
2. **Trace the one authority path.** Follow the operation from the client
   through policy resolution, signed admission, the selected backend, and
   host-side enforcement. For network or mailbox work, distinguish canonical
   MVM local contracts from optional MVMD cross-host delivery. Check that
   each backend either enforces the advertised capability or refuses it
   before execution; do not introduce a second gate, guest NIC, SSH path,
   silent fallback, or cache-based authorization.
3. **Name the threat and evidence.** Say which actor may be compromised and
   whether protected data is at rest, in transit, in use, or retained after
   termination. Check issuer, digest, revocation freshness, epoch, replay,
   bounds, key custody, and audit where relevant. Do not call a host-held
   key, best-effort RAM scrub, or simulated exchange a malicious-host or
   physical-erasure guarantee. State any hardware requirement explicitly.
4. **Review changed transitions.** For launch, build/cutover, mailbox,
   offline/reconnect, quarantine, replacement, or pack admission, enumerate
   states, transition owner, durable evidence, deadlines, cancellation,
   crash recovery, and typed refusal or unknown outcomes. A verified build
   is not an admitted or ready replacement; mailbox acceptance, delivery,
   and application acknowledgement are separate.
5. **Prove behavior at the right boundary.** Add a happy-path witness and
   negative tests for the relevant tampering, wrong principal/key, stale
   epoch, replay, unavailable enforcement, quota exhaustion, and cleanup
   failure. Use the actual backend or label mock/fixture evidence as such.
   Measure cold and warm readiness with admission included, and record
   image preparation, launch, and safe replacement separately when touched.
   Do not trade a required check for a faster reported clock.
6. **Report honestly.** Update the owning issue, applicable contract and
   user documentation with observed status and links to tests. Run the
   repository's scoped and required gates, name exact source revisions and
   commands, and call out unrun live/hardware checks. Keep unfinished
   checkboxes open. Do not claim another repository's design direction is
   implemented here.
