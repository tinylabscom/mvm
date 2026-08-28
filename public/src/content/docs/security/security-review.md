---
title: The security review
description: The questions an enterprise security team asks before approving an agent deployment, and the mvm mechanism that answers each one.
---

You're shipping an agent product into an enterprise. Somewhere between the
pilot and the contract, your customer's security team opens the review — and
the questions they ask are remarkably consistent. This page maps each one to
the mvm mechanism that answers it, with the numbered
[CI-enforced claim](/security/ci-claims/) that backs the answer.

Two ground rules, so this page survives the review it describes:

- Every claim number below links to a machine-checked ledger row with a named
  test or CI-job witness. Nothing here is asserted without one.
- Where the honest answer is "partially" or "roadmap", the page says so and
  links the limit. Reviewers find the gaps anyway; better they find them
  labeled.

## 1. What exact workload will execute?

A workload boots only from a signed `ExecutionPlan` — a typed, Ed25519-signed
authorization artifact naming the artifact, its hashes, and the granted
authority. Bundles are content-addressed and key-pinned, re-verified at fetch
and again at admit time; OCI images are admitted by resolved manifest digest.
The answer to "what will execute" is a hash, not a tag.
*Claims 8, 9, 14.*

## 2. Can the agent change what executes after approval?

A production rootfs is dm-verity sealed: a flipped block panics the kernel
before userspace runs. The sealed guest has no shell, no PTY, and no dev-only
agent verbs, so the admitted program cannot be swapped for an interactive
session or a replacement process.
*Claims 3, 4, 15.* One scoped exception exists: an operator can stream
**stdin** to the admitted entrypoint under an explicit plan grant — input to
the approved program, not program selection. Its limits are documented as
preview claim 17 in the [claims ledger](/security/ci-claims/).

## 3. Which network destinations can it reach?

Only the ones the admitted policy names. Egress defaults to deny-all, and an
unrestricted policy is not selectable at all: the one resolution funnel every
dispatched verb goes through yields deny-all, the `dev` preset via `--net`, or
an explicit `--allow-host` allow-list. Nothing warns about unrestricted egress
because nothing can request it.
*Claim 10.*

## 4. Can it discover or steal credentials?

Raw secret values never enter the guest. <!-- allow(doc-claim:secret-non-leakage): backed by numbered claim 13 (no raw secret crosses the broker channel) plus preview claim 16, both named on the line below; the `secret-non-leakage` parity row stays Planned because it asserts more than those two do -->
The workload sees placeholders; the
host-side endpoint substitutes real credentials only into connections it
originates, bound to destination and time. A credential scoped for one
service cannot be replayed to another from inside the guest, because the
guest never holds it.
*Claim 13, preview claim 16.*

## 5. What happens after prompt injection?

The containment does not depend on the model behaving. A fully compromised
agent still has no network device, still exits only through the deny-all
vsock gate, still holds no raw credentials, and still cannot open a shell in
a sealed guest. Prompt injection changes what the agent *tries*; the
boundary limits what trying can *do*.
*Claims 10, 13, 15.*

## 6. Can it escape the approved authority?

Authority is enumerated in the signed plan, not ambient. Host services
dispatch only against a plan binding, checked before the handler runs.
Inside the guest, services run de-privileged (no path to uid 0, no
host-filesystem access beyond explicit shares), and the host-side attack
surface — vsock framing, supervisor config, datapath ingress — is fuzzed.
*Claims 1, 2, 5, 12.*

## 7. Can we deploy it in our environment?

Local (your developers' macOS and Linux machines) is shipped, open source,
Apache-2.0. Hosted is design-partner preview; BYOC / private deployment is
roadmap. Status per tier is tracked on the
[capability status](/security/capability-status/) page — deployment answers
in a review should quote that table, not this sentence.

## 8. Can we prove what happened after an incident?

Every admission, launch, failure, policy decision, and provenance record
lands in a chain-signed audit log. Tampering with an entry breaks the chain;
`mvmctl trust audit verify` walks every segment and exits nonzero on drift.
Known limit, stated in the ledger: truncating the tail of the live segment
is not detectable — the chain proves integrity of what is present, not that
nothing was cut from the end.
*Claims 8, 14.*

## 9. How do we know the artifact hasn't changed since review?

The artifact your security team reviewed is identified by content hash and
digest, and every later admission re-verifies those pins before boot. A
mutable tag can't drift underneath an approval: production OCI runs refuse
mutable references before any network fetch.
*Claims 9, 14.*

## 10. Can you generate evidence for our compliance process?

The audit chain is the evidence: signed, ordered, machine-verifiable records
of what was admitted, under what policy, and what happened — consumable from
`~/.mvm/audit/` and verified with `mvmctl trust audit verify`. The
[CI-enforced claims](/security/ci-claims/) page itself is reviewable
evidence too: each control names the test or CI job that gates it.

---

The architecture behind these answers is in the
[threat model](/security/threat-model/); the per-claim witnesses are in
[CI-enforced claims](/security/ci-claims/); what's shipped versus roadmap is
in [capability status](/security/capability-status/).
