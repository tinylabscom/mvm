# AI Trust-Layer Entrant — Deep Comparison

**Date:** 2026-09-02
**Status:** Research note — competitive / ecosystem assessment
**Source basis:** the entrant's public website (home + one funding press
release) and funding coverage in the trade press. They are pre-GA with no
public docs, code, or pricing, so their side of this comparison is
positioning-level only; inferences are marked. The company name is deliberately
omitted — refer to "the entrant."

---

## 1. What the entrant is

- **Stage:** Seed. $5.1M announced 2026-08-11, led by Flying Fish, with Toyota
  Ventures, Amplify Partners, Tandem Ventures, SaaS Ventures. Pre-GA; hiring
  toward general availability. Primarily Seattle-based.
- **Leadership:** Founder/CEO is a senior AI-infrastructure operator —
  previously CPO at a major GPU cloud (through its IPO) and previously led the
  AI infrastructure business at a hyperscaler (grew it 20x). Strong
  go-to-market + infra operator profile; the seed thesis is clearly "AI infra
  veteran selling to enterprises."
- **Positioning:** "The trust layer for production AI" / "one control plane for
  the model layer." Their thesis: models, weights, datasets, prompts, and
  agents are becoming an organization's core IP; owning AI means owning its
  chain of trust; existing tools force teams to stitch together fragmented
  security/governance/compliance, so trust should be an intrinsic property of
  the platform instead.
- **Name caveat for search hygiene:** the company uses a name that collides
  with the brain-inspired silicon literature (spiking neural networks, that
  hardware family). Keep the two literatures separate in any search work.

### Their stated architecture (from the homepage)

A seven-stage AI lifecycle — Data → Experiment → Train → Align → Evaluate →
Optimize → Deploy — wrapped by a control plane that does two things: _enforce
policy at runtime_ and _create verifiable evidence_, while assets stay in the
customer's existing tools (notebooks, experiment tracking, pipeline
orchestration, deployment/monitoring) and existing infrastructure (public
cloud, on-prem, edge, hybrid).

Their one fully-specified primitive is **asset identity**:

> Every dataset, model, prompt, agent, policy, and compute environment receives
> a unique cryptographically verifiable identity that follows it throughout its
> lifecycle. Identity is derived from the contents of the asset itself, and for
> compute environments from their **measured state**. Every identity is signed,
> versioned, and immutable — any change produces a new identity while
> preserving history. Assets are **registered by reference**, so they stay in
> the systems where they already live.

Everything else (policy language, evidence format, enforcement mechanism,
attestation protocol) is unspecified publicly.

---

## 2. Side-by-side

| Dimension                    | The entrant                                                        | mvm (us)                                                                                                                                   |
| ---------------------------- | ------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------ |
| **Layer in the stack**       | Control plane / governance plane for the _model lifecycle_         | Isolation + execution plane for _workloads_                                                                                                |
| **Unit of trust**            | The **asset**: dataset, model, prompt, agent, policy               | The **run**: signed `ExecutionPlan` + content-addressed image + admitted flows                                                             |
| **Core primitive**           | Content-derived, signed, versioned, immutable asset identity       | Hardware-isolated microVM, no guest NIC, vsock-only I/O, chain-signed audit log                                                            |
| **Lifecycle scope**          | All 7 stages (data → deploy), plus serving/monitoring              | Build → attest → run. Explicitly _not_ training, sweeps, RLHF, model registry                                                              |
| **Trust mechanism**          | (Unspecified) registry + runtime policy engine + evidence          | Mechanical, hypervisor-enforced: dm-verity boot, seccomp, `no-new-privs`, default-deny egress with host-originated connections             |
| **Policy enforcement point** | "At runtime," in the control plane                                 | Admission (signed plan) + host-side egress gate + run-shaped agent-verb grants (ProdSafe vs DevOnly)                                       |
| **Evidence**                 | "Verifiable evidence" for security/compliance/business             | 15 numbered CI-enforced claims; chain-signed audit log; `mvmctl trust audit verify`; SCITT-compatible capsule design in flight             |
| **Secrets**                  | Not addressed publicly                                             | Claim 13: no raw secret crosses to the guest; destination/time-bound signed creds; PII/secret detect-and-replace on owned cleartext egress |
| **Compute-env identity**     | "Derived from measured state" — unspecified how measured           | dm-verity sealed images, hash-locked dep volumes, supervisor verification before launch — this _is_ a measured-environment identity        |
| **Deployment model**         | Customer's environment, all major clouds + on-prem + edge + hybrid | Local-first: macOS (HVF/libkrun) + Linux/KVM (Firecracker); builder VM; mvmd fleet; gateway backend for remote fleets                      |
| **Product form**             | Enterprise platform (early access, waitlist)                       | Open-source Rust workspace, `mvmctl` CLI, Python/TS/Rust SDKs, shipped release artifacts                                                   |
| **Maturity**                 | Pre-GA, seed, no public docs/code                                  | Shipped; security claims CI-enforced; BDD conformance suite; benchmarks                                                                    |
| **Business model**           | VC-backed SaaS/platform (enterprise trust budgets)                 | Open-source project (tinylabs); monetization TBD                                                                                           |
| **Buyer/user**               | Enterprise AI platform teams, CISO/compliance                      | Developers and platform engineers running untrusted/AI-agent workloads                                                                     |

---

## 3. Where the visions overlap

The shared belief is nearly word-for-word:

1. **Trust must be intrinsic, not a review process.** Them: "trust should not
   be another tool or another approval process." Us: security posture "enforced
   by CI, not by documentation," claims machine-checked.
2. **Cryptographic identity that follows the thing.** Their content-derived
   asset identity ≈ our content-addressed bundles (claim 9), hash-locked dep
   volumes (claim 11), and OCI provenance recorded in the audit chain (claim 14).
3. **Policy at runtime, not at review time.** Their headline capability ≈ our
   admission + default-deny egress + verb grants.
4. **Verifiable evidence for non-engineers.** They target business/security/
   compliance audiences; our audit chain + `trust audit verify` produces the
   same class of artifact, today aimed at operators.

**The honest read: we are building the bottom half of what the entrant
describes.** Their "identity for compute environments derived from measured
state" is precisely what a sealed, dm-verity-attested mvm image + verified dep
volume is. Their "policy enforcement at runtime" is what the host-originated
egress gate is. Their "verifiable evidence" is the chain-signed audit log /
SCITT receipts. They describe the whole trust chain for AI; we mechanically
implement the execution-environment third of it.

---

## 4. Where we differ fundamentally

1. **They anchor on ML assets; we anchor on execution.** Their identity graph
   is over datasets, weights, prompts, agents — lineage across training and
   deployment. mvm has no concept of a "model" as a lifecycle object; a model
   is just bytes in a mount or image. We say nothing about which checkpoint
   became which deployment across a sweeps pipeline.
2. **Their enforcement is platform-level; ours is hardware-level.** (Inferred)
   They enforce policy by sitting inside the ML tooling and runtime control
   plane — trust the control plane, and policy holds. mvm's guarantees survive
   a compromised workload process because the boundary is the hypervisor, not
   a policy hook: no NIC exists to bypass, the rootfs is verity-sealed, the
   guest agent has no `do_exec` in sealed builds.
3. **Trust direction.** They mostly answer "is this the approved asset, and can
   we prove its lineage?" (supply-side provenance). We mostly answer "what can
   this code reach, and what did it actually do?" (demand-side containment +
   behavioral evidence).
4. **Scope of lifecycle.** They cover data prep, training, alignment, eval,
   optimization, serving, monitoring. We cover build/attest/run. Training and
   eval orchestration are explicitly out of our scope.
5. **Maturity and distribution.** They're a funded pre-product enterprise
   platform; we're a shipped open-source engine with CI-enforced claims.

---

## 5. Threat-model implications (the sharpest divergence)

The entrant's model appears to trust the compute environment (they measure its
state, but the enforcement lives in the control plane running on that same
infrastructure). mvm's ADR-001 explicitly names a malicious host as out of
scope too — but our whole design removes the _workload's_ ability to act
outside the admitted plan regardless of workload compromise: even a
fully-compromised guest process cannot open a socket that doesn't exist, read a
secret the supervisor never sends, or spawn a program in a sealed image.

So the two address different adversaries:

- **Their adversary:** asset tampering, unapproved substitution, lineage gaps,
  compliance drift across a fleet of pipelines and clouds.
- **Our adversary:** the workload itself (prompt-injected agent, malicious
  dependency, arbitrary third-party code) trying to exfiltrate data or exceed
  its grant.

A production AI organization needs both, which is why these are more naturally
complementary than competitive — today.

---

## 6. Convergence scenarios to watch

**If the entrant moves down-stack** (likely — "compute environments from
measured state" begs for an isolation layer), they will need exactly what we
built: sealed images, measured boot, host-brokered egress, secret substitution.
Their options are: build it (expensive, slow, deep systems work), partner with
an open-source engine (mvm-shaped), or settle for weaker "measured state" via
agent-based telemetry (weak claim, enterprise buyers may not notice for a
while).

**If we move up-stack** (possible — SCITT capsules + asset registration are
already designed), we would grow from "trust in execution" toward "trust in the
model lifecycle," and start touching their space from below with stronger
mechanical guarantees but far less ML-tooling surface.

**Most likely near-term relationship:** no direct competition. Different
buyers, layers, and maturity. But our positioning language — "verifiable,"
"signed," "auditable," "trust" — collides with theirs in any enterprise
conversation, and they have a seasoned operator and $5.1M telling that story to
CIOs. If we ever sell into the same accounts, the pitch is: _they register and
prove the assets; we prove what actually ran, in what sealed environment,
reaching only what was admitted — and the evidence chains verify offline._

---

## 7. What we could adopt (and what to ignore)

Worth stealing:

- **"Registered by reference" framing.** Assets stay where they live; identity
  attaches. Our SCITT design already stores only digests — but the _phrasing_
  "identity follows the asset, by reference, wherever it already lives" is a
  better one-line description of content-addressed provenance than we currently
  use.
- **The two-line value split** ("enforce policy at runtime / create verifiable
  evidence") is a crisp way to compress our 15 claims for a non-specialist.
  Ours compresses to "the host originates every connection / every decision is
  signed and auditable."

Worth ignoring:

- Seven-stage lifecycle breadth. It's a pitch, not a product yet — and chasing
  it would pull us into ML tooling we have deliberately scoped out.
- "Compute environments from measured state" as a slogan without an isolation
  mechanism underneath it — if we ever integrate upward, our measured state is
  _stronger_ than theirs, and we should say so plainly.

---

## 8. Gap analysis → what mvm must cover (owner decision, 2026-09-02)

The asset-identity pitch — _every dataset, model, prompt, agent, policy, and
compute environment gets a content-derived address that follows it_ — is one
we match or beat per-primitive, but we have not assembled it into a stated
capability. Mapping their six asset classes onto what mvm can prove today:

| Asset class             | mvm coverage today                                                                                                   | Gap                                                                                                  |
| ----------------------- | -------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| **Compute environment** | Strong: verity-sealed image digest + kernel + hash-locked dep volume bound into the signed plan and audit chain      | None mechanically; needs to be _surfaced_ as a first-class "environment identity" object             |
| **Agent**               | Strong: workload = agent code; image content-address + plan signature is the agent's identity                        | Needs a named identity an external verifier can consume without reading mvm internals                |
| **Model**               | Weak: a model is bytes in a mount or volume; digests of mounts are not recorded in the plan/audit chain today        | Record content-derived digest of mounted/volume assets at plan-admission time                        |
| **Dataset**             | Weak: same as model                                                                                                  | Same                                                                                                 |
| **Prompt**              | None: prompts are runtime payloads over the input channel; not content-addressed                                     | Optional content-hash of declared prompt assets; at minimum don't claim it                           |
| **Policy**              | Partial: egress/network policy is a signed field of the ExecutionPlan; not separately content-addressed or versioned | Content-address the admitted policy projection (it is already deterministic — hash it and record it) |

Follow-up plan: `specs/plans/2026-09-02-content-addressed-asset-identity.md`
(author the asset-identity capability on top of existing plan/audit machinery;
no new trust roots — assemble, surface, and verify).
