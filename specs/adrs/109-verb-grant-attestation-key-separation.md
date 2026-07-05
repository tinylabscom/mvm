# ADR-109: Attested launch anchor for real verb-grant key separation

- Status: Proposed (scope-expansion proposal — needs maintainer decision + an ADR-002 threat-model update before any implementation)
- Date: 2026-07-05
- Owner: MVM Project
- Related: ADR-108 (verb-grant measured trust policy — the honest ceiling this proposes to lift + the `grant_key_source: Attested` seam), ADR-002 (microVM security posture — currently lists hardware-backed key attestation / TPM / SEV out of scope for v1), ADR-041 (signed audited execution plans — claim 8), ADR-001 (Firecracker-only execution)
- Tracks: #1458

## Context

ADR-108 established, and this ADR does not re-litigate, that **real cryptographic
key separation for the verb grant is not achievable within ADR-002's current
scope**. The delivered mechanism is honest *trusted-channel provisioning*: the
guest verifies the grant against a key the trusted launcher provides, over a
channel the launcher controls. Every in-scope anchor (kernel cmdline, config
drive, even the dm-verity roothash) is launcher-provisioned, and the per-host
runtime host-signer key cannot be baked into a build-time-generic verity image.
The verb-grant story therefore deliberately stays **off** the numbered claim
ledger.

ADR-108 left a churn-free forward hook: `VerbTrustPolicy.grant_key_source` has an
`Attested` arm (defined, treated fail-closed, unimplemented), and `trust_decision`
already routes it. This ADR asks the real question that hook defers: **what would
it take to give the guest an anchor for the grant's verifying key that the
launcher — or a malicious host — cannot forge**, so the verb-grant story could
be promoted to a numbered claim?

## The requirement

Real key separation needs a trust root the guest can verify that is **independent
of the entity that provisions the grant**. In the trusted-host model that entity
is the host; against a *malicious* host it is still the host. So the requirement
splits by adversary:

- **Against a trusted-but-buggy launch path** (defense-in-depth, in-scope today):
  an anchor computed by something other than the launch code — e.g. a
  measurement device — so a launch bug that mis-provisions the grant is caught.
- **Against a malicious host** (currently out of scope): an anchor rooted in
  **hardware the host cannot impersonate** — i.e. a CPU that signs an attestation
  over the launch measurement with a key the host does not hold.

Only the second yields *real* key separation. The first is a strictly weaker
"measured, but still host-rooted" improvement.

## The hard constraint: the workload VMM has no attestation surface

**Firecracker — the workload VMM on Linux (ADR-001) — is deliberately minimal:
no vTPM device, no measured-boot/PCR surface, no attestation report.** So the
classic "guest reads a TPM quote" pattern is unavailable on the primary
workload backend. Any attestation story therefore also implies a **VMM change**,
not just a guest/host protocol addition. This is the crux that makes attestation
a multi-quarter initiative rather than an incremental follow-up.

## Options considered

1. **Host-emulated vTPM under a vTPM-capable VMM** (QEMU / Cloud Hypervisor +
   `swtpm`). The guest measures its boot into PCRs and the vTPM signs a quote.
   *But* the vTPM is emulated by the (trusted) host process, and its
   attestation key is host-held — so a **malicious host can forge the quote**.
   Gives a *standard attestation shape* and independence from a *buggy launcher*
   (the measurement is computed by the vTPM, not the launch code), but **not**
   real separation against a malicious host. Requires abandoning/augmenting
   Firecracker for workloads. Medium-heavy; modest security gain over ADR-108's
   launcher-gated enforcement.

2. **Confidential computing — SEV-SNP / TDX** (hardware memory encryption +
   remote attestation). The **CPU**, not the host, signs an attestation report
   over the launch measurement with a vendor-rooted key the host does not hold.
   This is the **only option that achieves real key separation against a
   malicious host** — the guest (or a relying party) verifies the report against
   the CPU vendor's root, binds the grant's verifying key to the attested
   measurement, and flips `grant_key_source: attested`. Requires: SEV-SNP/TDX
   hardware, a CC-capable VMM (QEMU / Cloud Hypervisor — **not** Firecracker), an
   attestation-verification service, and a threat-model change (a malicious host
   moves partly in-scope). Heaviest; the genuine answer.

3. **Per-install build-time anchor** (non-hardware, partial). At `mvmctl init`
   provision a per-install trust anchor and bake its public half into images
   built for that install; sign grants under a key certified by it. Independent
   of the *per-launch* code path, so it catches a buggy launcher, but the anchor
   is still host-generated and host-held — **no** defense against a malicious
   host, and it complicates the image-build determinism invariant. Marginal.

4. **Do nothing more; keep trusted-channel provisioning.** ADR-108's
   launcher-gated enforcement (Stage A) already gives defense-in-depth against a
   buggy launcher without any of the above cost. Against a malicious host,
   nothing short of option 2 helps, and a malicious host is out of scope. This is
   the honest status quo.

## Recommendation

**Do not pursue attestation as a near-term follow-up.** The only option that
delivers what #1458 asks for (real key separation) is **option 2 (confidential
computing)**, and it is gated on decisions far larger than the verb grant: a
confidential-computing workload backend, SEV-SNP/TDX hardware, an
attestation-verification service, and an ADR-002 threat-model expansion that
brings a malicious host partly in-scope. Options 1 and 3 add real cost for a gain
that does not exceed ADR-108's already-shipped launcher-gated enforcement in the
trusted-host model.

Concretely:

1. **Keep the `grant_key_source: Attested` seam as-is** (defined, fail-closed,
   unimplemented). No code change now.
2. **Gate any attestation work on a prior, standalone decision to adopt a
   confidential-computing workload backend.** That decision — not the verb grant
   — is the real fork; the verb-grant binding is a small consumer of it.
3. **Do not promote the verb-grant story to a numbered claim** until an anchor
   with genuine host-independence exists (option 2). Trusted-channel provisioning
   must not be described as key separation in the claim ledger.
4. If a CC backend is later adopted, a *follow-on* ADR designs the concrete
   binding: attestation-report verification, measurement→`pubkey` binding, the
   guest/relying-party verification point, and the `attested` policy semantics.

## Promotion criteria (what a numbered claim would require)

A future "verb grant is bound to an attested launch measurement" claim is
justifiable only when **all** hold, each with a machine-checked witness:

- The grant's verifying key is bound to a launch measurement attested by a root
  the host cannot forge (CPU vendor root, not a host-held key).
- The guest (or a relying party) rejects a grant whose key does not match the
  attested measurement — negative-path tested (forged report, wrong measurement,
  replay).
- The attestation-verification path is fuzzed / adversarially tested, consistent
  with the existing claim-catalog discipline (`specs/claims/catalog.md`).

Until then this stays a `Preview`-style note at most, never a numbered claim.

## Consequences

- **Positive:** the "future attestation" hand-wave becomes a concrete,
  honestly-scoped roadmap with the hard constraints named (Firecracker has no
  attestation surface; real independence needs confidential computing). Prevents
  building options 1/3 as security theater.
- **Negative / accepted:** no key separation is delivered now. #1458 is
  effectively answered "yes, but only via confidential computing, which is a
  separate large initiative" — this ADR records that answer rather than shipping
  a partial mechanism.
- **Neutral:** ADR-108's launcher-gated enforcement remains the current best
  in-scope posture and is unaffected.

## Out of scope (for this ADR)

- Selecting or building a confidential-computing workload backend (its own ADR).
- Any code change — this ADR is a direction/decision record, not an
  implementation plan.
- The malicious-host threat model itself, which ADR-002 would need to revise
  before option 2 could be claimed.
