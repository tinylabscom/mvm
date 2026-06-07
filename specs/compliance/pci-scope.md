# PCI DSS — Scope Statement

**Status:** STUB. Filled out in Phase 9 of `specs/plans/60-mvm-libkrun-migration.md`.
**Last verified:** N/A (stub created 2026-05-07).
**Owner:** mvm + mvmd platform team.
**Scope:** the open-source `mvm` library + the hosted mvmd cloud (when launched).

## Default posture: out of scope

**mvm and mvmd do not handle cardholder data.** The default posture is PCI **scope reduction**:

- Customers who run mvm/mvmd are expected to delegate payment processing to an external PCI-compliant processor (Stripe, Adyen, Braintree, etc.) at their application layer.
- The microVMs run customer code, but cardholder data should never enter them. Customers who attempt to do so are subject to their own PCI compliance burden — mvm/mvmd does not assist or certify.
- This stance is publicly documented; customers cannot claim our compliance posture on their behalf.

## Opt-in `profile = "pci"` template (Phase 7b — not on default path)

For the rare customer who insists on processing PCI inside mvm, an opt-in template is available with stricter defaults:

- [ ] (TBD) Mandatory LUKS volume encryption
- [ ] (TBD) No shared infrastructure across tenants
- [ ] (TBD) Mandatory L7 egress proxy with cardholder-data DLP rules
- [ ] (TBD) Audit log retention ≥ 1 year
- [ ] (TBD) Mandatory quarterly ASV scans (operational; documented in `specs/runbooks/pci-asv.md`)
- [ ] (TBD) Mandatory annual penetration test (operational)

**We do not certify the PCI profile.** The template provides the substrate; the customer retains end-to-end PCI responsibility.

## Why we don't pursue PCI certification ourselves

- mvm is a microVM library; the PCI scope of certifying it would extend to the entire deployment, which we don't control in self-hosted scenarios.
- The hosted mvmd cloud may pursue certification at the platform layer (post-launch decision).
- PCI certification is operational, not technical: most controls are about audit, vendor management, and incident response — implementable but not what mvm is trying to be.

## PCI DSS 4.0 requirements vs. mvm capability (Phase 9 to fill)

### Requirement 1 — Network Security Controls
- [ ] (TBD) Default-deny egress (ADR-017)
- [ ] (TBD) L4/L7 proxy mediation (ADR-017)
- [ ] (TBD) Per-tenant network isolation

### Requirement 2 — Secure Configurations
- [ ] (TBD) Hardened defaults (W1-W6 from sprint 42)
- [ ] (TBD) `safe-agent-workload` template defaults

### Requirement 3 — Protect Stored Account Data
- [ ] (TBD) AES-256 LUKS volume encryption
- [ ] (TBD) AEAD snapshot encryption
- [ ] (TBD) PII redactor configurable for cardholder-data patterns (ADR-020)

### Requirement 4 — Protect Cardholder Data with Strong Cryptography
- [ ] (TBD) TLS 1.3 mandatory; rustls + iroh (ADR-027)

### Requirement 5 — Anti-Malware
- [ ] (TBD) Out of scope at the library level; deployment concern.

### Requirement 6 — Secure Software Development
- [ ] (TBD) ADR coverage; reproducibility; SBOM; cosign signatures

### Requirement 7 — Restrict Access (need-to-know)
- [ ] (TBD) Per-tenant policy bundles (mvm-policy crate)

### Requirement 8 — Identify Users and Authenticate Access
- [ ] (TBD) Attestation + identity keys (ADR-018)

### Requirement 9 — Restrict Physical Access
- [ ] (TBD) Out of scope at the library level.

### Requirement 10 — Log and Monitor
- [ ] (TBD) Audit chain (ADR-019)
- [ ] (TBD) Metrics catalog
- [ ] (TBD) Audit retention via `audit-remote-sink`

### Requirement 11 — Test Security
- [ ] (TBD) Continuous fuzzing
- [ ] (TBD) Reproducibility check

### Requirement 12 — Security Policy
- [ ] (TBD) `SECURITY.md` + disclosure policy
