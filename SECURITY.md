# Security Policy

mvm is security-critical infrastructure. We take vulnerability reports seriously and ask researchers to follow coordinated disclosure.

## Reporting a vulnerability

**Do not** open a public GitHub issue for a security vulnerability.

Report to: **security@tinylabs.com** (PGP key fingerprint published at <https://github.com/tinylabscom/mvm/security/advisories> when the GitHub advisory channel is enabled).

Please include:

- Affected mvm version(s) and platform(s) (macOS / Linux, arch, kernel version).
- Reproduction steps or proof-of-concept code.
- Your assessment of impact (confidentiality / integrity / availability) and the affected security claim (per [ADR-001 §"Security claims"](specs/adrs/001-microvm-security-posture.md)).
- Whether you've shared the finding with anyone else and on what timeline.

We acknowledge within **2 business days**.

## Our commitments

- **Acknowledgement:** within 2 business days.
- **Triage + severity assessment:** within 5 business days (CVSS v3.1 + impact-on-claims rubric).
- **Fix + advisory publication target** (under coordinated disclosure):
  - **Critical** (claim-breaking — see ADR-001's live claim list): 14 days.
  - **High** (mitigated by other layer but defense-in-depth weakened): 30 days.
  - **Medium / Low:** 90 days.
- **CVE assignment:** we request CVE IDs from the GitHub CNA or MITRE for any vulnerability rated Medium or higher.
- **Credit:** by default we credit the reporter in the advisory; reporters can request anonymity.

We will keep the reporter informed of progress at least weekly.

## Coordinated disclosure

The default disclosure window is **90 days** from acknowledgement to public advisory, or sooner if a fix is shipped earlier. We extend the window only with reporter agreement and a documented reason (e.g., a dependency CVE requires upstream coordination).

If we cannot meet a 90-day window, we will negotiate an extension before day 75 with a concrete fix-availability ETA.

## What's in scope

Security-relevant code:

- All four broker subprocesses (`mvm-broker`, `mvm-secrets-dispatcher`, `mvm-host-signer`, `mvm-audit-signer`) — see [Plan 104 §Hardening posture](specs/plans/104-host-services-broker.md#hardening-posture-layers-111).
- The per-VM supervisor (`crates/mvm-supervisor/`).
- The guest agent (`crates/mvm-guest/`).
- The CLI surface (`mvmctl`) including `mvmctl up`, `mvmctl run`, `mvmctl image pull`, `mvmctl deps`, `mvmctl audit`, `mvmctl host-key`, `mvmctl services`, `mvmctl doctor`.
- Audit chain integrity / verifier (`mvmctl audit verify`).
- The signed-`ExecutionPlan` admission ceremony (per [ADR-014](specs/adrs/014-signed-audited-execution-plans.md)).
- The OCI image runner (per [claim 10](specs/claims/claim-10-oci-image-provenance.md)).
- The app-deps audit pipeline (per [ADR-014](specs/adrs/014-signed-audited-execution-plans.md)).

## What's out of scope

- Vulnerabilities in upstream dependencies — please report those to the upstream project. We track their CVE surface per [ADR-020 §"Dependency CVE surface"](specs/adrs/020-host-services-broker.md#dependency-cve-surface) and will refresh our affected-version list per release. If an upstream CVE materially affects us, we coordinate with upstream and ship a doctor-refusal version of `mvmctl` once a fixed upstream is available.
- Physical attacks on the host (cold-boot DRAM, DMA via Thunderbolt/PCIe, chip-off, hardware tampering) — per ADR-001 these are out of scope; the trust model assumes the host owner controls physical access.
- Theoretical attacks without a reproducible exploit (we'll triage them but lower-priority).
- Best-practice suggestions without a vulnerability ("you should use X instead of Y") — please open a GitHub Discussion instead.

## How we ship fixes

1. **Patch developed on a private branch** (security advisory draft on GitHub if applicable; otherwise local).
2. **Patch reviewed** by at least two maintainers; for any patch touching the four broker subprocess crates or the audit-signer, the [CODEOWNERS](.github/CODEOWNERS) policy requires a second reviewer who didn't write the patch.
3. **Patch released** under a new mvm version on the standard release pipeline. The release artefacts go through the hardening lanes per [Plan 104 W9](specs/plans/104-host-services-broker.md) — cosign signature, Sigstore/Rekor transparency entry, in-toto attestation, per-binary reproducibility-double-build.
4. **Public advisory published** on GitHub Security Advisories simultaneously with or after the release tag, including:
   - Affected versions.
   - CVE ID (if assigned).
   - CVSS score.
   - Description of the issue, the security claim it touched, and what an attacker could have done.
   - Description of the fix.
   - Upgrade instructions.
   - Credits.
5. **Sigstore/Rekor log entry** for the patched binary is publicly searchable. The transparency log lets downstream users verify the fix was actually shipped, not just promised.

## Verifying a release

Every mvm release publishes:

- **Cosign signatures** for each binary (`mvm-supervisor`, `mvmctl`, `mvm-broker`, `mvm-secrets-dispatcher`, `mvm-host-signer`, `mvm-audit-signer`). Public key shipped in `mvm-release-public-keys.json` in the release tarball.
- **Sigstore / Rekor transparency log entry** per binary, queryable by `cosign tree --tag <release>`.
- **In-toto attestation** documenting the build provenance (steps + materials + products).
- **SLSA provenance** at build level.
- **SHA-256 + SHA-512 checksums** for each artefact, signed under the cosign key.

Verification command (will be added to a `tools/verify-release.sh` helper in Plan 104 W9):

```sh
cosign verify-blob --key mvm-release-public-keys.json \
                   --signature mvm-supervisor-<version>.sig \
                   mvm-supervisor-<version>
cosign tree --tag <version>          # confirm Rekor entry exists
# in-toto verification per https://in-toto.io/Specs/ instructions
```

## Hardening status by claim

Each of mvm's published security claims (currently 1–10; ADR-020 proposes two more on merge) is backed by a CI gate. The current claim → gate mapping is documented in [CLAUDE.md §"Security model"](CLAUDE.md#security-model) and per-claim files in [specs/claims/](specs/claims/).

A vulnerability that breaks a claim is **Critical** by definition.

## Acknowledgements

We thank the following researchers for responsible disclosures:

_(none yet — placeholder for future credits)_

## See also

- [ADR-001 — microvm security posture](specs/adrs/001-microvm-security-posture.md) — the master security claim list and threat model.
- [ADR-020 — host services broker](specs/adrs/020-host-services-broker.md) — the architecture of the broker subprocess set and the narrowed insider-threat clause.
- [Plan 104 — host services broker](specs/plans/104-host-services-broker.md) — the hardening implementation specifics (Layers 1–11).
- [threat model 02 — host services broker](specs/threat-models/02-host-services-broker.md) — STRIDE walk for the broker.
