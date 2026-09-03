# Security Policy

mvm is security-critical infrastructure. We take vulnerability reports seriously and ask researchers to follow coordinated disclosure.

## Reporting a vulnerability

**Do not** open a public GitHub issue for a security vulnerability.

Report to: **security@tinylabs.com** (PGP key fingerprint published at <https://github.com/tinylabscom/mvm/security/advisories> when the GitHub advisory channel is enabled).

Please include:

- Affected mvm version(s) and platform(s) (macOS / Linux, arch, kernel version).
- Reproduction steps or proof-of-concept code.
- Your assessment of impact (confidentiality / integrity / availability) and the affected security claim (per the claims ledger in [ADR-001](specs/adrs/001-microvm-security-posture.md)).
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

- The broker subprocess set (`mvm-broker`, `mvm-host-signer`, `mvm-audit-signer`) — see [ADR-020](specs/adrs/020-host-services-broker.md).
- The per-VM supervisors (`mvm-libkrun-supervisor`, `mvm-hvf-supervisor`) and the per-VM egress endpoint (`mvm-network-endpoint`), all under `crates/mvm-hostd/`.
- The guest agent (`crates/mvm-agentd/`).
- The CLI surface (`mvmctl`) including `mvmctl machine run`, `mvmctl run`, `mvmctl image pull`, `mvmctl deps`, `mvmctl trust`, `mvmctl secret`, `mvmctl doctor`.
- Audit chain integrity / verifier (`mvmctl trust audit verify`).
- The signed-`ExecutionPlan` admission ceremony (per [ADR-014](specs/adrs/014-signed-audited-execution-plans.md)).
- The OCI image runner (claim 14 of [ADR-001](specs/adrs/001-microvm-security-posture.md)'s claims ledger).
- The app-deps audit pipeline (per [ADR-014](specs/adrs/014-signed-audited-execution-plans.md)).

## What's out of scope

- Vulnerabilities in upstream dependencies — please report those to the upstream project. We track their CVE surface with `deny.toml` and the `deny` and `audit` CI jobs, which run on every pull request, and refresh our affected-version list per release. If an upstream CVE materially affects us, we coordinate with upstream and ship a doctor-refusal version of `mvmctl` once a fixed upstream is available.
- Physical attacks on the host (cold-boot DRAM, DMA via Thunderbolt/PCIe, chip-off, hardware tampering) — per ADR-001 these are out of scope; the trust model assumes the host owner controls physical access.
- Theoretical attacks without a reproducible exploit (we'll triage them but lower-priority).
- Best-practice suggestions without a vulnerability ("you should use X instead of Y") — please open a GitHub Discussion instead.

## How we ship fixes

1. **Patch developed on a private branch** (security advisory draft on GitHub if applicable; otherwise local).
2. **Patch reviewed** by at least two maintainers; for any patch touching the broker subprocess set or the audit-signer, a second reviewer who didn't write the patch is required.
3. **Patch released** under a new mvm version on the standard release pipeline: keyless cosign signature over every release blob, a Sigstore/Rekor inclusion proof carried in the signature bundle, a signed CycloneDX SBOM, and the reproducibility double-build lane.
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

- **Keyless cosign signatures** over every release blob — the `mvmctl` tarballs, the boot-image artefacts, the checksum manifests, and the SBOM. There is no long-lived public key: each artefact ships a `.bundle` beside it carrying the Fulcio short-lived certificate and the Rekor inclusion proof.
- **A Sigstore/Rekor inclusion proof** inside each bundle, so transparency-log membership is verified as part of signature verification rather than as a separate step.
- **A CycloneDX SBOM** (`sbom.cdx.json`), itself signed.
- **SHA-256 checksum manifests**, also signed.

Verify a downloaded artefact with:

```sh
cosign verify-blob \
  --bundle mvmctl-<target>.tar.gz.bundle \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp 'https://github.com/tinylabscom/mvm/.github/workflows/release.yml@refs/tags/.*' \
  mvmctl-<target>.tar.gz
```

Bundles use cosign's new bundle format, so verifying by hand needs cosign >= v2.4. `install.sh` and `mvmctl env update` run this automatically when `cosign` is on `PATH`. The full walkthrough is [Verifying a release](public/src/content/docs/guides/verify-release.md).

## Hardening status by claim

Each of mvm's published security claims is backed by a named witness — a test or a CI job. The claims ledger in [ADR-001](specs/adrs/001-microvm-security-posture.md) is the source of truth for the claim set, its witnesses, and each claim's status; `xtask check-claim-catalog` fails the build when a named witness stops existing. [CONFORMANCE.md](CONFORMANCE.md) is the generated view of the same register.

Claims carrying a `Preview` status are held to a weaker bar than the shipped ones and their limits are stated in the ledger. Read the status column before relying on a claim.

A vulnerability that breaks a claim is **Critical** by definition.

## Acknowledgements

We thank the following researchers for responsible disclosures:

_(none yet — placeholder for future credits)_

## See also

- [ADR-001 — microvm security posture](specs/adrs/001-microvm-security-posture.md) — the master security claim list and threat model.
- [ADR-020 — host services broker](specs/adrs/020-host-services-broker.md) — the architecture of the broker subprocess set, its trust gradient, and the narrowed insider-threat clause.
- [ADR-023 — secrets subsystem and egress substitution](specs/adrs/023-secrets-subsystem-egress-substitution.md) — why no raw secret value crosses the broker channel.
- [CONFORMANCE.md](CONFORMANCE.md) — the generated claim register with each claim's honesty level and witnesses.
