---
claim: catalog
status: Shipped
gated_phrases: []
exempt_paths: []
---

# Conformance claim catalog

The machine-checked map from each numbered security claim (the narrative
lives in `CLAUDE.md` §"Security model" and `specs/adrs/002-microvm-security-posture.md`)
to the witnesses that ratify it. `xtask check-claim-catalog` parses the
table below on every PR and fails when a named witness no longer exists,
so the claim list cannot silently drift from the tree.

Witness tokens are typed:

- `fn:NAME` — a `fn NAME(` must exist under `crates/` (a test, or the impl
  symbol the claim exercises).
- `ci:NAME` — `NAME` must appear in some `.github/workflows/*` file (a job
  key or lane name).

The witnesses here are a representative anchor per claim, not the full
test list — enough that a rename or deletion trips the gate. Grounding
each witness in an *external* authority (vs. a self-referential check) is
tracked separately as a follow-up audit (see "deferred follow-ups").

| #  | Claim | Witnesses | Authority | Status |
|----|-------|-----------|-----------|--------|
| 1  | No host-fs access from a guest beyond explicit shares | fn:seccomp_allows_listed_denies_unlisted, ci:seccomp-functional, fn:validated_conversion_enforces_mount_allow_list, fn:dir_share_two_part_defaults_ro, fn:vz_rootfs_disk_is_read_only, fn:libkrun_refuses_read_only_virtiofs_share, fn:enforce_admitted_shares_refuses_unadmitted_or_mismatched | seccomp + setpriv (ADR-002 §W2) + user-volume allow-list / ro-default / admission-enforced shares (mvm-cli + mvm-backend) | Shipped |
| 2  | No guest binary can elevate to uid 0 | fn:set_no_new_privs, fn:virtiofs_mount_flags_keep_workspace_read_only | setpriv --no-new-privs + RO config binds (ADR-002 §W2.2) | Shipped |
| 3  | A tampered rootfs ext4 fails to boot | ci:verified-boot-artifacts | dm-verity + roothash (ADR-002 §W3) | Shipped |
| 4  | The guest agent has no do_exec in production builds | ci:prod-agent-runentry-contract | ELF symbol contract (ADR-002 §W4.3) | Shipped |
| 5  | Vsock framing + supervisor-config JSON are fuzzed | ci:fuzz | cargo-fuzz (ADR-002 §W4.1/W4.2) | Shipped |
| 6  | The pre-built dev image is hash-verified | ci:hash-verify-tests, fn:download_runtime_overlay_rejects_checksum_mismatch | SHA-256 manifest (ADR-002 §W5.1) | Shipped |
| 7  | Cargo deps are audited on every PR | ci:cargo-deny, ci:cargo-audit, ci:reproducibility | RUSTSEC + deny.toml (ADR-002 §W5.2/W5.3) | Shipped |
| 8  | Every workload runs from a signed, audited ExecutionPlan | fn:synthesize_plan, fn:admit_for_run, fn:verify_audit_chain | Ed25519 + chain-signed audit log (ADR-041) | Shipped |
| 9  | Every published bundle is content-addressed and re-verified | fn:read_and_verify_bundle, fn:verify_plan_bundle | SHA-256 content-addressing (Sprint 52 W2) | Shipped |
| 10 | No untrusted workload reaches the network unless policy-admitted | fn:policy_default_is_deny_all, fn:test_resolve_network_policy_default_is_deny_all | default-deny network policy (Sprint 52 W3) | Shipped |
| 11 | Every app-dep volume is hash-locked, CVE-scanned and SBOM-enumerated | ci:app-deps-audit, fn:verify_sealed_volume, fn:apply_install_gate | CycloneDX + pip-audit (ADR-047) | Shipped |
| 12 | Every host-side service binding is plan-gated and audited | fn:unbound_service_returns_not_bound, fn:service_call_rejects_unknown_envelope_fields | ExecutionPlan.services binding (ADR-059) | Shipped |
| 13 | No raw secret value crosses the broker channel | fn:resolved_secrets_placeholders, fn:substitute | destination-bound signed credentials (ADR-049) | Shipped |
| 14 | OCI image provenance is recorded in the chain-signed audit log | fn:prod_pull_requires_digest_pin_before_network, fn:prod_run_image_requires_digest_pin_before_network | cosign + OCI digest (specs/claims/claim-10-oci-image-provenance.md) | Shipped |
| 15 | No interactive access to a sealed production microVM | fn:console_refused_on_sealed_image, ci:prod-agent-no-console, fn:prod_console_attachment_has_no_input | dev-image-only console + dm-verity + host accessible-gate + dev-shell-gated agent (Plan 165 WS-C, ADR-002 §W4.3 extension) | Shipped |

## Maintaining this catalog

- Adding a claim: append a row with the next number (the gate enforces a
  contiguous `1..=N`) and at least one resolvable witness.
- Renaming a witnessed test/fn or CI lane: update the row in the same PR,
  or the gate goes red.
- The `Status` column accepts `Shipped` / `Preview` / `Planned` /
  `Not-claimed`, matching `check-no-overclaim`'s status vocabulary.

## Deferred follow-ups

- [ ] Audit each witness for *external-authority* grounding (assert against
  a reference implementation / oracle rather than the code's own output);
  record gaps in the Authority column. Becomes its own
  `specs/plans/<N>-claim-witness-authority-audit.md`.
- [ ] For any witness found to be self-referential, file a follow-up to add
  a reference oracle.
