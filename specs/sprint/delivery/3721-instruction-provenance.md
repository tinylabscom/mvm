# Provenance for agent instruction files

An agent reads `CLAUDE.md`, `AGENTS.md`, a `SKILL.md` or a rules file as
instructions, and nothing verified them. Every boot now checks the instruction
files it is about to copy into the guest against an operator trust policy, and
records each verdict in the chain-signed audit log under the plan the boot was
admitted with.

**Policy.** TOML, `deny_unknown_fields` at every level, schema generated from the
Rust types (`schema/instruction-trust-policy-v0.json`, drift-tested under
`--features schema`). Publishers are keyless (issuer + exact repository + exact
workflow + ref glob, matched against the certificate SAN) or keyed (inline
public key, or a `key_id` enrolled with `mvmctl trust add`); a digest blocklist
refuses a file whoever signed it; enforcement is `deny` (the default once a
policy exists), `warn`, or `audit`. The user policy is authoritative. A project
policy can only raise enforcement, add includes, add blocked digests, or narrow
the user's publishers to entries it repeats verbatim; alone it is advisory and
capped at `warn`. No policy at all records the built-in includes in `audit`
mode and refuses nothing.

**Signatures** sit beside each file: `<file>.sigstore.json` is the Sigstore
bundle `cosign sign-blob --new-bundle-format` writes, verified by the claim-20
in-process verifier (`image_verify` gained a signer-returning variant so a ref
*pattern* can be matched; the exact-identity path release verification uses is
unchanged); `<file>.mvmsig.json` is a domain-separated Ed25519 envelope for
local keys. Per-file rather than per-directory so a signature travels with its
file and an edit invalidates only that file.

**Admission** scans `--mount` sources, `--asset` trees and the local
`--flake`/`--manifest` directory before signing (a broken policy fails there),
then, once the plan exists, writes `trust.instruction_verified` /
`_unsigned` / `_blocked` per file and applies the mode. `deny` records
`plan.admission_refused` (stage `instruction_provenance`) and never records the
boot as admitted.

**CLI**: `mvmctl trust instructions init|sign|verify|policy`. `init` and `sign`
emit local audit events (`trust_instructions_init`, `trust_instructions_sign`).

**CI**: `sign-instructions.yml` keyless-signs this repository's instruction
files on a path-filtered push to `main` or dispatch, verifies the fresh bundles
with `mvmctl trust instructions verify` under a policy trusting exactly that
workflow and ref, and uploads them as an artifact — it holds no write access
and never commits. Other repositories should copy it, not call it: a reusable
workflow's certificate names the called file, so trusting it would trust every
caller. The `lint-features` lane now runs the provenance tests with
`manifest-verify` (a real Sigstore bundle: trusted ref verifies, untrusted ref
is a publisher mismatch, tampered bytes a bad signature) and `schema`.

**Open.** Volumes attached as block devices are not scanned, which includes a
persistent machine's `machine volume mount --host DIR`: a host edit reaches the
guest at the next start unverified, and a `--rw` private copy keeps in-guest
edits across restarts. `--mount` is a per-launch snapshot, read-only by default
and scanned at every admission. Status is Preview; no ADR-001 row was added.

**mvm-scout** already flagged override/exfiltration phrases in
AGENTS/CLAUDE/SKILL files (`SCOUT-PROMPT-001`); tinylabscom/mvm-assurance#202
unifies the instruction-file surface definition and adds `SCOUT-PROMPT-002` for
concealed, escalating and credential-seeking content.
