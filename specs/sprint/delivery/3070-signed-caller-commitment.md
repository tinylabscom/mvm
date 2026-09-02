# A caller can bind its own commitment to an admitted execution

Issue #3070 needed a verifier-controlled value that survives as part of the
execution MVM actually signs and audits. Free-form audit labels were the wrong
contract: they are operational metadata, untyped, and can collide with
event-specific fields.

The shipped-source change introduces `CallerCommitment`, an opaque 32-byte
value with one canonical 64-character lowercase-hex wire representation. The
optional value is included in `ExecutionPlan`, its content address and host
signature, then copied as a typed field into every plan-derived chain-signed
audit entry. Absence is omitted from serialization so historical plan and
audit bytes remain unchanged.

`mvmctl run` and `mvmctl machine run` accept `--caller-commitment HEX`. The
value flows through plan-mode, transient admission, entrypoint calls, and
persistent machine specs so a later start cannot silently lose it. MVM
validates the representation but deliberately assigns the bytes no hash
algorithm or business meaning.

Validation completed on 2026-09-01:

- strict parsing, serde, plan-signature/content-ID, audit-signature tamper, CLI,
  admission, persistence, and frozen-wire compatibility regressions pass;
- `cargo test --workspace`, `cargo check --workspace`, formatting, and
  zero-warning workspace Clippy pass;
- Linux all-target and feature-gated BDD compilation passes through
  `just check-gated`;
- the non-live BDD suite passes 243 scenarios (242 executed successfully and
  one existing unsupported Docker block-attachment scenario skipped), including
  an end-to-end caller-commitment audit-chain verification scenario.

Landed through the merge queue in PR #3076 as `8623950746` on 2026-09-01;
issue #3070 closed from the landed evidence.
