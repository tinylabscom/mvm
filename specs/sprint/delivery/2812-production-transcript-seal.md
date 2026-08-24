# 2812 — production transcript seals reach the signed audit chain

`mvmctl trust audit transcript disarm` now anchors the sealed ciphertext
manifest in the tenant's chain-signed audit log. The command loads the admitted
plan persisted for the capture's VM, verifies that its tenant and workload
match the manifest binding, loads the host signer, and emits
`gateway.transcript_sealed` with the capture id, VM, root, and chunk count.

The path fails closed when the plan is absent, unreadable, or belongs to a
different tenant or workload. It validates the manifest root before signing,
and a repeated disarm recognizes the existing matching entry instead of
creating a duplicate that would make evidence export ambiguous.

Regression coverage drives `disarm` itself, verifies the resulting chain with
the trusted host public key, pins the exact transcript root, and exercises the
missing-plan, cross-tenant, and repeated-command paths.
