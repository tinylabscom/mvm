# Plan 280 — Transcript root audit binding

**Status:** Complete.

## Goal

Make an encrypted forensic transcript authenticatable as one ordered evidence
set before any payload is decrypted. The sealed manifest gets a deterministic
content address over its capture binding, bounds, wrapped-key metadata, and
ordered ciphertext chunk records. The host chain-signs that address, and
`mvmctl trust audit transcript export` requires an exact anchor in a valid tenant
audit chain.

Plaintext and plaintext digests never enter the manifest root or audit chain.
Existing version-1 manifests have no trustworthy aggregate root and therefore
fail closed on export rather than being silently treated as authenticated.

## Work

- [x] Add manifest format version 2 with an RFC-6962 Merkle root over fixed,
      domain-separated metadata and ordered chunk-record leaves; verify the
      root before chunk reads or decryption, with a pinned deterministic vector
      and mutation/error coverage.
- [x] Queue `gateway.transcript_sealed` on the bridge's ordered audit channel
      after the sealed manifest reaches disk, carrying capture id, VM name,
      ciphertext-manifest root, and chunk count; chain-sign it through the
      existing per-VM signer.
- [x] Expose authenticated audit entries from the existing chain verifier and
      require exactly one tenant/capture anchor whose VM, root, and chunk count
      match the manifest before transcript export unwraps its data key.
- [x] Cover the operator path with hermetic BDD scenarios for successful
      anchored export and fail-closed manifest tampering; pass formatting,
      workspace tests, documentation tests, check, and clippy.
- [x] Production follow-up: make the operator `disarm` path load the VM's real
      persisted admitted plan and emit the host-signed seal itself. Refuse a
      missing or cross-tenant plan, and keep repeated disarms idempotent so
      export still sees exactly one anchor.

## Security acceptance

- The aggregate root commits to ciphertext digests, ordering, capture identity,
  tenant/VM/session binding, bounds, recipient, and wrapped data key.
- Changing a binding, reordering chunks, changing a chunk record, removing the
  root, corrupting the chain, omitting the anchor, or signing a different root
  refuses export.
- Transcript payload bytes and plaintext digests remain absent from the signed
  audit entry.
