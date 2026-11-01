# Host secret store: provider seam and future KMS contract

Backing: preview
Validation: none — this contract defines required behavior for a future provider; it is not a claim that any remote provider exists.

Scope: [#4839](https://github.com/tinylabscom/mvm/issues/4839), host secret
storage. The issue owns status. [Key custody](key-custody-boundary.md) owns the
broader custody direction; this document narrows it to the tenant secret store.

## What exists

The seam is `mvm_core::crypto::secret_store::SecretStore`: `put`, `get`,
`delete` and `list` over `(tenant, name)`, with values carried as `SecretBox`.
Two local providers implement it.

- `FileSecretStore`: one AES-256-GCM record per secret at
  `<base>/<tenant>/<name>` (mode 0600, directories 0700), encrypted under a
  per-base 32-byte key file created once with mode 0600 and refused if the mode
  differs.
- `KeyringSecretStore` (`os-keyring` feature): OS keystore entry per secret,
  with a name index beside it.

Operator commands reach the store through `mvm-client`; the host-side
substitution endpoint in `mvm-hostd` is the only other reader. No provider shells out, and no provider receives a value
from the guest: workloads carry references, and the host-side endpoint resolves
a value only while preparing an admitted outbound request.

The local file format does not bind a record to its `(tenant, name)`: the AEAD
associated data is empty, so a record copied to another name under the same
store key decrypts there. That is acceptable for a single-host, single-key
store whose directory is already the trust boundary. It is not acceptable for a
shared remote provider, which is why the context rules below are mandatory.

## Provider obligations

A provider added behind `SecretStore` must satisfy all of these, and a
conformance test must exercise each against the provider before it is
selectable.

1. **Custody.** Plaintext exists only in host memory inside `SecretBox` and is
   never logged, returned in an error, written to a file the provider does not
   own, or sent to a guest.
2. **Semantics.** `put` replaces silently; `get` and `delete` of a missing entry
   fail; `list` returns sorted names for the tenant and never values; tenant and
   name pass `validate_shell_id` before any provider call.
3. **Isolation.** One tenant's operations cannot read, list or overwrite
   another's.
4. **Explicit selection.** The provider is chosen by configuration, never by
   falling back after another provider fails. A provider that is configured and
   unreachable returns a typed unavailable error. It does not read or write a
   weaker local store, and it does not create a replacement key under an
   existing key identity.

## KMS provider contract (not implemented)

A KMS provider protects the data key; it does not hold secret values.

- **Stored where.** Ciphertext records stay on the host in the existing
  per-secret layout. The KMS never receives the secret value. It wraps and
  unwraps a data key, either per store or per tenant.
- **Key identity.** Configuration names one key identity (a key ARN, not an
  alias) and its version. A record carries that identity so a rotation or a
  mismatch is detected at read, not guessed.
- **Context binding.** Every wrap and unwrap, and every record encryption,
  binds `(store id, tenant, name, key identity)` as authenticated context.
  A record moved to another name, tenant or key identity must fail to open.
- **Access policy.** The key policy grants the host's workload identity wrap and
  unwrap on that one key and nothing else. Granting a principal, choosing the
  identity mechanism and the credential source need reviewed scope before
  implementation; nothing in this contract chooses them.
- **Failure.** Unreachable, throttled, denied and key-disabled are distinct
  typed errors. None degrades to the file or keyring provider, and a failed
  unwrap never returns partial or cached-stale plaintext as success. A bounded
  in-memory data-key cache is permitted only with an explicit lifetime, and is
  zeroized on drop.
- **Configuration.** Provider kind, key identity and region come from host
  configuration read through `mvm-core::config`. Credentials come from the
  ambient host identity chain and are never stored in the secret store, in
  plan files or on a command line.
- **Audit.** Wrap, unwrap and refusal outcomes emit chain-signed entries naming
  tenant, secret name, key identity and result, never a value or a raw provider
  response.
- **Dependency.** The implementation lands only with a reviewed dependency
  decision. Until then no AWS SDK, Secrets Manager client or placeholder remote
  implementation is added to the tree.
