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

The local file format binds each record to its `(tenant, name)`: `put` and
`get` seal and open with the AEAD associated data
`mvm-file-secret\0{tenant}\0{name}` (`record_aad`), so a record copied to
another tenant or name fails authentication with a clear error. The format has
no version byte and there is no migration; a record written before the binding
must be re-put. The key is still one per base directory, so the binding stops
relocation of a record, not a reader who holds the base key. A shared remote
provider needs more than this: the context rules below stay mandatory for it.

## Dependencies

The local providers add no remote or cloud dependency.

- `FileSecretStore`: `aes-gcm` (AEAD), `zeroize` and `rand`, all unconditional
  `mvm-core` dependencies.
- `KeyringSecretStore`: the `keyring` crate, optional in `mvm-core` and enabled
  only by the `os-keyring` feature, so the file provider and the guest closure
  do not carry it.

The associated-data change (#4928) touched only
`crates/mvm-core/src/crypto/secret_store.rs`: it passes existing arguments to
the AEAD calls and adds no crate to `Cargo.toml` or `Cargo.lock`.

## Consumers and test coverage

Production construction sites of `FileSecretStore`, and readers of the
`SecretStore` trait:

| Consumer | Use |
| --- | --- |
| `mvm-client::secret` | operator secret commands; builds the default store (`default_secret_store`) or an injected `Arc<dyn SecretStore>` |
| `mvm-client::entrypoint::foreground_diagnostic` | reads the default store |
| `mvm-hostd::supervisor::network_endpoint` | per-VM substitution endpoint; `FileSecretStore::with_dir` over the configured or default directory |
| `mvm-hostd::keyholder::resolver` | resolves a reference to a value through `Arc<dyn SecretStore>` |
| `mvm-hostd::jailer` | names the store key path (`file_store_key_path_for_base`) |

`KeyringSecretStore` has no caller outside `mvm-core`; it is reached only
through `default_secret_store`.

Tests in `mvm-core` (`crypto::secret_store::tests`, run with
`--features host-state`): the file provider is covered by
`file_put_get_round_trips`, `file_put_stores_ciphertext_not_plaintext`,
`file_get_rejects_tampered_ciphertext`,
`file_get_rejects_record_copied_to_another_name` (tenant and name relocation),
`file_get_rejects_legacy_plaintext_record`, `file_store_key_is_created_at_0600`,
`file_store_key_with_loose_permissions_is_refused`,
`file_put_overwrites_silently`, `file_get_returns_clear_error_when_missing`,
`file_delete_removes_entry`, `file_delete_errors_on_missing`,
`file_list_returns_sorted_names`, `file_list_returns_empty_for_unknown_tenant`,
`file_rejects_unsafe_tenant_id`, `file_rejects_unsafe_secret_name`,
`file_put_creates_tenant_dir_at_0700` and `file_put_creates_secret_at_0600`.
The keyring and selection path is covered by
`auto_store_reads_file_backed_secret_when_keyring_misses`,
`auto_store_lists_file_backed_secret_when_keyring_index_is_empty`,
`persistence_keyring_put_refuses_entry_local_storage`,
`persistence_auto_put_survives_store_recreation`,
`keyring_index_round_trips_through_save_load`,
`keyring_index_is_empty_when_missing`, `keyring_entry_validates_tenant_and_name`
and `default_secret_store_returns_some_impl`. The module's filtered run passed
20 tests; that is a count of this module, not of the consumers.

Consumers exercise the file provider through their own tests, which build
`FileSecretStore::with_dir` over a temporary directory: `mvm-client`
(`admission::secrets`, `admission::run_secrets`, `secret`, `launch`,
`checkpoint::fs_quick`), `mvm-cli` (`commands::ops::secret`,
`commands::vm::exec::application_source`), `mvm-hostd` (`keyholder::*`,
`supervisor::network_endpoint*`, `supervisor::flowmux`, `supervisor::terminator`,
and the `egress_secret_leak_gate`, `network_endpoint_bin` and
`wasm_egress_witness` integration tests) and `mvm-conformance`
(`steps/secrets_pii.rs`). These tests were not re-run for this document.

No remote or KMS provider exists, and nothing here claims one has been run
against AWS.

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
