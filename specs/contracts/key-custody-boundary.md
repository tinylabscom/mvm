# Key custody and opaque encrypted artifacts

Status: **Proposed for review; not approved or implemented by this document.**

Intent: [#4185](https://github.com/tinylabscom/mvm/issues/4185), within
[#4178](https://github.com/tinylabscom/mvm/issues/4178).
This proposal does not activate policy, migrate keys, promise a confidential
backend, or block the initial trusted-host persistence hardening.

## 1. Guarantees and trust boundaries

The current governing model is [ADR-001](../adrs/001-microvm-security-posture.md):
the host is trusted with execution and private data. Its hardware-backed
signer amendment does not make guest execution confidential from that host.
[ADR-008](../adrs/008-iroh-aware-encryption-layering.md) assigns encryption and
authentication to distinct boundaries; [ADR-031](../adrs/031-serialization-crypto-storage-selection.md)
retains focused in-tree primitives rather than replacing the crypto/storage
stack. This proposal preserves those decisions for trusted-host operation.

| Property | Trusted-host deployment | Proposed host-blind deployment |
| --- | --- | --- |
| At-rest payload protection | Encryption protects stored artifacts under the selected custody and lifecycle policy; the authorized host can decrypt. | Storage and host orchestration never receive payload plaintext or unwrapped data keys. |
| Execution | Host OS, hypervisor and authorized host services remain trusted. | Approved measured guest/enclave code and hardware isolation become the execution trust boundary; the host OS/hypervisor outside it are untrusted. |
| Key release | OS custody reduces accidental exposure and protects stored keys; authorized host processes still use plaintext keys/data. | A customer-controlled external authority releases keys only to a fresh, approved attested recipient. |
| Authenticity | Signatures, HMACs and chain/epoch checks establish their respective integrity and authorization properties. | Those checks remain necessary, but do not replace attestation or payload encryption. |
| Residual exposure | Host administration and compromise are outside the confidentiality guarantee. | Hardware/firmware vendors, attestation roots, approved guest software, the release authority and authorized recipients remain trusted. Denial of service, traffic analysis and unmitigated side channels are excluded. |

“Host-blind” means payload confidentiality from the untrusted execution host,
not anonymity, oblivious access, or protection from an authorized recipient.
Hardware attestation is evidence about a particular execution environment, not
a proof of application correctness. A signed plan, signed transcript root,
vsock connection, disk encryption or non-exportable signing key alone cannot
establish this guarantee. A compromised authorized guest can still disclose data.

## 2. Approaches considered and recommendation

1. **OS-backed custody only.** Lowest integration cost; fits local workflows
   and existing envelopes. Useful defense in depth for trusted-host operation,
   but the host can observe computation and invoke authorized key operations.
   It cannot satisfy host-blind execution, even with TPM-sealed keys.
2. **External KMS with ordinary guests.** Central policy, rotation and audit
   improve fleet custody. Network availability, identity management and
   request charges are added. Releasing keys to an ordinary host process or
   VM still trusts that host; putting only an unwrap service in an enclave
   while returning plaintext to the host does not fix this.
3. **Two explicit profiles sharing an opaque storage boundary.** Improve local
   OS custody in the trusted-host profile, and separately qualify an attested
   execution profile with external measurement-bound release. Higher
   engineering and operational cost, but the guarantee follows the actual
   plaintext boundary instead of a provider's marketing label.

**Recommend option 3 as the architectural direction**, with option 1 as the
first independently useful delivery. Evaluate a whole confidential guest
before a narrow enclave for general workloads: the workload, decryptor and
protected I/O endpoints must all fit inside the attested boundary. A narrow
enclave is credible for deliberately constrained processing, not a drop-in
replacement for every microVM workload.

Retain current AEAD, canonical serialization, envelope and signing primitives;
use platform custody adapters and vendor attestation verification libraries
behind narrow interfaces. Do not introduce a new secrets database, universal
crypto framework or bespoke attestation protocol. Dependency and backend
selection require a separate reviewed implementation design.

## 3. Local OS custody and no-silent-fallback policy

This is a proposed policy, not a description of all current provider selection.
Provisioning records one explicit provider, key identity/version, owner and
protection profile. Admission probes that provider's actual capabilities,
identity and accessibility in the service's execution context.

| Custody choice | Useful guarantee and constraints | Proposed use |
| --- | --- | --- |
| macOS Keychain | OS-mediated storage and access controls. Interactive user and unattended service access differ; a stored symmetric secret returned to an authorized process is not a non-exportable hardware key. [Apple Keychain](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web) | Preferred local macOS adapter after locked-keychain, service-identity and restart tests. No UI prompt in an unattended request path. |
| Linux Secret Service | D-Bus service with collections, locking and possible prompts; its API is not a promise that a daemon, unlocked collection or hardware root exists on a headless machine. [API](https://specifications.freedesktop.org/secret-service-spec/latest/description.html) | Desktop option only when explicitly provisioned and tested in the caller's session. |
| Linux TPM-backed custody | Trusted keys can seal to a trust source and PCR policy; boot updates, TPM replacement and recovery need enrollment policy. Kernel encrypted keys without a trusted root inherit the strength of their master user key. [Linux documentation](https://www.kernel.org/doc/html/latest/security/keys/trusted-encrypted.html) | Candidate for managed headless hosts; verify real hardware and approved boot policy. A software TPM controlled by the host is not an independent hostile-host trust root. |
| Apple Secure Enclave handle | Hardware availability includes Apple-silicon Macs and specified Intel Macs with T1/T2; device-bound operations have different APIs and portability from generic Keychain secret retrieval. [Apple Secure Enclave](https://support.apple.com/guide/security/secure-enclave-sec59b0b31ff/web) | Evaluate key wrapping/derivation separately from signer handles. Do not promise arbitrary existing symmetric keys or signing algorithms can be imported unchanged. |
| External KMS/HSM | Central custody, access policy and audit; introduces network, credentials, service and disaster-recovery dependencies. Ordinary release is still trusted-host. | Explicit fleet option, not an automatic escape route when local custody fails. |
| Restricted file or environment delivery | Compatibility/test transport, not equivalent OS or hardware custody; keys enter host memory. | Only an explicitly enrolled trusted-host compatibility profile, scoped to a deployment and visibly reported. No production discovery-by-fallback. |

Required behavior after approval:

- Missing key, locked store, permission denial, unavailable service, invalid
  attestation, unsupported provider or unsupported platform is a typed failure.
  Never try a weaker provider, create a replacement key under an existing key
  identity, write plaintext, or relabel an artifact as protected.
- First-time key creation is an explicit provision operation, distinct from
  opening existing data. Normal reads, restore and recovery cannot provision.
- A compatibility exception names the provider, deployment, artifact class,
  approver and expiry. It cannot override a host-blind request. Errors report
  stable reason codes, not secret values, raw provider responses or paths.
- Changing custody is an authorized migration: preserve artifact binding,
  atomically publish a new wrapped-key reference, retain old recovery access
  until verification completes, then retire it under retention policy.
  Downgrade is never implicit; boot and reconnect cannot renegotiate it away.
- Recovery and escrow remain under the customer's authority. Losing the only
  eligible key can make ciphertext unrecoverable. A recovery principal capable
  of reading data is part of the documented trust boundary, not a hidden bypass.

## 4. Opaque encrypted-artifact contract

The following names describe a proposed semantic boundary, not shipped Rust
types or an allocated wire version. Storage must be usable without a
`KeyProvider`, key bytes, a decrypt capability, or a plaintext staging path.

### Ownership and data shape

- **Custody authority:** owns wrapping-key handles, authorization, key versions,
  rotation/revocation and recipient-bound release. It does not become the
  artifact store.
- **Protected producer/consumer:** performs encryption/decryption and validates
  artifact bindings. In the trusted-host profile this is an authorized host
  service; in the host-blind profile it is inside the approved attested guest.
- **Artifact store:** receives immutable ciphertext, wrapped-key envelopes and
  a minimal public descriptor. It stores, transfers, inventories and deletes
  those objects without interpreting plaintext.
- **Public descriptor:** format/version, opaque artifact ID, ciphertext digest,
  ciphertext length, protection profile, codec/algorithm identifiers,
  wrapping-key reference/version, opaque authorization-domain reference,
  generation and commit state. Avoid customer names, prompts, filenames and
  plaintext content digests. Storage-visible references still leak linkage.
- **Protected manifest:** workload identity, logical names, plaintext hashes,
  component ordering, lineage, restore configuration and other sensitive
  metadata are encrypted. Bind its ciphertext root to the public descriptor.
  Expose only the minimum opaque dependency references needed for retention.

Use existing `WrappedKey` semantics rather than a second wrapping hierarchy:
[rewrap_dek](../../crates/mvm-core/src/crypto/key_rotation.rs#L104)
preserves the binding and versioned wrapping envelope. Its supported
algorithms remain explicit; this does not enable unsupported algorithms.
Transcript wrapped-data-key and sealed-manifest semantics and snapshot
integrity sidecars remain separate formats, not silently interchangeable ones.

The authenticated context must bind authorization domain, artifact ID/class,
format, profile, generation, workload/policy identity and component
position/count. A ciphertext digest only detects byte changes; it does not
prove tenant ownership, freshness or approved execution. Existing formats
that cannot authenticate this context require a reviewed versioned extension,
not an unauthenticated sidecar asserted to provide the new guarantee.

### Operations and failure semantics

| Operation | Input/output | Invariant |
| --- | --- | --- |
| Begin upload | Authorized opaque descriptor and idempotency token → upload handle | Authorization is independent of possession of a digest or key reference. Enforce sizes and supported versions before allocation. |
| Put ciphertext | Upload handle and bounded ciphertext parts → acknowledgements | Storage never requests plaintext for deduplication, compression, validation or repair. |
| Commit | Handle, complete descriptor, envelope and authenticated manifest → immutable artifact reference | Validate ciphertext length/digests and completeness; atomically publish all dependencies. A retry with different bytes is a conflict. |
| Get / replicate | Authorized artifact reference → exact ciphertext package | No decrypt or rewrap permission is required. The consumer authenticates the complete package before exposing plaintext or resuming execution. |
| List / stat | Authorized scope and cursor → public descriptors | No secret-bearing metadata, raw diagnostic text or cross-tenant existence oracle. |
| Rewrap | Authorized custody request plus old envelope and binding → replacement envelope | Runs at the custody boundary, never in storage. Replace the envelope with generation-checked commit; payload ciphertext need not change. |
| Delete / collect | Authorized reference and retention/dependency decision → durable tombstone | Partial uploads are reconciled; concurrent readers/children cannot silently lose dependencies. Deletion is not proof of physical erasure or removal from backups. |

Denied, unavailable, locked, unsupported, malformed, authentication failure,
stale generation and incomplete commit remain distinguishable bounded error
classes without disclosing sensitive content. No failure changes the profile.
Unauthenticated plaintext must never be streamed to a consumer; authenticated
chunking must also authenticate the whole component set to reject truncation,
reordering and mixing. Crash recovery resumes or removes ciphertext uploads,
not host-side plaintext reconstruction in the host-blind profile.

Rewrapping is not retroactive revocation: someone who retained an old DEK can
still read old ciphertext. Key compromise can require fresh DEKs and
reencryption; historical copies remain a separate retention/security question.
Freshness against a malicious store requires an external authoritative
generation/lineage anchor, not merely a counter stored beside the artifact.

### Fit with existing boundaries

The scoped source baseline is `origin/main` commit
`3e820b6f53d3a4bad3351b315b5a462c966c3983`; graph spans were checked against
that checkout where used. These are integration seams, not a security inventory:

- [KeyProvider](../../crates/mvm-core/src/crypto/keystore.rs#L53) returns
  secret-boxed data-key material. Keep this capability on the protected
  consumer side; do not inject it into opaque storage.
- [private_fs](../../crates/mvm-core/src/private_fs.rs#L119) supplies local
  restrictive directory permissions. Reuse it for trusted-host custody and
  lifecycle work; permissions are not protection against host administration.
- [Instance snapshot sealing](../../crates/mvm-runtime/src/vm/instance_snapshot.rs#L110)
  and [CheckpointStore](../../crates/mvm-runtime/src/checkpoint/mod.rs#L45)
  supply existing artifact/lifecycle seams. Capture, materialization and
  restore must enforce the selected profile, not just the object writer.
- [TranscriptCaptureSink](../../crates/mvm-hostd/src/supervisor/transcript_sink.rs#L22)
  and the [host signer boundary](../../crates/mvm-hostd/src/host_signer/mod.rs#L1)
  remain distinct: payload encryption and integrity signatures are not
  interchangeable custody capabilities.

## 5. Attested execution and external release

The host-blind profile requires all of the following before admission:

1. The guest creates an ephemeral recipient/channel key inside the protected
   boundary. Its attestation evidence binds that key and an external verifier's
   fresh challenge; a host-provided public key alone is insufficient.
2. The externally controlled verifier validates the vendor chain, evidence
   signature, freshness, debug state, minimum TCB/security version and
   revocation status. It checks approved measurements for the boot chain,
   runtime, workload and security-relevant configuration. Anything not directly
   measured must be authenticated and verified by measured code before use.
3. Customer policy authorizes the workload, artifact domain, operation,
   recipient and generation. The execution host cannot edit that policy,
   enrollment, measurement allowlist or recovery grant. Cloud IAM permission
   alone is not measurement-bound authorization.
4. Key release encrypts the DEK to the attested recipient or establishes an
   equivalent attestation-bound secure session. Host relays see ciphertext
   only. Requests bind the artifact/envelope context so evidence cannot be
   replayed across tenants or substituted onto another release.
5. The guest authenticates/decrypts internally, keeps keys out of shared
   buffers, swap and dumps, and emits only approved encrypted outputs. Release
   leases have bounded duration and operation scope. Revocation stops future
   release; it cannot recall plaintext or keys already consumed.
6. Update approval is explicit: overlapping old/new measurements have a bounded
   rollout window and minimum-version policy. Verifier failure, expired
   evidence, unknown measurement or unavailable revocation data fails closed.
   A bounded offline policy, if ever allowed, needs separate approval.

Do not run the existing host stack inside an outer confidential VM and claim
that every administrator of that VM is excluded. Any decrypting service inside
that VM is in its TCB. Nested KVM availability and support for the existing
microVM image/device model require evidence, not inference from “confidential
VM.” Debug access, support access and image-building authority belong in the
approval model.

## 6. End-to-end coverage

| Surface | Trusted-host requirement | Additional host-blind requirement |
| --- | --- | --- |
| Transport ingress and egress | Authenticated peers and explicit termination boundary per ADR-008. | End-to-end protected channel terminates inside the attested guest and at the authorized client/service. Host proxies relay ciphertext. Host TLS termination or credential substitution on protected data is incompatible unless moved into the approved boundary. Vsock alone is not confidential from the host. |
| Outputs, tools and exports | Authorized destinations and declared plaintext lifetime. | Encrypt before leaving the guest to the authorized recipient. Include stdout/stderr, streaming deltas, tool arguments/results and error bodies. A host-executed tool needing plaintext is refused or explicitly outside the host-blind workload profile. |
| Diagnostics and audit | Minimize capture, bound retention and access; align with #4184. | No host plaintext console, traces, crash/core dumps or support bundles. Encrypt sensitive diagnostics to an approved recipient; host-visible audit uses bounded codes and opaque references. Signing diagnostic content does not hide it. |
| Snapshots/checkpoints and volumes | Explicit protection, protected staging, cleanup and restore verification under #4179–#4183. | Memory, registers, device state, disks, manifests and guest keys stay encrypted outside the boundary. Do not reuse a host-plaintext snapshot API. Unsupported protected capture/restore is refused; disabling snapshots is a valid initial profile restriction. |
| Migration, resume and fork | Preserve identity, lineage, integrity and authorized key access. | Fresh destination attestation and recipient-bound release, authoritative generation/lease transfer and replay/fork policy. No plaintext migration relay or portable host KEK. Initially disable live migration and full-memory fork until vendor capability and end-to-end tests qualify them. Application-level encrypted checkpoint/restart is a separate capability. |
| Metadata | Classify paths, identifiers, hashes and retention information. | Encrypt semantic manifests and use opaque IDs. Lengths, timing, access patterns, network endpoints, routing references and resource usage remain visible unless separately mitigated. Padding/batching has cost; no oblivious-storage claim is made. |

External destinations necessarily join the data trust boundary when they
receive plaintext. A host-blind execution claim must name these recipients,
including observability and model/tool services, instead of ending at the VM.

## 7. Availability, compatibility and operating cost

Official sources below were consulted on **2026-10-09**. They establish vendor
capabilities, not verified MVM compatibility or a deployment reservation.
Recheck region, SKU, image, firmware and feature status before approving a
spike or production rollout.

| Candidate | Documented availability/capability | Compatibility and cost consequence |
| --- | --- | --- |
| Local macOS/Linux OS custody | Keychain, Secret Service and Linux trusted-key sources are linked in section 3. Secure Enclave presence is hardware-specific. | Low infrastructure cost, but enrollment, locked sessions, boot changes, backup and replacement remain operational work. Neither Keychain nor TPM custody makes ordinary HVF/KVM guests host-blind. |
| Google Cloud Confidential VM | [Supported configurations](https://cloud.google.com/confidential-computing/confidential-vm/docs/supported-configurations) lists SEV-SNP on N2D and TDX on selected machine families/zones and supported images. The matrix distinguishes SEV from SNP and TDX and their migration support. | SNP/TDX are candidates, not generic SEV equivalence. Current matrix does not offer live migration for SNP/TDX; qualify exact image/device support. Budget VM capacity, release/verifier service, storage/egress and startup/performance measurements. No rate or capacity guarantee. |
| Azure confidential VMs | [Overview](https://learn.microsoft.com/en-us/azure/confidential-computing/confidential-vm-overview) documents SNP/TDX guest attestation, selected VM series/regions and feature limitations including live migration. | Platform attestation/disk release does not automatically bind MVM workload policy. Qualify guest images and external workload-key release. Budget selected VM size, encrypted disks/VM guest-state storage and authority operations. |
| AWS Nitro Enclaves | [Overview](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave.html) documents Linux enclaves on supported Nitro instance types, no persistent storage/external networking, parent-only socket communication, all AWS Regions and no Outposts. [KMS integration](https://docs.aws.amazon.com/enclaves/latest/user/kms.html) supports attestation-measurement policy conditions. | Credible constrained-processing alternative, not an existing MVM backend. Parent proxy, enclave packaging and output encryption must be designed. Budget parent-instance resources and KMS/transport operations; stop/termination ends enclaves and hibernation is incompatible. |

Hardware memory protection does not automatically protect attached GPUs,
accelerators or shared devices; admit them only with separate attested path
qualification. Unqualified platforms and backends remain trusted-host only.
No Windows custody adapter or production confidential backend is selected here.

Operational costs include verifier/KMS availability and latency, certificate
and endorsement refresh, revocation monitoring, measurement approval on each
release, recovery ceremonies, restricted debugging, reduced placement choices,
loss of snapshot/migration optimizations, and additional ciphertext I/O. Record
measured boot/restore latency, p50/p95 release latency, throughput, storage
amplification and per-workload service charges in a later authorized spike.
No billable resources are required to approve this architecture proposal.

Existing artifacts remain readable only under their declared legacy profile.
Do not relabel them host-blind or infer protection from a filename. Migration
needs a versioned adapter, authenticated binding and restore proof before
retiring the old envelope/key. Retain existing signature/lineage verification;
separate ciphertext storage hashes from protected plaintext identities.
Cross-profile export requires explicit authorization and recipient selection.
The #4181 checkpoint-format work and #4184 diagnostic work keep ownership of
their implementations; this document does not change their formats or policies.

## 8. Staged acceptance gates

These are proposed tests and approval evidence, **not tests run by this PR**.
Passing a local mock suite cannot certify confidential hardware.

| Gate | Required evidence and decision rule |
| --- | --- |
| A — contract review, no resources | Maintainers approve the profiles, provider policy, artifact binding, exposed metadata and authority ownership. Map each artifact class and egress surface to one profile. Reject a profile with any unowned plaintext boundary. |
| B — offline semantic tests | Fake custody/storage implementations demonstrate that put/get/replicate/list/GC require no keys. Roundtrip existing supported envelopes; reject tenant substitution, wrong keys, tamper, truncation, reordered chunks, unsupported versions and profile downgrade. Inject locked/unavailable provider, interrupted upload/rewrap and stale commit. No plaintext fallback or partial publication is permitted. |
| C — explicitly authorized OS integration | Exercise real Keychain/Secret Service/TPM service identities, lock/logout/reboot, unavailable provider, boot update, key loss/recovery, rotation and custom roots. Pass only with the declared provider and explicit failure modes, never an environment/file fallback. |
| D — attestation protocol qualification | Use published vendor evidence fixtures and negative vectors for wrong measurement, stale challenge, debug mode, revoked TCB, swapped recipient/domain and unauthorized generation. Verifier outage must deny release. Pass only if release is recipient-bound and host requests cannot alter customer policy. |
| E — separately authorized hardware spike | On one selected supported configuration, demonstrate protected client ingress → measured workload → encrypted output, external key release and rejection of altered images. Inspect instrumented host interfaces for test plaintext/keys; pair that evidence with vendor guarantees and threat review, not a claim that inspection proves absence. Record capability compatibility and the cost/latency metrics above. |
| F — lifecycle and production approval | Exercise encrypted checkpoint/restart where supported, destination reattestation, rollback/fork rejection, diagnostics, recipient revocation, recovery and retention. Unsupported migration/snapshots must fail admission. Require independent security review, rollout/rollback procedures and explicit threat-model approval before advertising host-blind operation. |

Bound the first hardware spike to one provider, one CPU-only workload and no
live migration. If the selected guest/device stack cannot keep all plaintext
inside the boundary, stop that backend evaluation or narrow the product
profile explicitly; do not weaken the release policy to obtain compatibility.

## 9. Decisions requiring approval

1. **Profile and threat model:** approve two named protection profiles and the
   residual metadata/side-channel exclusions, or keep all operation
   trusted-host. A host-blind profile requires an explicit ADR-001 amendment.
2. **Custody defaults and exceptions:** approve macOS Keychain and explicitly
   enrolled Linux custody choices, the no-silent-fallback rule and who can
   authorize expiring compatibility exceptions. No default changes in this PR.
3. **Authority ownership and recovery:** name the customer-controlled verifier,
   KMS policy and recovery administrators; decide whether availability warrants
   any bounded offline release. Recommendation: no offline release initially.
4. **Compatibility envelope:** approve versioned authenticated context and the
   minimum public metadata; require migration/restore evidence before any old
   artifact or key is retired. This does not allocate a wire version.
5. **First confidential candidate and funding:** choose one whole-guest
   SNP/TDX evaluation or a deliberately narrow Nitro Enclave workload after
   comparing current SKU/image availability. Recommendation: CPU-only
   whole-guest evaluation first, with snapshots/live migration disabled until
   separately qualified. Hardware testing needs separate resource authorization.

Review acceptance of this proposal authorizes only the agreed design direction.
Implementation, resource use, production policy activation and any advertised
confidentiality guarantee each require their own evidence and approval.
