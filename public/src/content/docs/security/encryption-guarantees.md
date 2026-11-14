---
title: Encryption guarantees and limits
description: What mvm's mailbox, snapshot, volume, and checkpoint encryption protects.
---

Encryption protects different assets at different boundaries. The local host holds
keys and is part of the [trusted computing base](/security/threat-model/). None
of these paths protects plaintext from a compromised host, or provides Signal-style
end-to-end encryption or per-message post-compromise recovery. A code path in this
table is not, by itself, a claim that the corresponding product workflow ships.

| Surface | Protection and evidence | Key and plaintext lifecycle | Limit |
| --- | --- | --- | --- |
| Local guest mailbox | The host encrypts with AES-256-GCM, signs the inner message, and verifies the capability, identity, execution epoch, expiry, and replay identity before queueing ([seal/open](https://github.com/tinylabscom/mvm/blob/main/crates/mvm-core/src/mailbox.rs), [service](https://github.com/tinylabscom/mvm/blob/main/crates/mvm-hostd/src/mailbox_service.rs)). | Signing and authority keys derive from the host signer for a mailbox and epoch; encryption derives from a **separate host encryption root** and a random **per-launch secret** ([key custody](https://github.com/tinylabscom/mvm/blob/main/crates/mvm-hostd/src/mailbox_launch.rs), [launch](https://github.com/tinylabscom/mvm/blob/main/crates/mvm-hostd/src/mailbox_process.rs)). The guest sends plaintext to the host sealer; the host service queues plaintext. | **Host-to-host, not guest-to-guest.** The queue and replay set are process-local. A new launch secret prevents an old encrypted frame from opening after a restart; this is not a durable mailbox, persistent deduplication, or per-message forward secrecy ([restart witness](https://github.com/tinylabscom/mvm/blob/main/crates/mvm-hostd/src/mailbox_service.rs)). |
| VM instance snapshot | New captures encrypt memory and VM state in AES-256-GCM chunks, with bundle integrity checked separately ([format](https://github.com/tinylabscom/mvm/blob/main/crates/mvm-core/src/crypto/snapshot_encryption.rs), [capture/restore](https://github.com/tinylabscom/mvm/blob/main/crates/mvm-runtime/src/vm/instance_snapshot.rs)). | The host admits a snapshot key; restore decrypts into a private temporary staging directory. | Older plaintext snapshots can still be resumed without a key; with a key configured, plaintext restore needs an explicit compatibility override. Restore support depends on the backend. Retained snapshots need restorable key material. |
| Managed local volume | A locked volume is an authenticated ciphertext archive; its wrapped data key is bound to the ciphertext ([unlock](https://github.com/tinylabscom/mvm/blob/main/crates/mvm-client/src/volume/lifecycle.rs)). | Unlock materializes a plaintext attachment artifact only on verified encrypted host storage; host-backed volumes rely on their host filesystem or block device ([states](https://github.com/tinylabscom/mvm/blob/main/crates/mvm-client/src/volume/dto.rs)). | An unlocked volume has plaintext on the trusted host; a host-backed volume has no additional mvm encryption layer. |
| Protected checkpoint | Sealed objects use authenticated encryption with host- or tenant-domain keys; wrong-key and cross-domain restores are refused ([custody](https://github.com/tinylabscom/mvm/blob/main/crates/mvm-runtime/src/checkpoint/custody.rs), [wrong-key witness](https://github.com/tinylabscom/mvm/blob/main/crates/mvm-runtime/src/checkpoint/protected_tests.rs)). | The host derives domain wrapping and reference keys from the relevant custody root; restoration needs that root. | Encryption alone does not establish freshness or rollback resistance. A signed audit-chain anchor is a separate input to lineage verification ([anchor](https://github.com/tinylabscom/mvm/blob/main/crates/mvm-runtime/src/checkpoint/verify.rs)). |

## Mailbox restart boundary

The local queue and replay set are volatile. Within one service lifetime, sending
the same valid envelope twice is refused. A new launch mints a new encryption
secret, so even with the same mailbox ID and execution epoch, the old ciphertext
must be refused while a newly sealed frame is accepted. The
[socket-level restart test](https://github.com/tinylabscom/mvm/blob/main/crates/mvm-hostd/src/mailbox_service.rs)
checks both outcomes; it does not establish that an untrusted party can reach the
socket in a deployed configuration. Teardown **attempts** to overwrite, flush,
and unlink the secret; [cleanup errors are logged](https://github.com/tinylabscom/mvm/blob/main/crates/mvm-vmm/src/host/vm_helpers.rs),
not proof of erasure. Filesystem snapshots and copy-on-write media may retain
old blocks; this is **not** a verified physical wipe. A compromised live host
can still read plaintext. [Durable encrypted admission and deduplication](https://github.com/tinylabscom/mvm/issues/4630)
are separate work, and the [mailbox ADR](https://github.com/tinylabscom/mvm/blob/main/specs/adrs/057-mailbox-semantics-and-threat-model.md)
describes a target contract rather than proof that durable delivery ships.

## Why not import the Signal Protocol?

Signal's [Double Ratchet](https://signal.org/docs/specifications/doubleratchet/)
derives per-message keys and recovers after a later exchange introduces fresh
entropy. [Sesame](https://signal.org/docs/specifications/sesame/) handles
asynchronous session changes, lost state, and restores. The host-held mailbox
does not have two independently trusted endpoints, while snapshots and volumes
must retain recoverable keys. A ratchet would not turn these into end-to-end
encryption and could break restore without an accompanying session-state design.

Keep the existing AEAD and signature library primitives. If guest-to-guest
secrecy or protection of recorded messages after a later key compromise becomes
a requirement, specify authenticated peers, key establishment, session persistence
and rollback, key erasure, and versioned migration first. Then evaluate a
maintained Rust implementation such as [libsignal](https://github.com/signalapp/libsignal)
with cryptographic and dependency review rather than inventing a protocol.
The scope and evidence are tracked in [#5314](https://github.com/tinylabscom/mvm/issues/5314).
