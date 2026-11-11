# mvm-core

`mvm-core` is the host-side foundation library for mvm. It supplies domain
types, identifiers, configuration paths, cryptographic helpers, policy
evaluation primitives, and runtime-neutral client contracts. It does not boot
VMs or present user commands.

## Who uses it

Nearly every host-side crate depends on `mvm-core`, including `mvm-net`,
`mvm-vmm`, `mvm-backends`, `mvm-runtime`, `mvm-build`, `mvm-agentd`,
`mvm-hostd`, `mvm-client`, `mvm-sdk`, `mvm-cli`, and the
root `mvmctl` facade. `xtask` also uses selected schemas for repository checks.

`mvm-core` itself depends on the smaller `mvm-contract` protocol layer and on
`mvm-http` only when the remote client feature is selected. Keeping VM drivers
and orchestration above this crate prevents dependency cycles and makes its
logic straightforward to unit test.

## How it works

The crate turns boundary inputs into validated domain types and centralizes
rules that all higher layers must interpret identically. Examples include:

- locating state through `MVM_HOME`-aware configuration helpers;
- validating names and deriving stable instance, TAP, and MAC identities;
- representing machines, templates, tenants, volumes, and runtime catalogs;
- signing, encrypting, redacting, and checking security-sensitive records;
- modeling snapshots, checkpoints, health, quotas, grants, and admission;
- defining shell/build environment traits without choosing an implementation;
- collecting metrics and span timing without installing a tracing subscriber.

Higher layers provide I/O and platform behavior. For example,
`mvm-runtime` implements lifecycle operations, `mvm-hostd` enforces admitted
plans, and `mvm-cli`'s observability module installs the process-global
tracing layer.

Modules used by only one workspace crate belong to that consumer rather than
this foundation crate. The remaining modules have overlapping consumers and do
not form independent dependency leaves. In particular, the pack implementation
is not an acyclic extraction seam: it uses core architecture, plan-key,
digest-shape, and image-verification code, while core image-set and trust/cache
modules consume pack types. Moving it alone would create a dependency cycle;
changing that boundary belongs with the broader `mvm-core`/`mvm-contract`
ownership decision.

## Main areas

| Area | Representative modules |
|---|---|
| Domain model | `domain`, `runtime_catalog`, `catalog`, `workload_address` |
| Configuration and identity | `config`, `naming`, `arch`, `platform` |
| Security | `crypto`, `policy`, `receipt`, `residency` |
| Lifecycle evidence | `checkpoint`, `snapshot_frame`, `health`, `image_lineage` |
| Host/guest services | `protocol`, `guest_netd`, `stream_client`, `substitution_wire` |
| Runtime abstraction | `build_env`, `client`, `util` test support |
| Observability data | `observability`, `span_timing`, `usage_capture` |

## Mailbox journal boundary

`mailbox::journal` stores bounded, authenticated records containing the
canonical encrypted mailbox frame and its deduplication identity. Its
`JournalAnchor` interface requires an independently trusted authority to read
the current `(cursor, head)` and atomically compare-and-advance it after a
journal write. The journal persists unsigned receipt state with a
destination-signed, domain-separated admission intent binding the verified
identity, canonical frame, and receipt state. The version-3 test path also
binds a `HistoryKeyRef` (mailbox address, epoch, AES-256-GCM key ID and nonzero
version) to the encrypted record and signed intent. Its recovery obtains the
exact key through an existing-only `HistoryKeyCustody` lookup and refuses
changed key identity, wrong key, or missing custody; it does not create a
replacement key. The raw-key opener cannot issue an `accepted_durable` receipt.
Constructing or deserializing a `HistoryKeyRef` does not grant authority: production reopening
must verify its scope against the admitted plan and an authenticated retained
manifest before loading a key.
The destination signs an actual acceptance receipt only after both commits.
Earlier private-handoff version-1 records are refused, not silently
reinterpreted. Version-2 test/local records have no custody reference and are
not silently promoted to version 3. Recovery verifies the intent, refuses a
missing or divergent anchored prefix, and may reconcile only an intact
contiguous suffix written before an interrupted anchor commit.
The original accepted receipt body and observation time are retained with
deduplication state; V1 retries still use their existing `duplicate` outcome.
The local opener and `admit_local` sign a distinct V2
`accepted_local_durable` receipt only after the encrypted record and local
anchor have been fsynced. An exact local retry re-verifies current admission
and the committed local tip before re-signing the original body/time, yielding
the same signed bytes after restart. Recovery refuses a local V2 receipt in an
independently anchored journal or a V1 strong receipt in a local journal.
The hostd service can bind that local journal to its existing endpoint, but
the production launch path still refuses until verified custody, retention,
and guest receipt handoff are integrated end to end.
`expire_next` records an authority-signed terminal expiry only after the
message's absolute deadline; a lost response can be reconstructed after
recovery. Expired messages are not disclosed, and an uncertain expiry write
cannot mint a terminal receipt. This does not yet implement an anchored
retention/compaction boundary: exhausted record or byte quotas still refuse
new work instead of deleting dedup history.
Retained guest-reader controls are checked against the historical signed
Receive capability, enrollment, lease and guest ACK before recovery accepts
their delivery state. An exact ACK retry still needs current boot, session,
policy and expiry authorization; an old committed ACK is not a new grant. A
message ever leased to a guest cannot be closed by the legacy unsigned host
ACK, including during recovery; it requires that guest's signed ACK.

`FileJournalAnchor` is a host-local anchor, **not** an independent
authority: restoring both the journal and its host-local anchor can hide
rollback. The hostd test-scoped custody prototype stores distinct retained
purpose keys under a signed restart binding, but it is not connected to the
production service. Until verified custody and the existing service's
admission handoff are integrated and tested, local
journal writes must not be presented as `accepted_durable`. The trusted-host
profile can access plaintext; host-blind confidentiality requires a different
attested key-release and protected-memory architecture.

The planned standalone `accepted_local_durable` tier has a distinct versioned
receipt contract and signer. Its history and payload-purpose keys belong in the existing
protected host keys directory, scoped to tenant/domain/mailbox/epoch and key
version, with an authority signer pinned for retained history. Recovery must
load the existing key version; it must not mint a new signer or use the erased
per-launch secret as its only opening key. Rotation and deletion need explicit
retention and refusal rules. A host-local chain can witness ordinary crash and
process restart, **not** rollback of the entire host. The local journal test
path is not production activation: its custody is synthetic, with no retained
key provider, authenticated restart manifest, or service adapter. The stronger
`accepted_durable` outcome continues to require a separately trusted
compare-and-advance checkpoint; no such provider is wired.

## Features

The default feature set is deliberately small. Notable opt-ins include
`client`, `client-remote`, `hostd-transport`, `manifest-verify`, `schema`,
`egress-ca`, platform attestation features, and `test-support`. Feature-gated
dependencies should stay out of the default closure unless every consumer
needs them.

## Developing

Run `cargo test -p mvm-core` for focused tests. Changes to serialized types need
round-trip and rejection tests; changes to path handling must cover `MVM_HOME`;
and changes to shared type shapes require the repository's gated-target check
because Linux-only consumers may not compile on macOS.
