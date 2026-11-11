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
journal write. The journal persists unsigned receipt state in record version 2
with a destination-signed, domain-separated admission intent binding the
verified identity, canonical frame, and receipt state. The destination signs
the actual acceptance receipt only after both commits. Earlier private-handoff
version-1 records are refused, not silently reinterpreted. Recovery verifies
the intent, refuses a missing or divergent anchored prefix, and may reconcile
only an intact contiguous suffix written before an interrupted anchor commit.
Retained guest-reader controls are checked against the historical signed
Receive capability, enrollment, lease and guest ACK before recovery accepts
their delivery state. An exact ACK retry still needs current boot, session,
policy and expiry authorization; an old committed ACK is not a new grant.

`FileJournalAnchor` is a local development aid, **not** that independent
authority: restoring both the journal and its host-local anchor can hide
rollback. The journal's current raw key input also does not establish
persistent, versioned history-key custody or recover the separately encrypted
payload after the per-launch mailbox secret is erased. Until those providers
and the existing service's admission handoff are integrated and tested, local
journal writes must not be presented as `accepted_durable`. The trusted-host
profile can access plaintext; host-blind confidentiality requires a different
attested key-release and protected-memory architecture.

The intended trusted-host custody boundary is a separately retained, versioned
mailbox-history root under host key custody. Each record must bind its key ID
and tenant/domain/mailbox scope; reopening existing history must **load the
existing version**, never mint a replacement or fall back to the signing seed
or erased per-launch secret. Durable payloads also need an explicitly
recoverable recipient encryption key: persisting the current per-launch key
would silently negate its erasure guarantee. Rotation retains old versions
only until their anchored history is retired. An independently operated
checkpoint must atomically compare the anchored `(mailbox, cursor, head)` with
the expected prior value; an unavailable or divergent checkpoint refuses
durable acceptance. These custody and checkpoint providers are not wired yet.

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
