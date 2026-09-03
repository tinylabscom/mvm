# mvm-core

`mvm-core` is the host-side foundation library for mvm. It supplies domain
types, identifiers, configuration paths, cryptographic helpers, policy
evaluation primitives, and runtime-neutral client contracts. It does not boot
VMs or present user commands.

## Who uses it

Nearly every host-side crate depends on `mvm-core`, including `mvm-net`,
`mvm-vmm`, `mvm-backends`, `mvm-runtime`, `mvm-build`, `mvm-agentd`,
`mvm-hostd`, `mvm-client`, `mvm-sdk`, `mvm-cli`, `mvm-observability`, and the
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
plans, and `mvm-observability` installs the process-global tracing layer.

## Main areas

| Area | Representative modules |
|---|---|
| Domain model | `domain`, `runtime_catalog`, `catalog`, `workload_address` |
| Configuration and identity | `config`, `naming`, `arch`, `platform` |
| Security | `crypto`, `at_rest`, `ingress_redaction`, `policy` |
| Lifecycle evidence | `checkpoint`, `snapshot_frame`, `health`, `action_state` |
| Host/guest services | `service`, `protocol`, `guest_netd`, `egress_broker` |
| Runtime abstraction | `build_env`, `client`, `util` test support |
| Observability data | `observability`, `span_timing`, `usage_capture` |

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
