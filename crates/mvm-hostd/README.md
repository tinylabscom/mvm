# mvm-hostd

`mvm-hostd` contains mvm's trusted host-side daemon roles. It provides the
supervisor library plus separate broker, host-signer, audit-signer, host-agent,
network-endpoint, and hypervisor-supervisor binaries. Keeping key-holding roles
in separate processes limits which code can access each key or service.

## Who uses it

`mvm-runtime` launches and communicates with these roles. `mvm-cli` and the root
`mvmctl` package expose the user workflows that require them. `mvm-client` uses
host services through its local backend. `mvm-conformance` exercises daemon
protocols and security behavior.

## How it works: process model

| Role | Responsibility |
|---|---|
| Per-VM supervisor | Own admitted execution state, child processes, egress, and teardown |
| `mvm-broker` | Dispatch allow-listed guest host-service calls |
| `mvm-host-signer` | Hold the host identity key and mint authorized signatures/grants |
| `mvm-audit-signer` | Append and chain-sign audit events |
| `mvm-host-agent` | Serve host lifecycle/control requests |
| `mvm-network-endpoint` | Mediate admitted workload network traffic |
| HVF/libkrun supervisors | Isolate backend-specific VMM process lifetime |

Each role receives a bounded configuration envelope and inherited descriptors,
installs its confinement before processing untrusted data, and communicates
over typed framed IPC. The parent arms process/socket observation before
launch, verifies child identity and readiness, and persists durable evidence
for recovery. A crash is reconciled from state rather than inferred from a
best-effort notification.

## How requests are enforced

The supervisor admits an execution plan and binds it to workload/artifact
identity. Guest calls reach the broker over vsock, where the requested service
is checked against that plan. Secret substitution, tool access, egress,
signing, and audit emission each pass through their dedicated policy gate. Key
material remains inside the smallest role that needs it; callers receive only
the result.

## Main areas

| Area | Representative modules |
|---|---|
| Supervision | `supervisor`, `run`, `prelaunch`, `parent_death` |
| Admission | `plan_admission`, `admission_budget`, assurance modules |
| Host services | `broker`, `keyholder`, `extension_controller` |
| Signing/audit | `host_signer`, `audit_signer`, `audit` |
| Confinement | `jailer`, `panic_hook`, per-role setup |
| Output/lifecycle | `stream`, `exit_capture`, `session_resume` |
| Health and IPC | `health_probe`, `framing`, `host_agent_idle` |

## Features and platforms

The default build avoids optional platform integrations. Features enable
libkrun, custom DNS, eBPF telemetry, trusted APFS, wasm routing, HVF live
validation, and network performance tooling. Linux confinement and Firecracker
behavior are target-gated; HVF-specific supervisors are macOS-only.

## Developing

Run `cargo test -p mvm-hostd` for portable tests. Security changes require
valid, unauthorized, tampered, expired, replay, and size-limit cases. Linux
confinement and Firecracker tests run in the builder VM; explicitly scoped HVF
live tests run on macOS.
