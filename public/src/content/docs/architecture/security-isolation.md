---
title: Security and isolation
description: Security-first architecture boundaries for mvm.
---

MVM's security posture is built from multiple layers rather than one control.

## Build boundary

Linux image construction goes through the builder VM. That keeps Nix evaluation, microVM image assembly, and Linux-only tooling out of the macOS host path.

## Launch boundary

Launches should pass through signed plan admission. A plan binds workload identity, artifact identity, resources, policy references, validity window, and nonce handling.

## Runtime boundary

Guest workloads run in microVMs. Control-plane operations should use the guest protocol and runtime supervisor instead of broad guest access.

## Policy boundary

Network, secrets, resources, and admission are policy-plane decisions. Examples should make those decisions visible.

## Audit boundary

Every high-value action should produce evidence: build, admission, launch, secret grant, network policy decision, snapshot, restore, and destroy.

## Environment hygiene

One filter, `mvm_core::env_hygiene`, keeps out environment variables that change what a process loads or runs before its own code starts:

| Family | Variables |
| --- | --- |
| loader | `LD_*`, `DYLD_*` |
| shell | `BASH_ENV`, `ENV`, `BASH_FUNC_*` (including exported functions such as `BASH_FUNC_name%%`), `PROMPT_COMMAND`, `IFS`, `CDPATH`, `GLOBIGNORE`, `SHELLOPTS`, `PS4` |
| interpreter | `PYTHONSTARTUP`, `PYTHONPATH`, `PYTHONHOME`, `NODE_OPTIONS`, `NODE_PATH`, `PERL5*`, `PERLLIB`, `RUBY*`, `GEM_*`, `JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS`, `JDK_JAVA_OPTIONS`, `DOTNET_STARTUP_HOOKS`, `GOFLAGS` |
| password-manager session | `OP_SERVICE_ACCOUNT_TOKEN`, `OP_CONNECT_*`, `OP_SESSION_*`, `BW_SESSION` |

Names match case-sensitively, as the loader and shells read them.

The filter applies at two seams:

- **Environment you hand a guest.** `mvmctl run --env`, `mvmctl machine run --env`, a `--launch-plan` document's env, and `mvmctl machine proc start --env` refuse a denied variable before anything boots or starts. The refusal names the variable and its family and never echoes the value. Re-admit one variable with `--allow-env NAME`. The name must be exact: a pattern such as `LD_*` or a bare family prefix such as `LD_` is refused. The host library's `guest.proc.start` applies the same filter and has no re-admission.
- **Host processes.** Every process `mvmctl` or a host daemon starts is built so that it does not inherit a denied variable from your shell. This covers the per-VM supervisors, the network and GPU endpoints, the broker and signers, the builder VM and its egress endpoint, the shells that launch Firecracker, the host build shell, helper contract probes, health-triggered restarts, and every tool `mvmctl` runs on the host: `cargo` and the rest of the toolchain, `nft`, `tar`, `codesign`, `cryptsetup`, `curl`, `git`, your editor, and the command `mvmctl seccomp-audit` traces. These variables are removed silently, and each removed name is logged at debug level. Two launches keep one variable each by exact name: a password-manager CLI keeps its own session token, and the interpreter running your script for `mvmctl run` or record mode keeps `PYTHONPATH` and `NODE_PATH`, so its imports still resolve. `PYTHONSTARTUP`, `NODE_OPTIONS` and the rest are still removed.

  The `check-helper-env-hygiene` gate scans every crate for raw process creation: a `Command::new`, or a direct `fork` or `exec`. Each one must be on a list that records where it runs: inside a guest, inside the builder VM, or inside the filter itself. Each list entry records the file, the enclosing function and the program, and says why the process may stay raw. If someone replaces a listed program with another in the same function, the gate treats it as a new site and fails.

An image's own declared `Env` is part of the workload, so the filter does not apply to it. The same holds for the placeholder names of substituted secrets, whose values are host-minted placeholders rather than caller content. A process inside the guest can still set any variable for its own children. The filter stops accidental or inherited passthrough; the microVM remains the isolation boundary.

## Host-executed SDK code

Runtime SDK record/live scripts execute host-side SDK code. Static decorator compilation is the safer authoring path when you need to inspect declarations without importing user modules.

## Related pages

- [Policy profiles](/guides/policy-profiles/)
- [Audit and receipts](/guides/audit-and-receipts/)
- [Threat model](/security/threat-model/)
- [Security claim ledger](/security/claim-ledger/)
