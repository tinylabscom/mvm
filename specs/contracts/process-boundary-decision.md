# Process boundary decision (recommendation)

Backing: preview
Validation: none — a decision record; the spawn inventory in `process-spawn-inventory.md` is the enforced half.

Scope: the umbrella box "resolve the exact backend/process boundary against #4414 and the maintainer's stricter instruction". This is a recommendation under the coordinator's delegated authority, not a new owner approval of numeric profiles, activation or privileged execution.

## Decision

1. **Allowed host processes** are exactly: the explicitly selected VMM executable (Firecracker, QEMU) launched directly by typed code; the dedicated per-VM supervisors (`mvm-hvf-supervisor`, `mvm-libkrun-supervisor`); and the hostd role processes kept apart for parser/signer isolation (broker, host signer, audit signer, network endpoint). Each is a typed launch plan with a fixed program and argv built in code.
2. **Forbidden on any production path**: shells and interpreters (`bash -c`, `sh -c`, `setsid` wrappers), utility binaries (`sudo`, `find`, `stat`, `systemd-run`, `kill`, `nft`, `mkfs`), re-executing `mvmctl`, and password-manager CLIs. A narrow approval for a VMM or role process does not authorize any of these as a fallback.
3. **Signer and parser isolation stays.** Collapsing a role process into its caller to reduce a process count is rejected; the boundary is the control.
4. **No exception is silently kept.** Inventory rows whose class is shell script, `systemd-run / sudo`, `mvmctl self re-exec` or toolchain are the open conflicts with this decision: the Firecracker detach script and `sudo find` descriptor inventory, the `sudo kill` signal, the QEMU `mvmctl` bridge re-exec, and the secret-source helper adapter. Each is removed by typed native code (born-bounded resource placement, in-process bridge, in-process descriptor handling), not by documenting it.
5. **Library embedders** (`mvm-client`, `mvm-hostlib`, SDKs, Studio) must work with no `mvmctl` on `PATH`; `refuse_cli_spawn` and `check-no-cli-shellout` hold that line.

## Reasoning

The direct current-user Firecracker boundary recorded in ADR-001 removes the need for privilege-escalation helpers. A utility fallback would re-create an unaudited second launch path outside signed admission. Keeping the VMM and role processes preserves the isolation the claims rely on, while the inventory makes every remaining conflict visible and CI-checked.
