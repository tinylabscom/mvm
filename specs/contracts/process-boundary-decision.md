# Process boundary decision

Backing: preview
Validation: none — a decision record; the spawn inventory in `process-spawn-inventory.md` is the enforced half.

Scope: the exact backend/process boundary for #4414, refined by the [owner-approved decision](https://github.com/tinylabscom/mvm/issues/4414#issuecomment-6587589521). This is not owner approval of numeric profiles, activation or privileged execution.

## Decision

1. **Selected workload and role processes** remain exactly: the explicitly selected VMM executable (Firecracker, QEMU) launched directly by typed code; the dedicated per-VM supervisors (`mvm-hvf-supervisor`, `mvm-libkrun-supervisor`); and the hostd role processes kept apart for parser/signer isolation (broker, host signer, audit signer, network endpoint). Each is a typed launch plan with a fixed program and argv built in code. No arbitrary public program/argv API is permitted.
2. **Always forbidden on production paths** are password- or sudo-based privilege escalation; shell command strings built from untrusted input; every workload launch outside signed admission (claims 8 and 10); and secrets in argv or the process environment (claim 13). No root password, `sudo -C`, sudoers edit or `visudo` setup may become a user requirement. The shell rule forbids shell interpretation of untrusted text, not all shell usage everywhere.
3. **Fixed programs with fixed, code-constructed argv are permitted**, including utilities such as `find`, `stat`, `kill`, `mkfs` and `nft`, when every invariant above holds and lifecycle is typed and owned. `systemd-run` is likewise permitted for born-bounded resource scopes (claim 18).
4. **Typed/in-process replacements are preferred on hot paths** for performance and simpler lifecycle ownership, not as a blanket security prohibition on executable names. Development, build, test and operator tooling are outside the production-runtime restriction.
5. **Signer and parser isolation stays.** Collapsing a role process into its caller merely to reduce a process count is rejected; the boundary is the control.
6. **No exception is silently kept.** Inventory rows are assessed against these invariants rather than by executable name. Existing conflicts remain open until each production path demonstrates signed admission, secret custody and typed, born-bounded lifecycle ownership where required.
7. **Library embedders** (`mvm-client`, `mvm-hostlib`, SDKs, Studio) must work with no `mvmctl` on `PATH`; `refuse_cli_spawn` and `check-no-cli-shellout` hold that line.

## Reasoning

The direct current-user Firecracker boundary recorded in ADR-001 removes the need for privilege-escalation helpers. A fixed-argv utility is not itself an unaudited second launch path; the violations are launching outside signed admission, interpreting untrusted text through a shell, exposing secrets, or losing typed and born-bounded lifecycle ownership. Keeping the VMM and role processes preserves the isolation the claims rely on, while the inventory makes every production process visible and CI-checked.
