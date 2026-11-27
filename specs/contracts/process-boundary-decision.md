# Process boundary decision

Backing: preview
Validation: none — a decision record; the spawn inventory in `process-spawn-inventory.md` is the enforced half.

Scope: the exact backend/process boundary for #4414, refined by the [owner-approved decision](https://github.com/tinylabscom/mvm/issues/4414#issuecomment-6587589521) and amended by the owner's spawn policy of 2026-11-24, tracked in #4839. This is not owner approval of numeric profiles, activation or privileged execution.

## Spawn policy

The policy is not "no process creation". It is three rules:

1. **No shell strings.** Production code never starts `sh -c`, `bash -c` or any other shell with a command string, whoever wrote the text.
2. **No external tool that has a replacement.** A program is not started when the tree, the standard library or an existing dependency already does the job.
3. **One launcher.** Every remaining spawn goes through one typed launcher. The launcher pins the program to a resolved path rather than a `PATH` lookup, scrubs the environment, marks inherited descriptors close-on-exec except an explicit keep-list, and owns the session, bounds and resource scope of the child. A gate refuses process creation anywhere else.

Where the tree stands against it (see `process-spawn-inventory.md` for every site):

- Host spawns go through `helper_command` and `helper_command_with` in `mvm-core`'s `env_hygiene`, which scrub the environment and mark every descriptor from 3 up close-on-exec in the child (a site that hands a helper descriptors names all of them in one `env_hygiene::keep_fds` call), but do not pin the program. `xtask check-helper-env-hygiene` holds the raw constructors to its `RAW_SITES` list. Neither is yet the launcher of rule 3.
- Shell strings remain behind the host bash seams, the Firecracker launch, `mvmctl env uninstall` and the Firecracker idle reaper. The inventory lists them as open review, and its `OPEN_REVIEW_CEILING` keeps that list from growing.
- External tools with an in-tree replacement are being replaced site by site.

Each of these is a migration step tracked in #4839, not a property the tree already has.

## Decision

1. **Selected workload and role processes** remain exactly: the explicitly selected VMM executable (Firecracker, QEMU) launched directly by typed code; the dedicated per-VM supervisors (`mvm-hvf-supervisor`, `mvm-libkrun-supervisor`); and the hostd role processes kept apart for parser/signer isolation (broker, host signer, audit signer, network endpoint). Each is a typed launch plan with a fixed program and argv built in code. No arbitrary public program/argv API is permitted. Firecracker does not meet this yet: `launch_script` in `crates/mvm-vmm/src/fc/daemon.rs` writes a launch script and starts it through `sh`. Replacing it with a typed launch is a tracked migration step in #4839.
2. **Always forbidden on production paths** are password- or sudo-based privilege escalation; shell command strings (spawn policy rule 1); every workload launch outside signed admission (claims 8 and 10); and secrets in argv or the process environment (claim 13). No root password, `sudo -C`, sudoers edit or `visudo` setup may become a user requirement. Inside a guest, the workload health command and the DevOnly exec with environment still run through `/bin/sh`, and builder shell jobs still run a script under `/bin/sh`. Whether those are named exceptions or must become argv is an open owner decision on #4839.
3. **Fixed programs with fixed, code-constructed argv are permitted only without a replacement** (spawn policy rule 2) and only through the launcher (rule 3). Examples are `systemd-run` and `systemctl` for born-bounded resource scopes (claim 18), `cryptsetup`, `debugfs` and the selected VMM. A utility such as `kill`, `tar` or `mkfs.ext4` is replaced by the tree's own code wherever it has an equivalent.
4. **Typed/in-process replacements are required wherever they exist**, not only on hot paths, because each removed program is one less binary resolved at run time and one less lifecycle to own. Development, build and test tooling (`xtask`, `build.rs`, tests, the conformance harness) stays outside the production-runtime restriction.
5. **Signer and parser isolation stays.** Collapsing a role process into its caller merely to reduce a process count is rejected; the boundary is the control.
6. **No exception is silently kept.** Inventory rows are assessed against these invariants rather than by executable name. Existing conflicts remain open until each production path demonstrates signed admission, secret custody and typed, born-bounded lifecycle ownership where required.
7. **Library embedders** (`mvm-client`, `mvm-hostlib`, SDKs, Studio) must work with no `mvmctl` on `PATH`; `refuse_cli_spawn` and `check-no-cli-shellout` hold that line.

## Reasoning

The direct current-user Firecracker boundary recorded in ADR-001 removes the need for privilege-escalation helpers. Process creation is not itself the violation; the violations are launching outside signed admission, interpreting text through a shell, exposing secrets, or losing typed and born-bounded lifecycle ownership. A shell string is forbidden outright rather than only for untrusted text, because whether text is trusted is not visible at the call site and a shell can neither pin its programs nor own their lifecycle. An external tool with an in-tree replacement adds a run-time program lookup and a second lifecycle for no capability. One launcher puts program resolution, environment, descriptors and bounds in a single reviewed place. Keeping the VMM and role processes preserves the isolation the claims rely on, while the inventory makes every production process visible and CI-checked.

The per-site assessment required by decision 6 is the Disposition column and the reviewed-site table in `process-spawn-inventory.md`; what is still unassessed is listed there with its missing piece, and `OPEN_REVIEW_CEILING` in the generator keeps that list from growing.
