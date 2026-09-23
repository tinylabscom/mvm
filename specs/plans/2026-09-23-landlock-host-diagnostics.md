# Landlock host diagnostics

Backing: shipped-source
Validation: check-sprint-append

Issue: #3578

## Problem

The per-VM network endpoint correctly refuses to serve when Linux cannot fully
enforce its Landlock ruleset. On a kernel built without
`CONFIG_SECURITY_LANDLOCK`, however, the useful reason used to appear only in
the endpoint log after the operator had already entered a builder or workload
flow. An undocumented environment variable could also skip both Landlock and
seccomp entirely, which contradicted the endpoint's fail-closed contract.

## Decision

Keep confinement mandatory. Add a side-effect-free Landlock ABI query for
diagnostics, make `mvmctl doctor` report the exact Linux kernel/LSM blocker, and
turn a `NotEnforced` endpoint result into the same actionable capability error.
Delete the unconfined bypass rather than making it a supported product mode.

The diagnostic uses the kernel's version-query form of
`landlock_create_ruleset`: a null attribute, zero size, and the version flag.
It does not create a ruleset, set `no_new_privs`, or restrict the caller.

## Tasks

- [x] Classify ABI v2+, old ABI, disabled, unavailable, unexpected query
      failure, and non-Linux hosts without changing process state.
- [x] Add a failing `doctor` security check with actionable kernel and active
      LSM remediation, including JSON output.
- [x] Preserve fail-closed endpoint startup and surface `NotEnforced` as the
      actionable Landlock capability failure.
- [x] Remove the undocumented unconfined endpoint escape hatch.
- [x] Pass focused tests, exact workspace tests, all-target workspace Clippy,
      gated targets, formatting, and all repository policy gates.
- [ ] Deliver through the protected merge queue and close #3578.
