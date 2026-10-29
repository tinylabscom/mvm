# ADR-009: Cross-platform strategy — current native hosts and future Windows support

## Status

Accepted. The permanent exclusion of native Windows execution is superseded by
the future libkrun/WHP direction in [#3553](https://github.com/tinylabscom/mvm/issues/3553)
and the owner's protected backend goals in
[#4839](https://github.com/tinylabscom/mvm/issues/4839).
This does not promote Windows to a supported or witnessed execution tier.

## Context

mvm's current native execution hosts are Linux and macOS. Native Windows
execution is a future goal through libkrun's Windows Hypervisor Platform
support, not a new in-house WHP supervisor or userspace device stack.

Non-CLI consumers use `mvm-client` library APIs. A frontend must not compensate
for a missing platform capability by launching `mvmctl`, changing backend tier
silently, or presenting remote execution as local execution.

## Decision

### Current support and capability reporting

Preserve the Linux/macOS backend contracts and admission-visible capability
tiers. A compiled package, mock test, or another operating system's boot does
not establish a supported Windows tier. Library and doctor capability reports
must distinguish unavailable, preview, and supported behavior.

Studio's local/remote scope is governed by its own current ADRs. This ADR does
not require a legacy fleet sidecar or make a working Windows Studio release a
substitute for native Windows VM execution evidence.

### Windows promotion gate

The first planned Windows path is the existing libkrun backend on x86_64/WHP.
Before promotion, the owning issue requires:

- a qualified Windows host and an archived end-to-end boot witness;
- correct private-state ACLs and preservation of admission, audit, secret
  custody, and the canonical guest/host transport contract;
- named refusal on hosts without usable WHP or on unsupported architectures,
  without a silent backend fallback;
- platform documentation and doctor capability output that agree;
- a recorded Windows artifact signing/integrity posture.

Compile-only or informational CI remains compile evidence, not a lifecycle or
security witness. Future backends may satisfy the same platform and `VmBackend`
contracts; this decision does not require implementing them speculatively.

## Consequences

Cleanup must preserve the future Windows direction without claiming it is
already delivered. No new WHP driver, GPU promise, compatibility shim, or
platform-tier bypass follows from this ADR. Linux/macOS validation and existing
security boundaries remain required while the Windows evidence is outstanding.
