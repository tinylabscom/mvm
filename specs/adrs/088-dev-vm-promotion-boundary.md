# ADR-088 — Dev VM mutation promotion boundary: mutable dev state never implicitly feeds prod, and SSH-agent stays dev-tier only

**Status:** Accepted
**Relates to:** [ADR-002](002-microvm-security-posture.md) (prod vs dev posture),
[ADR-071](071-stage0-bootstrap-trust-model.md) (declared-input trust model),
[ADR-079](079-app-builder-product-surface.md) (product ergonomics without
weakening the engine), [Plan 200](../plans/200-machine-ux-dx-layer.md) (machine
UX/DX), and [Plan 36](../plans/36-sealed-signed-builder-image.md) (dev vs prod
image posture)

## Context

Plan 200 adds a persistent dev-machine workflow on top of existing runtime
primitives: image-backed `machine create/start/exec/shell/stop`, `dev.init`,
volumes, and a future `ssh_agent` transport. That raises a boundary question:
if a developer mutates state inside a long-lived dev microVM, should later
production/prod builds be able to "see" those changes automatically?

The answer matters because mvm uses Nix and signed/admitted runtime contracts to
make production behavior reproducible and auditable. If a prod build can depend
on ambient mutable guest state, the system quietly regresses to "whatever
happened in the dev VM" instead of "declared source + config + artifacts."

The same question applies to SSH-agent authentication. ADR-002's "no SSH in
microVMs, ever" remains the stricter rule: forwarding an agent socket is not
permission to create an SSH session, install SSH clients or servers, bake SSH
configuration into a template, or mount/copy SSH key material. A forwarded
agent socket is a dev-tier host capability crossing into the guest and is
acceptable only on an explicitly local/dev tier, never on the sealed/prod path.

## Decision

1. **Mutable dev-VM state is not a production input.** A dev microVM is a
   mutable work surface only. Its rootfs mutations, ad hoc package installs,
   and `dev.init` side effects never implicitly flow into a prod/sealed build or
   runtime.

2. **Prod/sealed builds consume declared inputs only.** A prod build may depend
   on:
   - host workspace files and committed source;
   - declared config and lockfiles;
   - explicitly mounted host directories/volumes that are part of the build
     input model;
   - explicitly exported or promoted artifacts that re-enter the system as
     declared host-side inputs.

   A prod build may not depend on opaque live guest state.

3. **Promotion across the boundary is explicit.** If a dev workflow produces a
   change that should matter to prod, that change must cross the boundary as
   one of:
   - a host workspace edit;
   - an explicit sync/export from a dev volume back to the host;
   - a signed/exported artifact that later re-enters through an admitted input
     path.

   "It existed in the dev VM" is not itself a promotion mechanism.

4. **SSH-agent support is dev-tier only and does not authorize SSH sessions.**
   When implemented, `ssh_agent` means Unix-socket forwarding of
   `SSH_AUTH_SOCK` only. Private key files, `~/.ssh/`, host known-hosts
   material, SSH clients, SSH servers, and SSH config are never copied,
   mounted, or installed into guest templates. The feature is allowed only on
   an explicitly dev-tier machine/run posture and is refused on standard,
   sealed, or prod paths. Network/admission layers must still block SSH
   sessions; the agent socket is not a transport exception.

5. **Policy visibility is mandatory.** Whether a run/machine is using dev-only
   hooks such as `ssh_agent`, writable volumes, or `dev.init` must stay visible
   in dry-run, admission/audit, and receipts. The dev tier is not hidden behind
   convenience defaults.

## Consequences

- Prod builds stay reproducible and reviewable: the source of truth is host
  source/config/artifacts, not a mutable VM's leftover state.
- Dev workflows keep their ergonomics. A developer can still use a persistent
  mutable machine, but must explicitly promote anything that matters to prod.
- SSH-agent forwarding remains a narrow local-development feature without
  weakening the sealed/prod trust boundary or the project-wide SSH ban.
- Future features such as "sync back to host" or "export dev artifact" are
  allowed, but they must be explicit promotion verbs, not ambient leakage from
  guest state into prod inputs.

## Alternatives considered

- **Let prod builds read live guest state directly.**
  Rejected: breaks reproducibility, makes reviews/audit weaker, and turns
  "works in my dev VM" into an undeclared build input.

- **Disallow mutable dev machines entirely.**
  Rejected: too strict for the product goal. Persistent dev machines, `dev.init`,
  and future SSH-agent forwarding are useful, as long as their boundary to prod
  is explicit.

- **Support generic SSH by mounting keys, installing SSH clients/servers, or
  baking `~/.ssh/` material into templates.**
  Rejected: SSH sessions are banned by ADR-002, and host secret material must
  not cross the boundary. Agent-socket forwarding is the maximum acceptable
  dev-tier shape and does not permit an SSH session.

## Out of scope

- The concrete socket-forwarding transport for SSH-agent. This ADR sets the
  allowed posture and boundary, not the implementation mechanics.
- A particular host↔guest sync/export UX. This ADR requires explicit promotion
  but does not pick the final command shape.
- Changing the existing rule that prod/sealed machines reject dev-only hooks
  such as `dev.init`.

## References

- [Plan 200](../plans/200-machine-ux-dx-layer.md)
- [ADR-002](002-microvm-security-posture.md)
- [ADR-071](071-stage0-bootstrap-trust-model.md)
- [ADR-079](079-app-builder-product-surface.md)
- [Plan 36](../plans/36-sealed-signed-builder-image.md)
