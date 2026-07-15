# Security & Data-Governance Model

What the restructure preserves and strengthens. Nothing here is traded away for simplicity — see [01-goals.md](01-goals.md) for the non-negotiable framing.

## Guest sees no secrets, emits no PII — universal invariant

Once all egress crosses the host seam described in [03-networking.md](03-networking.md), "guest sees no secrets, emits no PII" stops being a per-backend property and becomes architecturally universal: bidirectional secret **substitution** + bidirectional **PII redaction/masking**, both written to the chain-signed audit log, backed by a CI witness across all workload backends. The architecture guarantees the host inspects every byte; ruleset completeness (which strings count as secrets, which patterns count as PII) is a policy concern layered on top, not a gap in the architecture itself.

## Secrets: user-defined `${mvm.NAME}` placeholders

The guest holds only a **named placeholder** — `${mvm.NAME}` — never the real value. The host injects the real value only on the secret's bound-destination flow, at the moment of egress, for exactly the destination that secret is bound to. The value never enters the guest's address space and is never logged; the audit record carries the placeholder name, the destination, and the admit/deny decision — never the secret bytes.

This replaces the earlier global `HTTP_PROXY=:1080` substitution proxy with the typed-connector path over the vsock seam (see [03-networking.md](03-networking.md)).

The security property here comes from **destination-binding + host-side-only injection**, not from placeholder opacity. Obscuring the placeholder name buys nothing — the guarantee holds because the host is the only party that ever holds the real value and it only ever releases that value onto a flow matching the pre-declared destination binding, decided and audited by the host, not the guest. A guest that tries to send `${mvm.NAME}` somewhere other than the bound destination just sends the literal placeholder string — no leak, because there is nothing to leak client-side.

## Retained and strengthened unchanged

- **Verified boot** — dm-verity rootfs + sealed runtime overlay.
- **Signed `ExecutionPlan` admission** — every workload runs from a signed, audited plan.
- **Content-addressed bundles** — every published bundle is content-addressed, key_id-pinned, re-verified at fetch and at admit time.
- **Chain-signed audit log** — tamper-evident; verifiable via `mvmctl trust audit verify`.
- **Attestation via nix templates** and the **machine-checked claims catalog** — the claim → witness mapping stays enforced by CI (`check-claim-catalog`); see [08-adr-consolidation.md](08-adr-consolidation.md) for where the claims ledger now lives (fenced in ADR-001).

## Auditable logging everywhere

`mvm-core::log` (a module, not a crate — see the crate map in [02-architecture.md](02-architecture.md)) emits two things from one call site: structured operational logs (`tracing`, → `~/.mvm/logs`) and chain-signed audit entries for every security-relevant action. Secrets and PII are redacted at the boundary before either sink sees them — never logged, in either stream. "Auditable everywhere" specifically means: every guest↔host RPC and every egress byte is traceable through the vsock seam and the chain-signed audit log — there is no other path a byte could have taken.

## Guest binary distribution

The guest binary (`mvm-agentd`, per [02-architecture.md](02-architecture.md)) ships **only** as the read-only, dm-verity-sealed **runtime-overlay volume** every microVM mounts. It is never baked per-rootfs. This means updating the overlay updates every microVM in one motion, and the sealed, read-only property is what makes the verified-boot guarantee meaningful for the guest binary specifically — a compromised rootfs still can't tamper with the overlay because it isn't writable and its hash is checked.

## Net effect on the claims catalog

None of the above changes what a claim *means* — the restructure changes *where the code lives*, not what it guarantees. The claims catalog, its witnesses, and the CI gates that enforce them are unaffected by the crate/binary/directory consolidation; they are expected to keep passing throughout, and any WS that would break a claim's witness must update the witness in the same change, never drop it. See [06-execution-plan.md](06-execution-plan.md) for the workstream-by-workstream detail (Phase 2's WS2/WS-NET carry most of the security-relevant surface area).
