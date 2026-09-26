# #3712 — private-range default deny at the egress gate

The first part of PS-02 (`specs/plans/2026-09-25-agent-sandbox-product-surface.md`).
It lands on its own, ahead of the route model, because it is a security
change with no dependency on it.

## What was there

Three lists answered "is this address internal?", and they disagreed:

- **`MANDATORY_DENY_RANGES`**, consulted by `CanonicalEgress::permits`,
  covered metadata, link-local, CGNAT and loopback. It deliberately left out
  RFC1918, ULA, multicast and the unspecified block.
- **The DNS-answer guard** also refused RFC1918 and ULA.
- **The host tools' `SsrfGuard`** refused almost everything.

None of the three looked inside NAT64, 6to4, Teredo or IPv4-compatible
addresses. As a result, an unrestricted policy connected to `10.x` and
`192.168.x` addresses, and `64:ff9b::a9fe:a9fe` reached the metadata service
as far as the range check could tell.

The substitution path's forward leg also resolved the host a second time
through the system resolver, after the gate had resolved and checked it.

## What landed

- **One classifier:** `mvm_contract::policy::restricted_address`, with two
  tiers.
  - **Absolute:** cloud metadata (`169.254.169.254`, `169.254.170.2`,
    `100.100.100.200`, `fd00:ec2::254`), loopback, `0.0.0.0/8` and `::`,
    link-local, CGNAT, and any restricted IPv4 address embedded in an IPv6
    translation form.
  - **Private:** RFC1918, `fc00::/7`, multicast and `240.0.0.0/4`. These are
    denied unless a grant names them.
- **How a grant names an address:** a rule naming it must lie wholly inside
  the private range it belongs to. That covers a literal IP, a CIDR inside the
  range, or the `/32` or `/128` an allow-listed host lowers to at admission.
  `0.0.0.0/0` and an unrestricted policy name nothing.
- **Where it applies:** `CanonicalEgress::permits`, the WASI projection,
  `clamp`, the DNS-answer filter and `SsrfGuard` all consult the classifier. A
  pinned DNS answer survives only in a re-admittable class.
- **Refusals:** `EgressGate` refuses with
  `DenyReason::RestrictedAddress { ip, port, class }`. The refusal message
  names the fix for a private class (`--allow-host 10.0.0.5:5432`).
  `DenyReason::audit_label()` records the class (`cloud_metadata`,
  `private_range`, …) on FlowMux TCP/UDP denials and substitution-path
  refusals. Every other refusal still records `policy_denied`.
- **DNS pinning:** the substitution path records the gate's `Allow` addresses
  per `(host, port)`. `HardenedForwarder` resolves through a `GateResolver`
  that returns exactly those, or asks the gate itself for an unrecorded host,
  so the forward leg never dials an address the gate did not admit. FlowMux
  already dialed the verdict's addresses.

## Behaviour change to review

The builder VM's egress policy is unrestricted, and it now reaches no private
range either. Its DNS answers were already filtered for private addresses, so
this only changes a flake that fetches from a literal private IP. The
builder-egress test asserts the refusal.

## Witnesses (claim 10, ADR-001 and `model/claims.toml`)

- `private_range_is_denied_by_default_and_readmitted_only_by_a_grant_naming_it`
- `metadata_and_the_absolute_ranges_are_never_readmitted`
- `a_name_that_resolves_inward_is_refused_as_the_address_it_reached`
- `an_embedded_ipv4_form_is_classified_by_the_address_it_reaches`
- `the_forward_leg_gets_the_gate_s_answer_not_a_fresh_lookup`

The following also cover the audit side:
`builder_egress_refuses_private_ranges_and_metadata_and_audits_both` and
`a_restricted_address_refusal_records_its_class`.
