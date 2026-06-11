# Plan 129 E1 Step 2 — per-destination egress redaction + entropy detection

**Status:** design, approved 2026-06-10. Implementation sequenced below.

## Goal

Catch **undeclared** secret-shaped tokens and PII on the egress the host can
see, and redact (or block) them per destination — the "predicted" half of
Plan 129, complementing declared-secret substitution (the "specified" half).
No declaration required.

## What already exists (do not rebuild)

A detector ecosystem predating Plan 129 (Plan 37 Wave 2.x) already lives in
`crates/mvm-hostd/src/supervisor/` and is wired live:

- `secrets_scanner.rs` — `SecretsScanner`: curated, high-precision
  gitleaks/trufflehog-style secret patterns compiled into one
  `regex::bytes::RegexSet`; denies secret-bearing egress, names the rule that
  fired, **never echoes the value**. Deliberately curated-only — its docs
  reject generic entropy / "looks like base64" as too noisy.
- `pii_redactor.rs` — `PiiRedactor`: `email`, `us_ssn`, `credit_card`
  (Luhn-validated), `e164_phone`; `Mode { Allow, Redact, Block }`; built from
  `mvm_core::policy::PiiPolicy { mode, categories }` via `from_policy`, which
  fails admission loudly on a bad mode/category.
- `RedactingSubstitution` (`network/stages.rs`) — byte-level redactor wrapping
  the above rules; `redact_bytes(&[u8]) -> Option<(masked, RedactionHits{secrets,pii})>`.
  Used by the gateway-bridge packet `SubstitutionStage` **and** the
  substitution-endpoint request redactor (`substitution_proxy::redact_outbound`).
- `injection_guard.rs` — `InjectionGuard`: prompt-injection patterns.

The inspector chain (`aggregate.rs::build_inspector_chain_with_pii`) is built
**once per workload** — detectors apply uniformly to every allowed
destination. `DestinationPolicy` is an allow/deny host list, not a per-host
detection action.

So the spec-named items break down as: secret-shaped regex ✅, PII regex ✅,
Luhn ✅, bounded `RegexSet` ✅. Genuinely missing: Shannon **entropy**,
**per-destination** action, **names**, **IBAN**. The spec's "`core::redact`
(new)" relocation and "named profile (125 E4)" coupling are both dropped — see
Decisions.

## Threat model & honest framing

This is a **best-effort hygiene layer on inspectable egress**, not a
containment boundary. The real containment is already shipped: claim-10
default-deny egress + declared-secret substitution (the raw secret never
enters the guest). Redaction **complements** those and must not weaken them or
justify widening an allowlist.

It addresses **accidental / sloppy leakage** — an LLM agent that dumps a
`.env`, a customer row, or a DB result verbatim into an allowed request. It
does **not** stop a determined exfiltrator: encoding, compression,
reformatting ("j dot doe at gmail"), or chunking defeat byte-level detection.
That scope is acceptable and is stated, not implied-away.

### Why the vsock architecture makes this feasible

All egress for these workloads funnels over **vsock** to the host endpoint —
the guest has no NIC and no route to originate its own external connection. It
hands the host a **cleartext request envelope** (method/url/headers/body); the
host originates the real TLS. So the host sees cleartext and can redact.

Coverage = **http + TLS-terminated (bound-host) https**. The one blind spot is
**https spliced to an *unbound* host** (Stage 2 passes ciphertext through
without terminating) — but that path does no substitution and is governed by
the allowlist/default-deny anyway. There is no raw-packet egress path here, so
the redactor is wired **only** into the cleartext endpoint path, never the
gateway-bridge packet pipeline.

## Detection design

### Tier 1 — structured PII (reliable: format + checksum)

`email`, `us_ssn`, `credit_card` (Luhn), `e164_phone` already exist. **Add
IBAN** (mod-97 checksum). **Account numbers**: only via a checksum (IBAN) or a
field-label anchor (Tier 3) — a bare digit run is indistinguishable from any
number and is out of scope.

### Tier 2 — entropy (secret-shaped unknowns)

New `EntropyScanner` (`mvm-hostd`). Shannon entropy over candidate token runs
— contiguous `[A-Za-z0-9+/=_\-]` of length ≥ `min_run_len` — flagged when
bits/char ≥ `min_bits_per_char`. Single pass over `&[u8]`, allocates only the
hit list, **never echoes** the matched bytes (audit carries rule + offset).
Additive to `SecretsScanner` — catches unknown-shape tokens the curated rules
miss. **Audit-only on first opt-in; redact is an explicit second step; never
block** — high-entropy false positives (JWTs, UUIDs, base64 uploads, hashes,
protobuf) must degrade, not break, and operators see hits before masking.

### Tier 3 — names (anchored + gazetteer, no ML)

NER (Presidio/spaCy) is **rejected**: an ML model in the host hot path breaks
the deterministic/reproducible-build invariant, adds an adversarial-ML input
surface, and is disproportionate for a non-boundary layer a determined
exfiltrator evades anyway. Instead, target the name leaks that actually matter
— structured dumps carry context:

1. **Field-label anchor** — JSON keys / form fields / `Label:` prose matching
   `name|first_name|last_name|full_name|customer|patient|cardholder|...` →
   redact the value.
2. **PII co-occurrence** — a capitalized 2–3 token run *near* a confirmed
   email/SSN/phone/CC/IBAN hit → redact (the "row" case: a name bound to other
   PII is the real leak).
3. **Gazetteer validation** — a compile-time static census first/last-name set
   (`phf` or a sorted slice baked into the binary — **data, not an ML dep**, no
   runtime cost) gates unanchored candidates so not every capitalized word is
   masked.

Names run **redact-mode, audit-first**. Freeform unlabeled names with no
nearby PII are **out of scope** (undetectable without NER, low-sensitivity) —
documented, not pretended-away.

## Per-destination action model

New in `mvm_core::policy::policies`:

```
RedactionAction {
    entropy: EntropyMode,   // Off | Audit{ min_bits_per_char, min_run_len } | Redact{ same }
    pii: PiiPolicy,         // reuse existing: mode + structured categories (+ iban)
    names: NameMode,        // Off | Audit | Redact — separate field: names use the
                            //   anchored+gazetteer mechanism, not the structured-regex path
    secrets: SecretAction,  // curated SecretsScanner action (existing default: Block)
}
```

`names` is deliberately its own field, not a `pii` category: structured PII is
regex+checksum, names are anchored+gazetteer with an audit-first default — two
mechanisms with different failure modes. (The audit *category label* is still
`name`; the config knob is `NameMode`.)

A workload's egress policy gains an optional ordered
`redaction_profiles: Vec<{ host: String /* `*.` wildcard */, action: RedactionAction }>`.
A `resolve(dest) -> &RedactionAction` picks the first matching host (reusing
the existing `host_matches` wildcard helper), else a `default` = today's
curated-only baseline (entropy `Off`, names `Off`, structured PII per the
workload `PiiPolicy`, curated secrets `Block`). `deny_unknown_fields` + a parse
error on a bad enum value so a typo fails **admission**, not runtime — matching
`PiiRedactor::from_policy`.

**Self-contained** — independent of the unbuilt Plan 125 E4 `--profile`
(whole-workload capability matrix). The two compose later: E4 sets workload
posture, this sets per-destination redaction.

## Where it plugs in

Both live cleartext call sites already resolve a destination — the
substitution endpoint (`substitution_proxy::process`, has `destination`) and
the bound-host TLS terminator (`handle_terminator_connection`, has `orig_dst`).
Each resolves `redaction_profiles.resolve(dest)` and applies that action's
detectors. The shared rule definitions stay in `mvm-hostd` — **no `core::redact`
relocation** (everything is host-side and already shares one definition; the
move buys nothing).

## Fail-closed posture

- A `Block`-mode hit (curated secret, or an opted-in Block category) denies the
  request — claim-10/13 lineage.
- **Over-cap bodies** and **`Content-Encoding`-compressed bodies** to a
  redaction-opted-in destination are **blocked + audited** — otherwise both are
  silent bypasses (PII past the scan window / inside a gzip stream). Bounded
  in-window decompression is a later refinement.
- A malformed profile fails **admission**, not runtime.
- Default for every unlisted destination is the unchanged curated-only
  baseline, so the low-false-positive posture is preserved unless an operator
  opts a destination in.

## Audit

Reuse `secret.redacted { destination, categories }` (the `audit_redactions`
path already in `substitution_proxy`) — extend `categories` to carry `entropy`,
`name`, `iban`. Metadata only; **never** the matched bytes. A `Block` keeps its
existing deny-audit. `verify_audit_chain` stays green.

## Out of scope / deferred

- ML/NER name detection (rejected — see Tier 3).
- Freeform unlabeled names with no co-occurring PII.
- Bare account numbers without a checksum or label.
- Decompressing bodies to scan inside (blocked + audited for now).
- https spliced to unbound hosts (ciphertext; governed by the allowlist).
- Raw gateway-bridge packet-pipeline redaction (no cleartext there; no raw path
  over vsock).

## Implementation slices (each a mergeable, TDD PR)

1. **`EntropyScanner`** standalone — flags a high-entropy run, ignores
   low-entropy prose, respects `min_run_len`/threshold, masks without echoing;
   audit/redact modes. (No wiring yet.)
2. **IBAN** rule (mod-97) added to the structured PII set + `PII_CATEGORY_NAMES`.
3. **Name detector** — field-label anchor + PII co-occurrence + gazetteer
   validation; redact/audit modes; static census name set baked in.
4. **`RedactionAction` + `redaction_profiles` + `resolve`** in `mvm-core`
   policy — serde, wildcard match, first-match-wins, default fallback, parse
   error on bad enum.
5. **Destination-aware wiring** — endpoint + terminator resolve the profile and
   apply the action; over-cap / compressed bodies fail-closed; `secret.redacted`
   carries the new categories.

REFACTOR-STATUS Plan 129 boxes ticked with **each** landing, date bumped, in
the same change.

## Acceptance

- Entropy detector catches an unknown high-entropy token a curated rule misses;
  audit-first, never blocks; no value in the chain.
- IBAN + structured PII redacted/blocked per the resolved per-destination action.
- A labeled or PII-co-located name is redacted; an unlisted destination passes
  it; a bare capitalized word with no anchor/gazetteer hit is not masked.
- Over-cap and compressed bodies to an opted-in destination are blocked +
  audited.
- Default (no `redaction_profiles`) is byte-identical to today's behavior.
- `secret.redacted` carries `entropy`/`name`/`iban` categories, never bytes;
  `verify_audit_chain` green. `cargo nextest` + clippy + fmt green; **no ML/heavy
  dependency** (a compile-time name set via `phf`/sorted-slice is data, not a
  runtime dep).
