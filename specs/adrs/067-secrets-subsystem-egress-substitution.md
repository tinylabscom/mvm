# ADR-067 — Secrets subsystem: egress substitution, never in the guest

**Status:** Accepted (2026-05-31). Supersedes ADR-049 (in-guest resolve-over-vsock). Fills the gap ADR-062 left when it dropped `host.secrets.v1` from the broker. Implemented by plan 129; the `SecretsNotImplemented` gate in `mvm-ir/src/validate.rs` lifts when 129 lands. Backs claims 12 + 13.

## Context

The guest is the untrusted workload. A raw secret reaching it can be exfiltrated, logged, or baked into a snapshot. The requirement: **a raw secret value never enters guest RAM.** The workload still needs secrets to reach external services (an API key, a SigV4 signature, a webhook HMAC).

The model already half-exists. `mvm-ir` carries `EnvValue::SecretRef` — a secret-store *key* plus a mount shape, never bytes ("No secret bytes ever live in this struct"). `mvm-sdk/src/runtime_substitution.rs` (ADR-049) resolved placeholders over vsock so the *guest* SDK could sign — but that brings the credential into the guest, which we now reject. ADR-062 dropped the broker's `host.secrets.v1` handler without a replacement, so the subsystem is gated (`SecretsNotImplemented`).

Constraints that shaped the decision:

- **Same story with or without `mvmd`.** mvm runs standalone (local dev) and under `mvmd` (production, multi-tenant). The secret API, the workload's view, and the substitution flow must be identical; only the value's *source* differs.
- **No hardware requirement.** Requiring a Secure Enclave/TPM to run the demo is an unacceptable DX. Hardware sealing must be a transparent upgrade, never a gate.
- **Don't trust-the-host-with-everything more than necessary.** ADR-002 trusts the host, but the blast radius of a host bug should be one small audited component, not "every secret in plaintext in a general proxy." (This is where the adjacent MITM-everything designs are weakest: one proxy terminates all guest TLS and sees every secret.)

## Decision

A secret is a reference. The host substitutes the real value into outbound traffic at the egress boundary; the guest holds only a placeholder. Four parts.

### 1. Mechanism — proxy-native transparent substitution (SDK optional)

> **Update (plan 129 Stage 2 — proxy-native is the primary path).** The
> original framing below made SDK-cooperative routing primary and the non-SDK
> path a "coverage boundary." That is now inverted. The **transparent host-side
> terminator** is the primary mechanism: an nft `nat` REDIRECT steers the
> guest's outbound `:80`/`:443` to a per-VM terminator that recovers the
> original destination (`SO_ORIGINAL_DST`), substitutes on bound hosts, and —
> for `https` — terminates TLS under a **per-VM name-constrained intermediate**
> the guest trusts (ADR-006), splicing unbound hosts through untouched. A
> generic `curl https://<bound-host> -H "Authorization: Bearer $PLACEHOLDER"`
> with **no SDK** now gets the real credential substituted host-side. The SDK
> forward-proxy (`HTTP_PROXY` + placeholder env) remains supported as an
> alternative, but is no longer required. The claim-12 allow-list and claim-13
> "no value to the guest / metadata-only audit" invariants are identical on both
> paths. The §"Coverage caveat" below is superseded for **bound** hosts (they
> substitute SDK-or-not); an unbound destination still gets the placeholder
> dropped, which remains the correct failure.

The workload's HTTP client routes a secret-bearing request to a **host substitution endpoint** (configured by the SDK / proxy env), carrying a placeholder token where the secret goes. That hop is host-local (vsock / UDS), so its plaintext is fine — the host is in the TCB and the channel has no third-party observer. The host endpoint:

1. checks the destination is allow-listed for that secret (binding-gated — claim 12),
2. substitutes — injects the value (bearer) or delegates to the signer (signing-based, §3),
3. makes the **real TLS** to the destination and streams the response back.

The workload never makes its own TLS to the destination for a secret-bearing request and never holds the value. We do **not** MITM the guest's other TLS — only requests the workload explicitly routes for substitution are seen host-side.

The egress proxy (claim-10 default-deny, ADR-064 `NetworkProvider`) is the catch-all underneath: **all** egress traverses it. Secret-bearing requests are routed for substitution; everything else is policy-checked and **leak-scanned** — a placeholder or a known secret value appearing in non-substitution egress is dropped and audited. This is the "detect" backstop for the case a workload tries to smuggle a placeholder out a side channel; it cannot smuggle a *value* because it never had one.

Coverage caveat, stated honestly: a workload that bypasses the SDK and emits a placeholder via a raw `curl` to an arbitrary host gets the placeholder dropped (the proxy never substitutes for an unbound destination), not a secret. That is the correct failure — you only get substitution on the bound path.

### 2. Resolver — pluggable, identical story with or without `mvmd`

A `SecretResolver` trait resolves a `SecretRef` (name + auth-type + allowed-hosts) to material at substitution time. Two backends, same trait:

- **Local** — the OS keyring / encrypted file. This is the existing `KeyProvider` in `mvm-core` (`keystore.rs`: Keyring/File/Env), so it largely exists. Define with `mvmctl secret set <NAME> --host <allowed-host> --type sigv4|bearer|hmac`. No `mvmd`.
- **mvmd** — the same trait, backed by the tenant control plane (a separate mvmd plan).

The `Sandbox` API, the placeholder, the egress flow, and the audit are identical on top. The resolver is an implementation detail the workload never sees. Dev (Local) → prod (mvmd) is one continuous story, not two systems.

### 3. Keyholder — software-first, hardware-optional, split by auth-type

How the secret is *used*, independent of where its value came from:

- **Signing-based (SigV4, HMAC webhooks, JWT/OAuth client-assertion):** a jailed **signer** receives the canonical request and returns a signature. The key never goes on the wire. If a Secure Enclave / TPM is present the key is sealed there and signing is a hardware op — **the host never sees the plaintext key.** If not, a confined software signer decrypts-signs-zeroizes (key encrypted at rest via 122's DEK/KEK). Same flow; the property strengthens with hardware. This reuses the `mvm-hostd` separate-signer-process model and the keyless `core::subprocess` scaffold.
- **Bearer / basic (the value is transmitted):** the raw value must hit the wire, so a host component must see it — there is no way around that, and we will not overclaim otherwise. We confine it: decrypted only inside a minimal jailed **injector** that terminates TLS to the bound destination, injects, and zeroizes; encrypted at rest; never written to disk in plaintext; never to the guest. Blast radius is one audited component scoped to that secret's destinations. The design steers integrations toward signing schemes (most cloud APIs offer HMAC/assertion) so the hardware-sealed path covers as much as possible and bearer is the fallback.

**No hardware is required.** The default is pure software: encrypted at rest with a software-managed key, and the OS keyring (software-backed by default; on macOS it can ride the Secure Enclave for free with no setup). Hardware sealing changes nothing about the DX or the demo.

Honest framing for the docs and tests: *software default = encrypted at rest, decrypted only in a minimal jailed keyholder; hardware = never seen.* Same code path.

### 4. IR contract, placeholder, audit

- **`SecretRef`** gains `auth_type` (`sigv4 | hmac | bearer | basic`, extensible) and `allowed_hosts` (wildcards like `*.internal.corp`) alongside the existing name + mount shape. Still no bytes. The validator's `SecretsNotImplemented` gate is replaced by real resolution.
- **Placeholder** is an opaque, per-session, single-use token (not the secret name) so a leaked placeholder reveals nothing and can't be replayed for a different session or destination.
- **Audit** (chain-signed, claim-13 lineage): every substitution emits a `secret.substituted` entry (name, destination, auth-type — never the value); every dropped leak emits `secret.placeholder_dropped`. `mvm_supervisor::verify_audit_chain` covers it; `mvmctl audit verify` surfaces drift.

## Consequences

- Stronger than a general MITM proxy: signing keys can be hardware-sealed and never seen; the host sees only the requests the workload routes for substitution, not all its TLS; bearer values are confined to one audited component.
- The demo runs with no hardware and no `mvmd`: `mvmctl secret set` + run.
- The SDK-cooperative path requires the workload to use the mvm SDK (or proxy env) for secret-bearing calls. The proxy's default-deny + leak-detector make the non-cooperative path fail safe (placeholder dropped), so this is a coverage boundary, not a hole.
- Claims 12 (binding-gated dispatch) and 13 (no raw secret to the guest) are restored, with a CI leak-gate built in plan 128 asserting (a) no raw secret crosses to the guest, (b) substitution only fires for bound destinations, (c) the audit chain carries no secret bytes.

## Alternatives considered

- **TLS MITM of *all* guest egress** (the adjacent-SDK approach). Rejected: the host terminates every TLS session and sees all plaintext, the guest's end-to-end TLS is broken, and it requires the guest to trust a long-lived blanket-trust host CA. Maximum host visibility for a platform whose pitch is minimal blast radius. **Note (plan 129 Stage 2):** the scoped terminator we *did* build is not this — it terminates **only bound hosts** (the host already sees their plaintext via substitution → zero added visibility), splices everything else untouched, and trusts a **per-VM name-constrained** intermediate that cannot vouch for any host outside the plan's allow-list (ADR-006), not a blanket CA.
- **Pure SDK-cooperative with no proxy detection.** Rejected: no backstop for a placeholder leaking via a non-cooperative side channel. The default-deny proxy + leak-scan is cheap and closes it.
- **Hardware-sealed required.** Rejected: unacceptable DX; hardware is a transparent upgrade, not a gate.
- **Resolve into the guest for signing** (ADR-049). Rejected and superseded: it brings the credential into guest RAM, which is the thing we are eliminating. Signing moves to the host keyholder.
