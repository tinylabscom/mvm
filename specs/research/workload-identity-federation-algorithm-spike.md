# WS-B0: can mvm's Ed25519 signer federate to a cloud provider?

Backing: preview
Validation: none — a decision note; cited external docs, no code

**Answer: no. EdDSA is not accepted, so federation needs a second key type.**
The cost is smaller than that sounds, and it is not where the real cost lives.

## The question

`specs/plans/2026-08-17-survey-followups-federation-ingress-webfetch.md` (WS-B)
proposes replacing long-lived secrets in `secret_store` with short-lived,
identity-bound credentials the provider issues. Every signing path in this
workspace is Ed25519 (`ed25519_dalek`, `crates/mvm-core/src/plan/signing.rs`).
If cloud federation endpoints accept EdDSA, WS-B is a moderate feature. If not,
it is a crypto-surface expansion — and that changes whether it is worth doing.

This spike was blocking for exactly that reason.

## Finding 1 — AWS: RSA or ECDSA only

`AssumeRoleWithWebIdentity` requires tokens signed with RSA (RS256/384/512) or
ECDSA (ES256/384/512). EdDSA appears nowhere in the supported set. ECDSA support
is itself recent — announced November 2024; before that it was RSA only.

So the canonical target rules Ed25519 out. That settles the question: a second
key type is required regardless of what other providers accept.

## Finding 2 — GCP: not definitively documented

Google's public Workload Identity Federation docs show RS256 in examples but do
not publish a complete list of accepted algorithms. Third-party services that
document their own support (Snowflake, Databricks) list RS256 and ES256.

**Do not treat GCP as confirmed either way.** It does not change the decision —
AWS already forces a second key type — but if GCP becomes a target, verify
against a live provider rather than inference. This note asserts only what the
first finding supports.

## What it actually costs

Cheaper than "add a crypto stack", because we need to **sign**, not verify:

- **A P-256 key for ES256.** `p256` (RustCrypto) is pure Rust with no OpenSSL.
  Confirmed genuinely new: no `p256`, `ecdsa`, `elliptic-curve`, or `rsa` entry
  exists in `Cargo.lock` today. ES256 over RS256 keeps keys and signatures small
  and avoids an RSA implementation.
- **JWS: hand-roll it.** A signed JWT is
  `b64url(header).b64url(payload).b64url(sig)`. `base64` 0.22, `sha2`, and
  `serde_jcs` are already in the tree. Signing-only JWS is on the order of a
  hundred lines and needs no `jsonwebtoken`/`jose` dependency — which matters,
  because `deny.toml` and `check-duplicate-majors` gate new dependencies and the
  workspace has a standing "limit dependencies" rule.

So the crypto delta is **one dependency tree plus a small module** — not the
blocker it looked like.

## Where the real cost is

Not crypto. The premise of federation is a **stable issuer with a reachable
JWKS**, because a customer configures the trust relationship in their own cloud
account once, against an issuer URL and a `sub`.

mvm is a local CLI. Every developer's host signer is a different issuer, and
nobody will add a per-laptop trust relationship to a production cloud account.
The issuer has to be mvmd, which today has no outbound issuance at all — its
`mvmd-iam` surface is `api_key` + `principal`, and its only OIDC reference is
*inbound* (`oidc_client`), i.e. users authenticating **to** mvmd.

That subsystem — a hosted issuer, key rotation, a published JWKS endpoint, and
its availability story — is the actual expense. The signing algorithm was never
the hard part; it just looked like a blocker from inside this repo.

## Recommendation

**Proceed to B1, treat B2 as the real commitment gate.**

B1 (the identity claims DTO) is worth doing now: it is pure data, needs no key
type and no issuer, and it forces the `sub` question to be settled correctly —
`(tenant, workload)`, per `crates/mvm-core/src/plan/content_id.rs`, **not**
`plan_id`, which is per-execution and would break the customer's trust policy on
every run.

Do not start B2 (the mvmd issuer) as an implementation task. Decide first
whether mvm/mvmd wants to operate an identity provider, with the availability
obligation that carries — a workload that cannot reach the JWKS cannot
authenticate. That is a product commitment, not a coding task, and it should be
made deliberately rather than arrived at.

## Sources

- [AssumeRoleWithWebIdentity — AWS STS API Reference](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html)
- [Create an OpenID Connect (OIDC) identity provider in IAM](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html)
- [Announcing AWS STS support for ECDSA-based signatures of OIDC tokens](https://aws.amazon.com/about-aws/whats-new/2024/11/aws-sts-ecdsa-based-signatures-oidc-tokens)
- [Configure Workload Identity Federation with other identity providers — Google Cloud](https://docs.cloud.google.com/iam/docs/workload-identity-federation-with-other-providers)
