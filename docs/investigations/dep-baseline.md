# Dependency baseline (plan 126 Task A1)

Measured 2026-06-05 on `main` @ `bb1cbcbe` (post plan-126 B5). This is the
canonical measurement method + the live numbers every later plan-126 task
records its delta against. Plan 127's dep-count dashboard reads from here.

## Method (the canonical commands)

Two different numbers, measured two different ways — don't conflate them:

```sh
# (1) Default binary closure — what actually compiles into a default
#     `mvmctl` build. This is the number the B-tasks move.
cargo tree --workspace -e no-dev --prefix none | sed 's/ (.*)//' | sort -u | wc -l

# (2) Full lockfile — every package resolved across all features, targets,
#     and dev-deps. A coarser supply-chain-surface proxy.
grep -c '^name = ' Cargo.lock

# Per-target closure (how many crates a target drags):
cargo tree -p <crate> -e no-dev --prefix none | sed 's/ (.*)//' | sort -u | wc -l
# Who pulls a target:
cargo tree -i <crate> -e no-dev
# Feature-on closure (a gated feature's added cost):
cargo tree -p mvmctl --no-default-features --features <feat> -e no-dev --prefix none | sed 's/ (.*)//' | sort -u | wc -l
```

## Baseline numbers

| Metric | Value |
|---|---|
| Default binary closure (method 1) | **407** unique packages |
| Full lockfile (method 2) | **722** packages |
| `mvmctl` + `manifest-verify` closure | 469 (sigstore adds ~62) |
| `mvm` + `template-registry-s3` closure | 355 (opendal) |

Lockfile drifted 739 (2026-06-03) → **722** now — B5 + the intervening
merges + the 0.16.0 version bump. The brief's "723"/"735" earlier counts
were the lockfile metric at other points in time.

## The four B-task targets — corrected findings

The plan's Phase-B target list was written on assumptions that the live
tree contradicts. What's actually true:

| Target | In **default** closure? | Closure | Reality |
|---|---|---|---|
| `sigstore` | **No** — gated behind `manifest-verify` (off by default) | ~62 added when on | B1's *default-build* benefit is **already realized**. Only a `manifest-verify` build pays for it. B1 is now purely the cross-repo "relocate cosign-verify to mvmd" decision (the prod/admit gate lives in mvmd), not a default-closure cut. |
| `opendal` | **No** — gated behind `template-registry-s3` (off by default) | part of the 355 | Same as sigstore: B2's default benefit is **already realized**. B2 (→`object_store`) only helps the `template-registry-s3` build, and is coordinated with plan 123. |
| `pgp` (rpgp 0.17) | **Yes** — unconditional dep of `mvm-build` | **168** | **B3's premise is wrong.** `pgp` is **not** our release signing. It verifies the **Alpine minirootfs tarball's upstream PGP signature** against an embedded Alpine release key in Stage 0 (`crates/mvm-build/src/stage0.rs::verify_alpine_pgp_signature`). It **cannot** move to minisign — Alpine dictates the format. See below. |
| `aws-lc-rs` 1.16 | **Yes** — `rustls` default crypto provider | **16** + a C/cmake build | **B4 stands.** Pulled `reqwest(rustls-tls) → hyper-rustls → rustls → aws-lc-rs`. Pinning rustls to the `ring` provider removes it and kills the native cmake build. |

### The only two default-closure targets are `pgp` (168) and `aws-lc-rs` (16).

`sigstore` and `opendal` are already out of the default binary — their
cuts only shrink the respective *feature-on* builds.

## B3 re-scope: `pgp` is Alpine-tarball verification, not release signing

`mvm-build/src/stage0.rs` fetches Alpine's official minirootfs and verifies
it **two ways**: a source-pinned **SHA-256** (`verify_sha256` against
`ALPINE_MINIROOTFS_{AARCH64,X86_64}`) **and** a detached **PGP** signature
against the embedded `ALPINE_RELEASE_KEY_ASC` (fingerprint also pinned).
The doc comment calls PGP the layer that "catches a malicious upstream
mirror that signs with the wrong key."

But the tarball is **already byte-pinned by SHA-256** for the pinned
`ALPINE_VERSION`. For a pinned version the hash is the binding integrity
check; the PGP verify is **defense-in-depth** whose distinct value is
mainly at *version-bump* time (verify a new tarball's signature before
trusting its not-yet-pinned bytes).

So reducing the 168-crate `pgp` closure is **not** a minisign swap. The
options, each a real decision (not mechanical):

1. **Drop the PGP verify, keep the SHA-256 pin** (−168 crates). Removes a
   defense-in-depth layer; needs security-owner sign-off + an ADR-002
   note, and a documented version-bump procedure (verify the new tarball's
   PGP signature out-of-band before pinning its hash).
2. **Keep PGP, find a lighter verifier.** rpgp *is* the lean option for
   OpenPGP detached-signature verification; sequoia is heavier. No obvious
   smaller crate exists for RSA-OpenPGP verify. Low expected payoff.
3. **Gate it behind a feature** so only the contributor Stage-0 build pays
   for it (the published binary doesn't run Stage 0 the same way). Needs a
   look at whether any default path reaches `verify_alpine_pgp_signature`.

Recommendation: pursue option 1 (biggest win) **as a security decision**,
or option 3 if a feature boundary is clean — but not as a silent swap.

## Suggested task order (revised)

1. **B4 (`aws-lc-rs` → `ring`)** — cleanest default-closure cut; −16 + no
   C build. Needs a runtime TLS smoke (provider-pinning can compile-green
   yet break at connect time).
2. **B3 (`pgp`)** — biggest number (−168) but a security decision (above).
3. **B1/B2** — no default-build benefit left; pursue only for the
   feature-on builds / the cross-repo relocation, sequenced with 123.
4. **C1** (`reqwest`/`oci-client` duplicate majors), **D1** (the gate).
