# ADR-017: OCI image verity — deterministic at materialize time, enforced when sealed

## Status

Accepted

## Context

`mvmctl` can launch an arbitrary OCI image reference as a workload, alongside
its Nix-built and packed-artifact workloads. A Nix-built rootfs already gets
a deterministic, reproducible verity story as a side effect of how it's
built; an OCI reference is arbitrary input from an external registry, so it
needs the same integrity guarantee without inheriting Nix's determinism for
free.

Two different threats are in play, and no single mechanism covers both:
provenance — did this launch really come from the registry reference it
claims to? — and at-rest integrity — do the bytes actually on disk right now
match what was verified when they arrived? A production launch needs an
answer to both, not a choice between them.

## Decision

**OCI distribution and rootfs materialization are separate steps, and only
distribution happens at `mvmctl image pull`.** Pulling an image fetches its
manifest, verifies every layer's digest against that manifest, and unpacks
layers through an allow-listed unpacker. No filesystem materialization and
no verity generation happen at pull time. An ext4 rootfs, and its verity
metadata, are produced later, at the point a pulled image is actually
launched.

**Every OCI-derived rootfs materialization computes deterministic dm-verity
metadata, regardless of profile.** A Merkle tree and roothash are generated
over the assembled ext4 image using fixed parameters — 4096-byte blocks,
zero salt — so the roothash is a pure function of the input tree, not of
which run produced it. Generation happens either through mvm's in-process,
memory-safe ext4-and-verity writer, which is the default, or, where that
path can't be used yet, by shelling `veritysetup` inside the builder VM;
both compute the identical roothash for the same input given the fixed
parameters.

**Boot-time enforcement is conditional on sealing, not on generation.** A
sealed (production) launch's backend refuses to boot if verity metadata was
intended — a roothash was recorded — but the on-disk sidecar is missing or
incomplete. An unsealed (dev-tier) launch boots without enforcing the
verity metadata that was already computed for it.

**A production pull or launch refuses a mutable reference before any
network access.** `--prod` requires a digest-pinned reference and a
configured registry trust policy; a tag-only reference is rejected before
the registry is ever contacted, for both `mvmctl image pull` and a launch.
Cosign verification of the resolved digest is required under `--prod`, and
the policy cannot disable it.

**Every launch of a pulled image records its provenance in the chain-signed
audit log.** The registry host, repository, the reference as supplied, the
resolved manifest digest, the layer digest list, and the trust policy in
effect are all recorded as part of admission (claim 14); tampering with any
of those fields breaks the chain.

## Consequences

Deferring materialization and verity generation to launch time, rather than
to pull time, means the first production launch of a freshly pulled image
pays the sealing cost inline instead of amortizing it across the pull. It
also means a pull-only workflow — inspecting or re-exporting a pulled image
without ever launching it — never has to carry verity machinery at all.

Two writers computing the same deterministic verity metadata, the
in-process default and the builder-VM-shelled fallback, is accepted
redundancy rather than a correctness gap: both are pinned to the same block
size and zero salt, so they agree on the roothash for the same input. It
does mean a sealed launch today can pay for both paths where the fallback is
exercised, which is wasted work worth collapsing to one path over time.

Splitting provenance, an audit-chain property, from verity, a boot-time
integrity property, keeps each mechanism honest about what it actually
catches: provenance answers whether a launch came from where it claims,
verity answers whether these exact bytes match what was verified. Neither
substitutes for the other, and a production launch gets both.
