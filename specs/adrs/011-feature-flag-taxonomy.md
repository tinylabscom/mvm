---
title: "ADR-011: Feature flag taxonomy"
status: Proposed
date: 2026-05-07
related: ADR-004 (libkrun pivot), ADR-007 (VmBackend), ADR-009 (cross-platform), plan 60-mvm-libkrun-migration
---

## Status

Proposed. Feature flags are declared in Phase 0 (root `Cargo.toml`); each is exercised by at least one CI build configuration by Phase 9.

## Context

The feature-flag namespace can sprawl quickly in a workspace this size. Without a taxonomy, every contributor invents new feature names ad-hoc, and we end up with `enable-foo` next to `with-bar` next to `bar-disabled`. Worse, dev-only features can slip into production builds if the gating is sloppy.

This ADR establishes:
1. The categories of flags
2. The naming conventions
3. The CI matrix that exercises them
4. The hard rule that **`dev` must never be enabled in production builds**.

## Decision

### Categories

```toml
# Backends (at least one must be enabled — CI checks)
firecracker     = ["dep:vmm-firecracker-client"]   # Linux-only
libkrun    = ["dep:libkrun"]             # cross-platform
backend-cloud-hypervisor = []                      # post-Phase-10

# Front-ends
mcp             = ["dep:rmcp", "mvm-mcp/server"]
sdk             = ["dep:mvm-sdk"]

# Observability
metrics-prometheus = ["dep:metrics-exporter-prometheus"]
metrics-otel       = ["dep:opentelemetry-otlp"]
audit-remote-sink  = ["dep:reqwest"]

# Encryption tiers
luks            = []                               # Linux-only volume encryption
apfs-encrypt    = []                               # macOS-only fallback
bitlocker       = []                               # Windows-only fallback

# Network paths
egress-l4-proxy = ["dep:smoltcp", "dep:tun"]
egress-l7-proxy = ["egress-l4-proxy", "dep:hyper", "dep:rustls"]
egress-firewall-nft = ["dep:nftables"]             # Linux nftables only

# Computer-use & GPU
computer-use    = ["dep:image", "egress-l4-proxy"]
gpu-virgl       = []                               # virtio-gpu via virgl/Venus (libkrun)
gpu-passthrough = ["backend-cloud-hypervisor"]

# Attestation
attestation-tpm2     = ["dep:tss-esapi"]
attestation-sev-snp  = ["sev-snp"]
attestation-tdx      = ["tdx"]

# Confidential compute (API stubs reserved)
sev-snp         = []
tdx             = []

# Add-on system
addons-registry = []

# Dev mode (NEVER enabled in production)
dev             = []
```

### Naming conventions

- Lowercase, kebab-case, terse but descriptive.
- Backends: bare name (`firecracker`, `libkrun`).
- Categories prefixed: `metrics-*`, `egress-*`, `attestation-*`, `gpu-*`.
- Stub features for future work end with `-deferred` or are simply empty (`sev-snp = []`).
- The `dev` flag has no prefix to make it unmissable.

### Default feature set

```toml
default = ["firecracker", "libkrun", "mcp", "metrics-prometheus", "luks"]
```

(`luks` is in default because Linux is the primary deploy target; on macOS/Windows the `luks` feature compiles to a no-op runtime stub.)

### Production build incantation

```bash
cargo build --release --no-default-features \
  --features "firecracker,libkrun,mcp,metrics-prometheus,luks,egress-l7-proxy,egress-firewall-nft,attestation-tpm2"
```

**`dev` is omitted, explicitly.** Production builds with `dev` enabled fail compile via a `#[cfg(all(feature = "dev", not(debug_assertions), not(test)))] compile_error!(...)` guard (Phase 0).

### CI matrix

At minimum, three feature combinations are built per PR:
1. **Minimal**: `--no-default-features --features "libkrun"` (cross-platform sanity)
2. **Default**: `cargo build` (the developer's typical path)
3. **Full prod**: the production incantation above (the deployer's path)

Failing any of the three blocks the PR.

## Consequences

**Positive**:
- New flags inherit a clear naming + scoping convention.
- Production builds are mechanically verified to exclude `dev`.
- Feature drift (a flag that nothing uses; a flag that doesn't compile) is caught by the CI matrix.

**Negative**:
- The matrix grows the CI runtime. Mitigated by sharding on the runner pool.
- Some feature combinations may have subtle interaction bugs that only surface in specific matrix entries. Acceptable — fast feedback is the point.

## Alternatives considered

- **One mega-feature**: rejected. Loses the ability to ship a slim `libkrun`-only build.
- **Per-crate features only**: rejected. Workspace-level features with `workspace.dependencies` propagation is the idiomatic Cargo pattern.
- **Runtime config flags instead of compile-time**: rejected for `dev`. Compile-time exclusion is the only way to ensure dev paths can't be invoked in production.

## Threat model impact

The `dev` compile-time exclusion is a load-bearing security property. A subverted release pipeline cannot ship a `dev`-flagged binary because `compile_error!` makes that combination unbuildable.

## Compliance impact

- SOC 2: positive — separation of dev and prod is a documented control.
- All others: neutral.
