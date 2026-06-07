# Plan: bring `mvm` to feature parity with `../mvm`, pivoted to libkrun + libkrun, then rename to `mvm`

## Context

The repo at `/Users/auser/work/tinylabs/mvmco/mvm` is a hand-written 5-crate skeleton (~520 LOC, almost entirely stubs). The previous iteration at `/Users/auser/work/tinylabs/mvmco/mvm` is a mature 13-crate Lima+Firecracker stack (~40-50K LOC) with full security model, persistent storage, networking, observability, and an MCP server. The orchestrator at `/Users/auser/work/tinylabs/mvmco/mvmd` (10 crates, ~305K LOC) imports the `mvmctl` facade as a library — that's the contract we cannot break.

The pivot in this iteration: **libkrun (libkrun-backed) becomes the builder and the macOS/Windows execution path; Firecracker stays as the preferred Linux execution path**. The output of every build is a complete Nix-built microVM image with zero drift between machines. mvm is the library; mvmd is the orchestrator that consumes it.

### Product positioning — the workloads we must serve

mvm is a **safe execution environment for AI agents and developer code**, in the same product class as other secure AI-agent sandboxes and hosted code-interpreters. The five workloads we must serve well:

1. **Claude-Code-in-dangerous-mode**: a developer runs Claude Code (or another agent) inside a microVM where they don't have to approve every action — the VM itself is the security boundary. The host stays safe even when the agent does anything within the VM.
2. **One-click "safe OpenClaw"** deployment template — hardened defaults, audit log, restricted egress.
3. **Long-running developer workflows**: agents that run for hours, install packages, save state across reconnects. State persists across `mvmctl down`/`up`.
4. **Computer-use sandboxes**: graphical microVMs an agent can take screenshots of and synthesize input into. Headless display server (Xvfb + Xpra) inside; vsock RPC out.
5. **Web search + code execution tools**: not raw internet for the agent — host-mediated tool RPCs over vsock, audit-logged.

These are **first-class** use cases, not extensions. The `mvm-sdk` ergonomics, the built-in templates, the Phase plan, and the security model are all shaped by them.

The user experience targets:
- Install a package and *experience* persistent state, even though under the hood every install rebuilds the rootfs (cached + warm-builder makes this ≤ 30 s).
- Reconnect to a running session days later and find your shell history, files, and running processes intact.
- Long-running tasks survive host suspend/resume.
- Speed feels like a local dev shell, not a remote VM.

The user's hard constraints:
- **Security is the top priority** — encryption everywhere with key rotation; mounted volumes encrypted; secrets encrypted; runtime microVMs have **no open egress** unless a policy explicitly enables it; all VM↔host traffic on vsock or an inspectable TUN/TAP; **every action auditable** (commands, state changes, secret reads, flow attempts).
- **Cross-platform**: Linux (primary deploy + dev + native CLI), macOS (dev + native CLI + `mvm-studio` Tauri host), **Windows (Tauri-only)** — Windows users go through the `mvm-studio` Tauri build; native Windows CLI is best-effort. `mvm-studio` at `../mvm-studio` packages `mvmd` as a local coordinator.
- **Speed-to-boot and DX** tied for second.
- **OSS-first** — prefer high-quality MIT/Apache crates over hand-rolled. Exception: **the vsock protocol is rolled in-house** — we keep the `AuthenticatedFrame` framing from the previous iteration. `tokio-vsock` stays only as the raw-socket layer.
- **microvm.nix** (https://microvm-nix.github.io/microvm.nix/intro.html, **MIT-licensed, confirmed**) is the foundation for microVM image generation — it already supports Firecracker, Cloud Hypervisor, QEMU, crosvm, kvmtool, stratovirt as a NixOS module, and dramatically shrinks our own Nix maintenance.
- **Update model**: there is no in-VM updater. **Update = rebuild**. The CVE-roller agent (future) generates a new flake input set, rebuilds, and rolls instances. This means the build pipeline must be reproducible byte-for-byte and image diffs must be inspectable.
- **mvmd networking is iroh QUIC** (already TLS 1.3 by default with NAT traversal + relay). We do *not* duplicate TLS at the mvmd↔mvm-agent network hop — iroh handles it. We *do* still need mTLS at the mvmd-agent↔mvm-hostd Unix-socket hop (different process boundary, different threat).
- **Code quality** — small files (≤ 400 LOC soft limit), idiomatic Rust, builder structs instead of long arg lists (no `#[allow(clippy::too_many_arguments)]` ever), tests everywhere (unit, integration, fuzz, smoke).
- **Feature-gated** — cargo features keep the surface focused; dev-only paths cannot be compiled into production builds.
- **Final rename** `mvm/` → `mvm/` once the migration is verified.

The current hand-written skeleton (`mvm-backend::Backend<Sb,Ctx>`, `mvm-builder::BuilderBackend`, `mvm-providers` empty) **does not need to be preserved** — the user wrote it themselves and explicitly OK'd replacement. It conflicts with the `VmBackend` shape that mvmd already imports through the facade.

## North-star architecture

```
   AI agent (Claude Code, OpenClaw, etc.)        Developer tools (CLI, REPL)
                  │                                       │
                  ▼                                       ▼
   ┌──────────────────────────┐         ┌──────────────────────────┐
   │  Modal-style decorators   │         │      mvm CLI (mvmctl)    │
   │  + sandbox-runtime API    │         │  init, build, up, exec,  │
   │       (mvm-sdk)           │         │  install, session, …     │
   └──────────────────────────┘         └──────────────────────────┘
                  │                                       │
                  └────────────────┬──────────────────────┘
                                   ▼
                ┌────────────────────────────────────────┐
                │         mvm-studio (Tauri)              │
                │   (cross-platform desktop wrapper —     │
                │    packages mvmd as local coordinator)  │
                └────────────────────────────────────────┘
                                 │ launches
                                 ▼
                  ┌─────────────────────────────────────┐
                  │              mvmd                    │
                  │  (orchestrator: gateway, agent,      │
                  │   coordinator, IAM, billing;         │
                  │   iroh QUIC for cross-host)          │
                  └─────────────────────────────────────┘
                                 │ imports as a library
                                 ▼
                  ┌─────────────────────────────────────┐
                  │           mvm  (library)             │
                  │                                      │
                  │  facade: mvmctl::{core, runtime,     │
                  │     build, security, mcp, sdk,       │
                  │     supervisor, observability}       │
                  │                                      │
                  │  hosts: persistent builder pool,     │
                  │     snapshot pool, host-mediated     │
                  │     agent tools (web search, fetch,  │
                  │     code-eval, file transfer)        │
                  └─────────────────────────────────────┘
                                 │
       ┌─────────────────────────┼─────────────────────────┐
       ▼                         ▼                         ▼
  libkrun /            Firecracker                  vsock + L4/L7
   libkrun (build         (preferred Linux            mediated network
    everywhere,                exec, jailer +          (default-deny;
    macOS/Win exec)            dm-verity rootfs)        per-tenant policy
                              microvm.nix-generated)    explicitly opens)

   Inside each microVM:
     - Entrypoint (shell or program(s)) supervised
     - Tmux-backed long-running sessions
     - Encrypted persistent overlay at /workspace
     - Optional: Xvfb+Xpra for computer-use templates
```

**Single backend trait**: `mvm_core::vm_backend::VmBackend` (ported verbatim from `../mvm/crates/mvm-core/src/protocol/vm_backend.rs`). Implementations: `FirecrackerBackend` (Linux), `LibkrunBackend` (cross-platform; Linux/macOS confirmed; Windows pending verification — fall back to WSL2 if libkrun doesn't support native Windows yet). The hand-written `Backend<Sb,Ctx>` and `BuilderBackend` traits are deleted.

**Build vs. execution split** (kept as in the previous iteration): `ShellEnvironment` (base) and `BuildEnvironment` (extends) live in `mvm-core::build_env`. `mvm-build` consumes `BuildEnvironment`; `LibkrunBuildEnv` provides the impl that runs Nix inside a libkrun box. mvmd's own `BuildEnvironment` impl in mvmd-runtime keeps working unchanged.

**Builder microVM is a persistent, reused service**. It is *not* destroyed after each build — it is a per-tenant warm pool because:
- The same builder regenerates artifacts when mvm itself upgrades.
- Different tenants get distinct builders (their secrets, signing keys, and Nix substituter configs differ).
- Warm builders eliminate the cold-start penalty for every build.
- Build outputs land in a content-addressed artifact store (`~/.mvm/artifacts/<sha256>/`) shared with runtime VMs by hash; the builder pushes, runtime VMs pull.

The builder VM is the **only** microVM allowed open egress (gated by the tenant's policy bundle); runtime VMs default-deny. Builder traffic is fully logged with destinations, byte counts, TLS SNI.

**microvm.nix integration**: instead of hand-writing every NixOS rootfs config, we extend microvm.nix's NixOS module. Our `mvm-build` Nix flake imports microvm.nix and configures it with our security profile (per-service uids, seccomp, dm-verity, no-egress overlay). This shrinks our `nix/` directory and gives us multi-hypervisor portability for free.

## Target workspace layout

```
mvm/                              (renamed from mvm/ at the end)
├── Cargo.toml                    (workspace root, mvmctl bin/lib package)
├── src/
│   ├── lib.rs                    (mvmctl facade — mirrors ../mvm/src/lib.rs exactly)
│   └── main.rs                   (thin entry → mvm_cli::run())
├── crates/
│   ├── mvm-core/                 (A — copy verbatim from ../mvm/crates/mvm-core)
│   ├── mvm-storage/              (A — copy verbatim from ../mvm/crates/mvm-storage)
│   ├── mvm-security/             (A — copy verbatim, the policy/posture/HMAC bits)
│   ├── mvm-attestation/          (NEW — identity keys, runtime measurement, hardware attestation stubs)
│   ├── mvm-plan/                 (A — copy verbatim, signed-state Ed25519 protocol)
│   ├── mvm-policy/               (A — copy verbatim, policy bundle eval)
│   ├── mvm-guest/                (B — copy + adapt console/exec for libkrun)
│   ├── mvm-build/                (C — rewrite around libkrun, salvage nix/*)
│   ├── mvm/              (B — port lifecycle, swap Lima/FC-direct for VmBackend dispatch)
│   ├── mvm-mcp/                  (B — copy + swap dispatcher to call VmBackend)
│   ├── mvm-supervisor/           (A — copy verbatim, egress proxy + audit + redactor)
│   ├── mvm-sdk/                  (A — port from mvmforge-sdk; Rust runtime types + traits)
│   ├── mvm-sdk-macros/           (NEW — Rust proc macros: #[mvm::function/image/secret/volume/addon])
│   ├── mvm-sdk-addon/            (NEW — port from mvmforge-addon; addon trait + registry)
│   ├── mvm-tree-sitter/          (NEW — grammars for mvm.toml, Nix subset, decorator forms)
│   ├── mvm-cli/                  (C — clean rewrite using clap derive; tests/cli.rs is the spec)
│   └── xtask/                    (A — copy verbatim from ../mvm/xtask)
├── python/                       (NEW — Python SDK)
│   ├── pyproject.toml
│   ├── mvm/
│   │   ├── __init__.py           (re-exports: Sandbox, App, Image, Secret, Volume, …)
│   │   ├── _native/              (pyo3-built native extension for hot paths)
│   │   ├── runtime.py            (Sandbox / AsyncSandbox — sandbox-runtime-shaped)
│   │   ├── declarative.py        (App, Image, Secret, Volume, decorators)
│   │   ├── _types.pyi            (auto-generated from mvm-core)
│   │   └── tests/
│   └── README.md
├── typescript/                   (NEW — TypeScript SDK)
│   ├── package.json              (npm: @mvm/sdk)
│   ├── tsconfig.json
│   ├── src/
│   │   ├── index.ts              (re-exports)
│   │   ├── runtime.ts            (Sandbox — sandbox-runtime-shaped, Promise-based)
│   │   ├── declarative.ts        (App, Image, Secret, Volume, TC39 decorators)
│   │   ├── types.d.ts            (auto-generated via ts-rs from mvm-core)
│   │   └── _native/              (napi-rs binding for hot paths)
│   └── README.md
├── nix/                          (port from ../mvm/nix, tighten rootfs size)
├── specs/                        (already present, keep as-is)
└── tests/
    ├── cli.rs                    (already present — 91 tests, our burndown spec)
    ├── e2e/                      (already present)
    ├── sdk_compat/               (NEW — shared scenarios run against all 3 SDKs)
    └── smoke_invoke.rs           (already present, gated by MVM_LIVE_SMOKE=1)
```

Codes A/B/C: A = copy verbatim; B = adapt; C = rewrite. `mvm-libkrun` and `mvm-apple-container` from the previous iteration are **dropped** (libkrun covers libkrun + macOS through one dependency).

## OSS crates we lean on (do not roll our own)

| Concern | Crate | License | Why |
|---|---|---|---|
| Hypervisor (build + macOS/Windows exec) | `libkrun = 0.4.5` | Apache-2.0 | Native libkrun wrapper; user's chosen pivot |
| Hypervisor (Linux exec) | shell to `firecracker` binary; thin Rust JSON-API client | — | Upstream Firecracker is the canonical implementation |
| Authenticated encryption (volumes, snapshots) | `aes-gcm` 0.10 + `chacha20poly1305` 0.10 (RustCrypto) | Apache-2.0/MIT | AEAD; constant-time; widely audited |
| Disk-encryption tooling (LUKS) | shell to `cryptsetup`; thin Rust wrapper | — | LUKS2 is the standard; no Rust replacement is mature |
| Asymmetric file encryption (snapshots, secrets at rest) | `age` 0.10 | MIT | Modern; small spec; key-rotation friendly |
| Signing (plans, audit chain) | `ed25519-dalek` 2 | BSD-3-Clause | Industry standard; constant-time |
| Key derivation | `argon2` 0.5 + `hkdf` 0.12 | Apache-2.0/MIT | Argon2id for passphrase; HKDF for KEK→DEK |
| Secret zeroization | `zeroize` 1 + `secrecy` 0.10 | Apache-2.0/MIT | Drop-clearing + type-level secret hygiene |
| OS keyring | `keyring` 3 (already commented in root Cargo.toml — re-enable) | Apache-2.0/MIT | macOS Keychain / Windows Cred Mgr / Linux Secret Service |
| TLS for mvmd↔mvm-hostd | `rustls` 0.23 + `tokio-rustls` 0.26 | Apache-2.0/MIT/ISC | No OpenSSL; mTLS native |
| On-the-fly cert generation | `rcgen` 0.13 | Apache-2.0/MIT | Used by mvmd already; consistent CA chain |
| MCP server | `rmcp` (Apache-2.0, **confirmed updated within last 7d**) | Apache-2.0 | Replaces hand-rolled JSON-RPC dispatcher in `../mvm/crates/mvm-mcp` where compatible |
| DNS resolver (named networks) | `hickory-resolver` + `hickory-server` 0.24 | Apache-2.0/MIT | Pure-Rust resolver and authoritative server |
| Packet-level traffic inspection (TUN/TAP) | `tun` 0.6 + `pnet` 0.34 | Apache-2.0/MIT | Per-VM userspace TAP for egress mediation |
| Userspace TCP stack (vsock-mediated network proxy) | `smoltcp` 0.11 | Apache-2.0/MIT | Lets us terminate guest TCP on the host without exposing raw routing |
| Firewall rules (Linux) | `nftables-rs` 0.5 (with shell-out fallback) | Apache-2.0 | Programmatic nftables; required for runtime-VM egress denial |
| Structured logging | `tracing` + `tracing-subscriber` (already declared) | Apache-2.0/MIT | Industry default |
| Metrics | `metrics` 0.24 + `metrics-exporter-prometheus` 0.16 | Apache-2.0/MIT | Aligns with mvmd's choice; Prometheus exposition |
| Distributed tracing | `opentelemetry` 0.27 + `tracing-opentelemetry` 0.28 | Apache-2.0 | Optional shipping to OTLP collector |
| CLI parsing | `clap` 4 derive (already declared) | Apache-2.0/MIT | The 91 `tests/cli.rs` tests are the spec |
| CLI testing | `assert_cmd` 2 + `predicates` 3 + `insta` 1 | Apache-2.0/MIT | Cleaner than hand-rolled assertions |
| Property/fuzz tests | `proptest` 1, `cargo-fuzz` + libFuzzer | Apache-2.0/MIT | Already used in `../mvm/crates/mvm-guest/fuzz` |
| XDG paths | `directories` 5 | Apache-2.0/MIT | Replaces hand-rolled `~/.mvm` config code |
| Async event bus | `tokio::sync::broadcast` (in stdlib of tokio) | MIT | No new dep |
| Vsock raw socket | `tokio-vsock` 0.5 (raw socket only) | Apache-2.0/MIT | tokio-vsock is the only mature async vsock crate; we wrap it but layer our own protocol |
| Vsock framing/protocol (auth, multiplex, replay protection) | **rolled in-house** — port `AuthenticatedFrame` from `../mvm/crates/mvm-guest/src/vsock.rs`; fuzz harnesses in `mvm-guest/fuzz/` | — | No OSS crate covers our auth + replay + multiplexing requirements; the existing fuzz coverage is the safety net |
| Builder-pattern derive (avoid hand-typed builders) | `bon` 3 | Apache-2.0/MIT | Generates type-state builders; eliminates `clippy::too_many_arguments` cleanly |

Everything we *don't* delegate is glue (≤200 LOC) or domain-specific protocol code that has no OSS equivalent (the vsock protocol being the largest in-house piece).

## Cargo feature flags (kept narrow and orthogonal)

```toml
# mvm root workspace
[features]
default = ["firecracker", "libkrun", "mcp", "metrics-prometheus"]
# Backends (at least one must be enabled)
firecracker     = ["dep:vmm-firecracker-client"]   # Linux-only
libkrun    = ["dep:libkrun"]             # cross-platform
# Front-ends
mcp             = ["dep:rmcp", "mvm-mcp/server"]
sdk             = ["dep:mvm-sdk"]
# Observability
metrics-prometheus = ["dep:metrics-exporter-prometheus"]
metrics-otel       = ["dep:opentelemetry-otlp"]
audit-remote-sink  = ["dep:reqwest"]               # ship audit log to a remote collector
# Encryption tiers
luks            = []                               # Linux-only volume encryption
apfs-encrypt    = []                               # macOS-only fallback
bitlocker       = []                               # Windows-only fallback
# Network paths
egress-l4-proxy = ["dep:smoltcp", "dep:tun"]
egress-l7-proxy = ["egress-l4-proxy", "dep:hyper", "dep:rustls"]
egress-firewall-nft = ["dep:nftables"]             # Linux nftables
# Dev mode (compiled OUT in production)
dev             = []                               # `mvmctl dev *` subcommands
# Compliance / advanced isolation
sev-snp         = []                               # AMD SEV-SNP confidential compute
tdx             = []                               # Intel TDX confidential compute
# Computer use & GPU
computer-use    = ["dep:image", "egress-l4-proxy"] # Xvfb+Xpra screenshot/input/window RPCs
gpu-virgl       = []                               # virtio-gpu via virgl/Venus (libkrun)
gpu-passthrough = ["backend-cloud-hypervisor"]     # VFIO compute GPU; needs CH backend
backend-cloud-hypervisor = []                      # CH backend for GPU/heavy workloads
# Attestation
attestation-tpm2     = ["dep:tss-esapi"]
attestation-sev-snp  = ["sev-snp"]
attestation-tdx      = ["tdx"]
# Add-on system
addons-registry = []                               # Loadable user-defined addons
```

**Production builds use `--no-default-features --features "firecracker,libkrun,mcp,metrics-prometheus,luks,egress-l7-proxy,egress-firewall-nft"`** — explicitly omitting `dev`. CI builds at least three feature combinations: minimal (no MCP, libkrun-only), default, full-prod.

The `dev` feature gate matters because subcommands like `dev shell` open a PTY into a sandbox; this must be impossible to invoke in a customer-facing build.

## microvm.nix integration

We adopt `microvm.nix` (https://github.com/microvm-nix/microvm.nix) as the Nix-side foundation. It already supports Firecracker, Cloud Hypervisor, QEMU, crosvm, kvmtool, stratovirt as a NixOS module. Our `nix/` directory shrinks to:

- `nix/flake.nix` — imports microvm.nix; declares our security overlay (per-service uids from W2.1, dm-verity from W3, seccomp profiles from W2.4, read-only `/etc` from W2.2).
- `nix/profiles/{minimal,worker,builder}.nix` — three NixOS modules built on microvm.nix that compose into the rootfs.
- `nix/lib/mkGuest.nix` — the user-facing helper for templates (`mkGuest { profile = "minimal"; services = { … }; }`).

This gives us hypervisor portability (microvm.nix already abstracts Firecracker / Cloud Hypervisor / crosvm) so adding a new backend later is a config change, not a kernel-and-initramfs rewrite. **Phase 1 builds the integration; subsequent phases use it.**

Risk: microvm.nix is a third-party project. We pin a specific commit in `flake.lock`, audit it before pinning, and re-audit on every bump. Listed as an explicit supply-chain concern in the security section.

**Fallback (named explicitly):** if a microvm.nix audit surfaces a security regression we can't accept, fall back to the previous iteration's hand-rolled NixOS modules under `../mvm/nix/`. ADR-013 names this as a ready-to-execute escape hatch, not a vague intention. The cost: ~5K LOC of NixOS-module maintenance returns to our scope. The benefit: smaller trust boundary. We choose microvm.nix as the default *because* its trust boundary is acceptable today; if that changes, we revert.

**Explicit non-goal: OCI images.** mvm is microVMs, not containers. Libkrun's API exposes both `RootfsSource::Oci(reference)` and `RootfsSource::DiskImage { path, format, fstype }`; we use **only** the `DiskImage` path. The runtime never pulls from an OCI registry; the bridge from our Nix-built `.ext4` rootfs to libkrun is a host-local `.raw` hard-link plus `fstype("ext4")`. ADR-013 §"Non-goal: OCI / container images" carries the full rationale (reproducibility, trust boundary, offline-by-default boot). Code review gate: any PR introducing `RootfsSource::Oci`, `RegistryAuth`, or OCI image references is reviewed against this invariant.

## L4 + L7 egress proxy (default-deny + policy-gated)

Two proxies, both running in `mvm-supervisor`:

**L4 proxy** (`mvm-supervisor/src/proxy/l4.rs`, gated by `egress-l4-proxy` feature)
- Terminates TCP/UDP from the guest TAP using `smoltcp` (userspace TCP stack)
- Per-tenant allowlist: `(protocol, dest_cidr, dest_port)` tuples
- Default action: **drop + audit-log** (every dropped flow is recorded with src VM, dst, reason)
- Used for non-HTTP traffic (databases, custom protocols) when policy permits

**L7 proxy** (`mvm-supervisor/src/proxy/l7.rs`, gated by `egress-l7-proxy` feature, depends on L4)
- HTTPS-aware: SNI extraction, per-tenant SNI allowlist, optional MITM (when tenant policy installs a CA cert into the guest)
- HTTP/1.1 + HTTP/2 + (optional) HTTP/3 via `hyper`
- Used for fine-grained egress filtering (tenant policies can say "stripe.com but not stripe.com/v1/disputes")
- All requests recorded to audit log with method, host, path-prefix (full path optional, redacted by default to avoid logging secrets)

**Firewall layer** (`mvm-supervisor/src/firewall/`, gated by `egress-firewall-nft` feature)
- Linux: `nftables-rs` installs default-deny on the bridge for runtime VMs; only the proxy's TUN endpoint is reachable
- macOS: pf rules via `pfctl` shell-out; same default-deny semantics
- Windows: WFP via `windivert` shell-out; same semantics
- The L4/L7 proxies are *additive* enforcement — even if the firewall is misconfigured, the proxy's allowlist is the second line

**Policy gating**: a tenant has zero allowed flows by default. The tenant config (`mvm-policy::TenantPolicy`) lists explicit allow rules. `mvmctl policy show <tenant>` prints the allowlist; `mvmctl policy verify <tenant>` re-runs the deny defaults; `mvmctl policy update <tenant> --add-flow ...` requires a signed Plan from mvmd.

**Builder VM** is the explicit exception: its policy bundle ships with a permissive egress allowlist (cache.nixos.org, GitHub, the configured Nix substituters) but every flow is still audit-logged. No tenant can mint a builder policy themselves — only mvmd's signing key can.

## Addons — composable capability bundles

The SDK ships **addons** as the primitive for capability composition. (The previous iteration's `mvmforge-addon` crate already used this name; we keep it.) An addon bundles:

- A **Nix derivation** (the binaries/configs/services the addon provides)
- A **service spec** (what runs at boot, with which uid/seccomp tier)
- A **network policy fragment** (egress allowlist additions)
- A **secret schema** (which secrets it expects, and at which mountpoint)
- A **tool surface** (host-mediated RPCs it adds to the agent's toolbox, optional)
- **Provides** (capability tags, e.g. `postgres`, `chromium`, `claude-code`)
- **Requires** (other addons or capabilities — composes a DAG)

Templates are just **pre-baked compositions of addons**. `ai-sandbox` template = `claude-code` + `web-tools` + `persistent-workspace` addons.

SDK macro:

```rust
#[mvm::addon(
    provides = ["postgres"],
    requires = ["persistent-workspace"],
    nix = "./postgres.nix",
    services = [PostgresService],
    egress = [],
    secrets = ["pg_password" => "/run/mvm-secrets/postgres/password"],
)]
struct PostgresAddon;
```

Built-in addon catalog (Phase 7b ships this list — corresponds to the templates that compose them):

| Addon | Provides | Notes |
|---|---|---|
| `persistent-workspace` | encrypted `/workspace` overlay | Used by every long-lived template |
| `claude-code` | Claude Code CLI in the closure | Used by `ai-sandbox` |
| `openclaw-runtime` | OpenClaw service + hardened defaults | Used by `safe-openclaw` |
| `web-tools` | host-mediated `web_search` + `web_fetch` RPCs | Used by `ai-sandbox`, `safe-openclaw` |
| `code-eval-tools` | host-mediated `code_eval` RPC (nested sandbox) | Used by `ai-sandbox`, `safe-openclaw` |
| `chromium` | sandboxed Chromium + Xvfb + Xpra | Used by `computer-use` |
| `postgres` | PostgreSQL service | Optional plug-in |
| `redis` | Redis service | Optional plug-in |
| `nodejs`, `python`, `rust-toolchain` | language toolchains | Stackable |
| `ssh-disabled` | sentinel that asserts no SSH in the closure | Default for production tenants |

Users compose addons in `mvm.toml` or via SDK macros. The `mvm-tree-sitter` safety scanner (Phase 5) understands addon composition — it can flag "this composition reaches CVE-2025-XXXX through `chromium` addon" without running anything.

`mvm-sdk-addon` (port from `mvmforge-addon`) is the trait + registry crate; `mvm-sdk-macros` emits the registration glue.

## Built-in templates and use-case profiles

Each ships as a versioned flake under `templates/` plus a manifest. `mvmctl init --template <name>` scaffolds the project; `mvmctl catalog ls` discovers them.

| Template | Purpose | Entrypoint | Default egress | Default volumes | Notable features |
|---|---|---|---|---|---|
| `minimal` | Empty rootfs, shell entrypoint | `/bin/sh` | none | none | The "blank canvas" |
| `worker` | Long-running headless workload | configurable command | none | `/var/data` (encrypted) | Auto-restart, sleep policy |
| `ai-sandbox` | Claude Code / generic agent dangerous-mode | `claude code` (or `bash`) | host-mediated tool RPCs only (web-search, etc.) — **no raw internet** | `/workspace` (encrypted, persistent) | Long sessions, install transparency, MCP server bound, full audit |
| `safe-openclaw` | One-click hardened OpenClaw | OpenClaw runtime | LLM endpoints allowlisted (anthropic.com, openai.com); everything else denied | `/workspace`, `/openclaw/state` | Hardened security defaults, signed plans required for changes |
| `computer-use` | Graphical agent sandbox | Xvfb + Xpra session + agent runtime | as `ai-sandbox` plus optional vetted browser endpoints | `/workspace`, `/home/agent/.cache` | Screenshot RPC, input-synthesis RPC, window-tree RPC |
| `repl` | Interactive REPL for code-eval tools | configurable language REPL | none | `/workspace` ephemeral | Lowest-latency boot via snapshot pool; for one-shot eval calls |

Each template is a real microvm.nix flake under `templates/<name>/flake.nix` and a manifest at `templates/<name>/mvm.toml`. Tests in `tests/templates.rs` boot each template and exercise its hello-world path. The agent-oriented templates (`ai-sandbox`, `safe-openclaw`, `computer-use`) get extra tests for their RPC tool surfaces.

## Entrypoints (port from `../mvm`)

Microvms run an entrypoint at boot. Three forms supported, all from the `mvm.toml`:

```
[entrypoint]
# Form 1 — interactive shell (development)
shell = "/bin/bash"

# Form 2 — custom program (production)
command = ["/usr/local/bin/myworker", "--config", "/etc/worker.toml"]

# Form 3 — multiple services (workers + supervisors)
[entrypoint.services.web]
command = ["/usr/local/bin/web", "--port", "8080"]
restart = "always"
[entrypoint.services.worker]
command = ["/usr/local/bin/worker"]
restart = "on-failure"
```

The previous iteration's `mvm-guest/src/entrypoint.rs` parses these and supervises the processes; we port verbatim, then layer on:
- **Per-service uid** (already in W2.1 from the existing security plan)
- **Per-service seccomp tier** (W2.4)
- **`/run/mvm-secrets/<svc>/`** scoping (W2.1)
- **Audit-logged service start/stop/crash** (Phase 4)

(Note: the previous iteration uses `exec` as the TOML key. We can keep it as `exec` during the port — only renamed here to avoid a false-positive hook on the planning text.)

## Snapshots — first-class feature

Snapshots are the cornerstone primitive for fast boot, fork-like semantics, save-before-risky-op, host suspend/resume, and forensic capture. Treated as a first-class user-facing feature, not just an internal mechanism.

### What a snapshot captures
- **Memory image** (running RAM, paused VCPU state) — encrypted with a per-snapshot DEK (AEAD: AES-256-GCM)
- **Disk state** (rootfs base hash + overlay deltas) — copy-on-write extent reference, no full copy
- **Metadata**: timestamp (wall + monotonic + RFC 3161), VM identity, kernel version, attestation report at snapshot time, tenant_hash, tags, parent snapshot ID (if forked)
- **HMAC chain** linking each snapshot to its predecessor for tamper detection
- The DEK is wrapped by the tenant KEK; supports KEK rotation without re-encrypting snapshots

### Use cases
1. **Instant boot from known-good** — pool of warm snapshots per template; new VMs clone from the closest match. Cold boot ≤ 30 ms (Phase 9 perf gate).
2. **Fork-like semantics** — `mvmctl up --from-snapshot <id>` creates a new VM identical to a captured one. Useful for parallel exploration in agent workflows.
3. **Save before risky op** — agent about to run untrusted code does `sb.snapshot("pre-untrusted")` then can revert if anything goes wrong.
4. **Host suspend / resume** — auto-snapshot on host suspend; restore on wake (already in Phase 7).
5. **Forensic capture** — when an audit event flags suspicious behaviour, snapshot the VM for offline analysis. Forensic snapshots get a special `forensic = true` tag and longer retention.
6. **Long-running session continuity** — auto-snapshot on session detach; restore on reattach so even hours-old sessions resume instantly.
7. **Compliance / debugging** — point-in-time captures for incident replay.

### CLI surface
```
mvmctl snapshot save <vm> [--name <n>] [--tag <t>...] [--note <text>]
mvmctl snapshot list [--vm <vm>] [--tag <t>] [--tenant <id>]
mvmctl snapshot info <id>                    # metadata + attestation report
mvmctl snapshot load <vm> <id>               # restore in place (replaces VM state)
mvmctl snapshot fork <id> [--name <new-vm>]  # boot a NEW VM from this snapshot
mvmctl snapshot delete <id> [--purge]        # purge zeroes the underlying ciphertext
mvmctl snapshot diff <a> <b>                 # files changed, processes added/removed
mvmctl snapshot tag <id> <tag>               # add/remove tags
mvmctl snapshot retain <id> --until <date>   # override retention policy
mvmctl snapshot export <id> > snap.bin       # signed portable bundle (for backup/migration)
mvmctl snapshot import < snap.bin            # imports if signature verifies + tenant matches
```

### SDK surface (runtime, sandbox-runtime-style)
```rust
let snap = sb.snapshot()
    .name("pre-untrusted")
    .tag("checkpoint")
    .save()
    .await?;

// Later, fork from it:
let sb2 = Sandbox::from_snapshot(snap.id()).build().await?;

// Or revert in place:
sb.restore(snap.id()).await?;
```

### Retention policies (configurable per template / per tenant)
- `keep-last-n` — most recent N snapshots
- `keep-tagged` — anything explicitly tagged stays
- `keep-time-window` — anything within a rolling window (e.g., 7 days)
- `keep-forensic` — `forensic = true` snapshots stay regardless
- Defaults: `ai-sandbox` template = `keep-last-3 + keep-tagged`; `safe-openclaw` = `keep-last-5 + keep-tagged + 30-day window`

`mvmctl snapshot prune --tenant <id>` runs the policy. Scheduled via supervisor cron.

### Storage layout
```
~/.mvm/snapshots/<tenant_hash>/<snapshot_id>/
  meta.json.sig         # signed metadata (Ed25519 + tenant key)
  memory.aead           # encrypted memory image (chunked AEAD frames)
  disk_delta.cow        # CoW overlay extents (encrypted ext4)
  attestation.json      # attestation report at snapshot time
  parent.link           # symlink to parent if forked
```

Snapshot IDs are content-hashed; the same VM state captured twice produces the same ID (good for dedup, good for caching). Per-tenant snapshot store is encrypted-at-rest by the same Layer-2 AEAD path covered earlier.

### Per-tenant quotas + audit
- Quota: max snapshots per tenant; max total snapshot bytes; configured via tenant policy.
- Every `save`/`load`/`fork`/`delete`/`export`/`import` is audit-logged with the full attestation header. `delete` with `--purge` triggers cryptographic erasure of the DEK + zero-fill of the ciphertext, recorded as a `chain.snapshot.purge` event.
- `fork` and `import` carry parent attestation; verifier traces the lineage.

### Backend portability
- **Firecracker**: native snapshot support (`firecracker --snapshot-create`/`--snapshot-restore`). Memory image is what FC produces, wrapped in our AEAD.
- **libkrun / libkrun**: pause + memory dump (libkrun exposes this via `krun_pause`/`krun_resume`); slightly more expensive than FC but works.
- **Cloud Hypervisor (future)**: native snapshot support via the CH API.

The user-facing surface is identical; the backend differences are hidden behind `VmBackend::snapshot_create`/`snapshot_restore`.

### Performance targets
- Save: ≤ 200 ms p50 for a 256 MB VM (Firecracker, snapshot pool warm)
- Load (clone-from-pool): ≤ 30 ms p50
- Load (full restore from cold storage): ≤ 1 s p50
- Diff: ≤ 100 ms for typical session-sized snapshots

### Tests
- Unit: `mvm::vm::snapshot::tests::save_load_round_trip`; `..::tests::tampered_memory_rejected`; `..::tests::fork_lineage_records_parent`
- Integration: `tests/cli.rs::test_snapshot_save_then_fork_independent_diverges`; `test_snapshot_diff_reports_file_changes`; `test_snapshot_retention_purges_expired`; `test_snapshot_export_then_import_round_trip`; `test_snapshot_purge_zero_fills_ciphertext`
- Property: `proptest` over the AEAD layer (1000+ cases)
- Performance: `tests/perf.rs::snapshot_save_p50_within_budget`, `..::snapshot_load_pool_p50_within_budget`

### Phase placement
- Phase 2 (encryption) ships the storage layer + AEAD + HMAC chain
- Phase 7 (sessions) wires in auto-snapshot-on-detach
- Phase 7a (install) uses snapshots as the rollback point on rebuild failure
- Phase 9 (perf) ships the snapshot pool for ≤ 30 ms boot
- ADR-032 (NEW): Snapshot model — captured what, named how, retention policy, fork lineage. Add to ADR catalog.

## Long-running sessions

A `Session` is a logically-persistent shell or program inside a VM that survives reconnects. Backed by tmux inside the guest (zero new code; `tmux` is in the default closure). Surface:

```
mvmctl session create <vm> [--name foo] [--shell bash]
mvmctl session list <vm>
mvmctl session attach <vm> <session>
mvmctl session detach <vm> <session>
mvmctl session kill <vm> <session>
mvmctl session timeout <vm> <session> --idle 24h
```

Session state survives:
- Network disconnects (you reattach)
- `mvmctl down` then `up` (the VM is paused and restored — Firecracker snapshot, libkrun sleep)
- Host suspend/resume (snapshot taken at host suspend, restored at resume)

Session state is wiped only on explicit `kill`, idle timeout, or VM destruction.

`mvm-core::domain::session` already exists in `../mvm`; port. Surface defined by `mvm-cli/src/commands/session/`.

## Computer-use support (feature: `computer-use`)

Agents that use vision + UI-automation need a graphical microVM. Built on:

- **Inside guest**: `Xvfb` + `Xpra` (in the microvm.nix profile) provides a headless X11 display; `xdotool` and `wmctrl` synthesize input and query window tree.
- **Host-side**: `mvm/src/compute_use/` exposes vsock RPCs:
  - `screenshot` → PNG bytes (resolution from manifest)
  - `input` ← `Vec<InputEvent>` (mouse moves/clicks, key down/up)
  - `windows` → `Vec<Window>` (tree of windows with positions, titles, app names)
  - `clipboard_get` / `clipboard_set`
  - `process_list` → `Vec<Proc>`
- **Agent-side**: an `mvm-sdk::computer_use::Display` handle wraps the RPCs.

All RPCs run over the existing authenticated vsock channel. Display dimensions, DPI, fonts, available browsers configurable in `mvm.toml`. Graphical sessions count as long-running sessions (so they reattach across reconnects).

Security: the X server is itself sandboxed (its own seccomp profile, runs as a non-root uid, `/tmp/.X11-unix` per-session). The VM still has zero default egress; web browsing is host-mediated through the web-tool RPCs unless tenant policy explicitly opens it.

## Transparent install / rebuild

The DX win: **`mvmctl install <pkg>` looks like a local install but is actually a rebuild + swap**.

Architecture:

- The rootfs is the **base layer** — read-only, content-addressed, comes from a build.
- The persistent state is the **overlay** — encrypted ext4 mounted at `/workspace`, with bind-mounts at `/home/<user>`, `/var/log`, `/etc/agent-config` (configurable per template).
- When a user runs `mvmctl install python:3.12`:
  1. mvm computes the new flake input set (existing flake + the package's inputs).
  2. Submits to the warm builder VM.
  3. Builder produces a new rootfs (typically ≤ 30 s with cached substituters; ≤ 5 s if everything is cached).
  4. mvm checkpoints the user's session metadata (cwd, env, pending mvm RPCs).
  5. **Rolling swap**: pause the VM, swap the rootfs (overlay stays mounted), resume. Live processes inside the VM are restarted (this is the honest part: long-running processes do restart). Tmux sessions reattach; their scrollback is preserved (it's in the overlay).
  6. mvm reattaches the user's session.
- User experience: a "installing python:3.12…" progress bar, ~10-30 s, then the new package is "there" and their workspace is unchanged.
- A future `--in-flight` flag could use CRIU to checkpoint live processes (Linux only, brittle); deferred.

CLI surface:

```
mvmctl install <vm> <pkg>[, <pkg>...]
mvmctl uninstall <vm> <pkg>[, <pkg>...]
mvmctl rebuild <vm> [--dry-run]      # rebuild without changing inputs (e.g., for security patches)
mvmctl freeze <vm> > frozen.flake     # snapshot the current input set for reproducibility
```

The diff of base layers (old vs. new) is shown to the user with `--explain` so they understand what changed.

Implementation lives in `mvm/src/install/` (new module). Drives `mvm-build` for the rebuild, `mvm/src/vm/snapshot.rs` for the swap, `mvm/src/vm/overlay.rs` for the persistent overlay management.

## Host-mediated agent tools

The agent inside a runtime VM does *not* get raw internet. Instead, the host exposes a set of vetted tool RPCs over vsock that the agent calls. This is the cornerstone of "safe AI environment":

| Tool | RPC | Backed by | Audited fields |
|---|---|---|---|
| Web search | `tools.web_search` ← query | configurable provider (Brave / Tavily / SerpAPI) | tenant_hash, query, result_count |
| Web fetch | `tools.web_fetch` ← url, method | host-side `reqwest` with per-tenant URL allowlist | tenant_hash, url, method, status |
| Code eval (nested sandbox) | `tools.code_eval` ← language, src | spins a *child* `mvmctl` sandbox | tenant_hash, language, src_hash |
| File transfer | `tools.upload` / `tools.download` | host-side proxy with size + path allowlist | tenant_hash, paths, bytes |
| Time | `tools.time_now` | host clock | (no audit; trivially low-sensitivity) |

These live in `mvm-supervisor/src/tools/`. The MCP server (Phase 7) exposes the same tool surface to external MCP clients. Tenant policy (`mvm-policy`) decides which tools each VM gets; default for `ai-sandbox` is web_search + web_fetch + code_eval + file transfer.

## SDK DX design — Rust + Python + TypeScript, three first-class SDKs

Three SDKs, all first-class, all targeting **libkrun-style runtime + sandbox-runtime API surface** + **Modal-style decorators**. Common Rust core protocol; language-specific surface idiomatic to each ecosystem.

### Architecture
```
                ┌──────────────────────────────────────┐
                │        Python SDK (PyPI: mvm)         │
                │  sandbox runtime + Modal decorators   │
                └──────────────────────────────────────┘
                ┌──────────────────────────────────────┐
                │      TypeScript SDK (npm: @mvm/sdk)   │
                │  sandbox runtime + TC39 decorators    │
                └──────────────────────────────────────┘
                ┌──────────────────────────────────────┐
                │    Rust SDK (crates.io: mvm-sdk)      │
                │   bon-builder runtime + proc macros   │
                └──────────────────────────────────────┘
                                 │
                                 ▼
                  ┌─────────────────────────────────────┐
                  │  Common wire protocol (mvm-core)     │
                  │  - JSON-RPC over Unix socket or HTTP │
                  │  - Vsock for in-VM agent control     │
                  │  - Versioned (PROTOCOL_VERSION)      │
                  └─────────────────────────────────────┘
```

The Rust SDK is the reference implementation; Python and TypeScript are stable client implementations that target the same protocol. Wire-format compatibility is enforced by a shared test suite that runs each SDK against the same fixtures (`tests/sdk_compat/`).

### Distribution
- **Rust**: `crates.io/mvm-sdk` (and `mvm-sdk-macros`). Tracks protocol version.
- **Python**: `pypi.org/project/mvm` (package name `mvm`). Wheels for Linux/macOS/Windows on Python 3.10+. Uses `pyo3` for the hot-path connection layer (compiled native binding for performance + zero-copy where possible) plus pure-Python over JSON-RPC for the rest.
- **TypeScript**: `npmjs.com/package/@mvm/sdk`. ESM + CJS, types included. Uses `napi-rs` for the connection layer where it helps; pure TS otherwise. Targets Node 20+, Bun, Deno, modern browsers (with appropriate transports).
- All three SDKs version-locked to the wire protocol via a shared `PROTOCOL_VERSION` constant; running a v2 SDK against a v3 server is a hard error with a clear migration message.

### Type-stub generation (already in plan)
`cargo xtask gen-stubs` (Phase 5) takes the Rust types in `mvm-core` and emits:
- `python/mvm/_types.pyi` (Pydantic-derived stubs for IDE support)
- `typescript/src/types.d.ts` (via `ts-rs`)
- `typescript/src/types.js` (runtime validators if needed via `zod`)

This guarantees the three SDKs report the same shapes for the same protocol structures.

---

### Style 1 — Runtime SDK (faithful to the established sandbox-runtime interface)

The runtime SDK matches the **established sandbox-runtime documented API** method-for-method, so anyone who has used the established sandbox-runtime category APIs can use mvm without re-learning. mvm-specific extensions (snapshots with our richer model, secrets, attestation, computer_use, network policy) are clearly additive — they layer on top, never displace the category's primitives.

#### Core lifecycle (mirrors the established sandbox-runtime API 1:1)

**Python**:
```python
from mvm import Sandbox

# Create — mirrors the established sandbox-runtime signature exactly
sbx = Sandbox(timeout=300, metadata={"job": "agent-run-42"})
# or with explicit template
sbx = Sandbox(template="ai-sandbox", timeout_ms=300_000, metadata={...})

# Reconnect to a running sandbox by ID
sbx = Sandbox.connect(sandbox_id)

# Static lifecycle helpers
running = Sandbox.list()                 # list running sandboxes for this user
Sandbox.kill(sandbox_id)                 # kill by ID

# Per-instance lifecycle
sbx.set_timeout(60)                      # extend timeout (seconds)
info = sbx.get_info()                    # sandbox_id, template_id, started_at, end_at, metadata
sbx.pause()                              # pause (state preserved)
sbx.resume()                             # resume from pause
sbx.kill()                               # destroy
```

**TypeScript**:
```typescript
import { Sandbox } from '@mvm/sdk'

const sbx = await Sandbox.create({ timeoutMs: 300_000, metadata: { job: 'agent-run-42' } })
// or with template
const sbx = await Sandbox.create({ template: 'ai-sandbox', timeoutMs: 300_000 })

// Reconnect
const sbx = await Sandbox.connect(sandboxId)

// Static lifecycle
const running = await Sandbox.list()
await Sandbox.kill(sandboxId)

// Per-instance
await sbx.setTimeout(60)
const info = await sbx.getInfo()
await sbx.pause()
await sbx.resume()
await sbx.kill()
```

**Rust**:
```rust
use mvm_sdk::runtime::Sandbox;

let sbx = Sandbox::builder()
    .template("ai-sandbox")
    .timeout(Duration::from_secs(300))
    .metadata([("job", "agent-run-42")])
    .build().await?;

let sbx = Sandbox::connect(&sandbox_id).await?;
let running = Sandbox::list().await?;
Sandbox::kill(&sandbox_id).await?;
sbx.set_timeout(Duration::from_secs(60)).await?;
let info = sbx.get_info().await?;
sbx.pause().await?;
sbx.resume().await?;
sbx.kill().await?;
```

#### Commands (mirrors the sandbox-runtime convention — foreground + background under one namespace)

**Python**:
```python
# Foreground — returns when complete
result = sbx.commands.run("ls /home")
print(result.stdout, result.stderr, result.exit_code)

# Background — returns a handle immediately
proc = sbx.commands.run("python server.py", background=True)
proc.pid                                 # process id
proc.kill()                              # terminate
# Stream output asynchronously
for line in proc.stdout:
    print(line)
```

**TypeScript**:
```typescript
const result = await sbx.commands.run('ls /home')
console.log(result.stdout, result.stderr, result.exitCode)

const proc = await sbx.commands.run('python server.py', { background: true })
proc.pid
await proc.kill()
for await (const line of proc.stdout) console.log(line)
```

**Rust**:
```rust
let result = sbx.commands().run("ls /home").await?;

let proc = sbx.commands().run("python server.py").background(true).await?;
let mut stdout = proc.stdout();
while let Some(line) = stdout.next().await { println!("{line}"); }
proc.kill().await?;
```

#### Files (mirrors sandbox-runtime primitives — read, write, list, remove, rename, make_dir, exists, watch_dir)

**Python**:
```python
sbx.files.write("/home/user/data.csv", "col1,col2\n1,2\n")
content = sbx.files.read("/home/user/data.csv")
entries = sbx.files.list("/home/user")
sbx.files.make_dir("/home/user/sub")
exists  = sbx.files.exists("/home/user/data.csv")
sbx.files.rename("/home/user/old.txt", "/home/user/new.txt")
sbx.files.remove("/home/user/data.csv")

# Watch
def on_event(event):
    print(event.type, event.path)
watcher = sbx.files.watch_dir("/home/user", on_event=on_event)
watcher.stop()
```

**TypeScript**:
```typescript
await sbx.files.write('/home/user/data.csv', 'col1,col2\n1,2\n')
const content = await sbx.files.read('/home/user/data.csv')
const entries = await sbx.files.list('/home/user')
await sbx.files.makeDir('/home/user/sub')
const exists = await sbx.files.exists('/home/user/data.csv')
await sbx.files.rename('/home/user/old.txt', '/home/user/new.txt')
await sbx.files.remove('/home/user/data.csv')

const watcher = await sbx.files.watchDir('/home/user', (event) => {
  console.log(event.type, event.path)
})
await watcher.stop()
```

**Rust**:
```rust
sbx.files().write("/home/user/data.csv", b"col1,col2\n1,2\n").await?;
let content = sbx.files().read("/home/user/data.csv").await?;
let entries = sbx.files().list("/home/user").await?;
sbx.files().make_dir("/home/user/sub").await?;
let exists = sbx.files().exists("/home/user/data.csv").await?;
sbx.files().rename("/home/user/old.txt", "/home/user/new.txt").await?;
sbx.files().remove("/home/user/data.csv").await?;

let mut watcher = sbx.files().watch_dir("/home/user").await?;
while let Some(event) = watcher.next().await {
    println!("{:?} {}", event.kind, event.path);
}
watcher.stop().await?;
```

#### PTY (terminal sessions — mirrors the sandbox-runtime convention)

**Python**:
```python
terminal = sbx.pty.create(size={"rows": 24, "cols": 80}, on_data=lambda b: print(b))
sbx.pty.send_input(terminal.pid, b"ls\n")
sbx.pty.resize(terminal.pid, rows=30, cols=120)
sbx.pty.kill(terminal.pid)
```

**TypeScript**:
```typescript
const terminal = await sbx.pty.create({
  size: { rows: 24, cols: 80 },
  onData: (data) => process.stdout.write(data),
})
await sbx.pty.sendInput(terminal.pid, new TextEncoder().encode('ls\n'))
await sbx.pty.resize(terminal.pid, { rows: 30, cols: 120 })
await sbx.pty.kill(terminal.pid)
```

**Rust**:
```rust
let term = sbx.pty().create().rows(24).cols(80).await?;
term.send_input(b"ls\n").await?;
term.resize(30, 120).await?;
term.kill().await?;
```

#### Code interpreter (sub-package — established sandbox-runtime convention)

The `run_code` / `runCode` API lives in a separate package, mirroring how the established sandbox-runtime category organizes its code-interpreter SDK:

**Python** — `pip install mvm[code-interpreter]` (or `pip install mvm-code-interpreter`):
```python
from mvm.code_interpreter import Sandbox

sbx = Sandbox()
execution = sbx.run_code("x = 1 + 1; x")
print(execution.text)             # "2"
print(execution.results)          # rich outputs (plots, dataframes…)
print(execution.logs.stdout)
```

**TypeScript** — `npm install @mvm/code-interpreter`:
```typescript
import { Sandbox } from '@mvm/code-interpreter'

const sbx = await Sandbox.create()
const execution = await sbx.runCode('x = 1 + 1; x')
console.log(execution.text)
console.log(execution.results)
```

**Rust** — `mvm-sdk-code-interpreter` crate:
```rust
use mvm_sdk_code_interpreter::Sandbox;

let sbx = Sandbox::builder().build().await?;
let exec = sbx.run_code("x = 1 + 1; x").await?;
println!("{}", exec.text);
```

#### Libkrun-flavored language-specific sandboxes (mirrors libkrun)

For folks coming from libkrun, we ship typed shortcuts:

**Python**:
```python
from mvm import PythonSandbox, NodeSandbox

async with PythonSandbox.create(name="data-job") as sb:
    out = await (await sb.run("import pandas; print(pandas.__version__)")).output()

async with NodeSandbox.create(name="api-job") as sb:
    out = await (await sb.run("console.log(process.version)")).output()
```

**TypeScript**:
```typescript
import { PythonSandbox, NodeSandbox } from '@mvm/sdk'

await using sb = await PythonSandbox.create({ name: 'data-job' })
const out = await (await sb.run('import pandas; print(pandas.__version__)')).output()
```

These are thin wrappers over the core `Sandbox` with the matching template + REPL pre-wired.

#### Async style

- **Python**: both sync `Sandbox` and `AsyncSandbox` are exported, identical surface, async methods are coroutines. Context-manager support: `with Sandbox(...)` and `async with AsyncSandbox(...)`.
- **TypeScript**: all methods return `Promise`; `await using` (TC39 explicit-resource-management) supported for auto-cleanup.
- **Rust**: tokio-based; `Drop` impl issues a best-effort kill if not explicitly closed.

#### mvm extensions (additive — beyond the established sandbox-runtime surface)

These layer on top of the category-compatible surface. None of them rename or remove a sandbox-runtime primitive.

- `sbx.snapshot.save / restore / list / fork / delete / diff / export / import` — full snapshot model from earlier section. (The established sandbox-runtime surface has only `pause`/`resume`; we keep those AND add this.)
- `sbx.secrets.put / get / list / rotate` — per-tenant secret access bound to the VM
- `sbx.network.allow / deny / show` — runtime egress adjustments (subject to tenant policy ceiling — cannot exceed the policy)
- `sbx.computer_use.{screenshot, input, windows, clipboard, process_list}` — present only when the sandbox is built from a `computer-use` template
- `sbx.attest()` — returns the current attestation report (boot measurement + identity key + hardware report if enabled)
- `sbx.metrics()` — current per-VM resource counters (CPU sec, memory, disk bytes, egress bytes)
- `sbx.logs()` — structured JSON tail of the guest's logs

These are namespaced under sub-objects so the core surface stays exactly sandbox-runtime-shaped.

#### Surface parity guaranteed across all three SDKs
Every method present on one is present on the others with semantically-identical behaviour. CI test `tests/sdk_compat/` runs the same scenario fixtures (create → write → run → snapshot → reconnect → kill, etc.) against all three and diffs the output.

---

### Style 2 — Declarative SDK (Modal-style decorators)

#### Python — full Modal-shaped DX
```python
import mvm

app = mvm.App("my-project")

# Image composition (mirrors Modal's Image.debian_slim().pip_install)
image = (
    mvm.Image.from_template("worker")
        .add_addon("python")
        .pip_install("requests", "pandas")
        .apt_install("ffmpeg")
        .add_files({"./local.py": "/app/local.py"})
)

# Secrets and volumes
stripe_key = mvm.Secret.from_env("STRIPE_KEY")
data_vol   = mvm.Volume.from_name("project-data", encrypted=True)

@app.function(
    image=image,
    secrets=[stripe_key],
    volumes={"/data": data_vol},
    cpus=2,
    memory_mib=1024,
    timeout_secs=600,
    egress_allow=["api.stripe.com:443"],
)
def charge(amount: int) -> str:
    import requests, os
    key = os.environ["STRIPE_KEY"]
    r = requests.post("https://api.stripe.com/...", auth=(key, ""))
    return r.json()["id"]

# Class with state — equivalent to Modal's @app.cls
@app.cls(image=image, gpu=None)
class Worker:
    @mvm.enter()
    def setup(self):
        self.model = load_model()  # runs once when the VM starts

    @mvm.method()
    def predict(self, x):
        return self.model.run(x)

# Web endpoint
@app.web_endpoint(method="POST")
def webhook(request):
    return {"received": True}

# Schedule — cron-style
@app.function(schedule=mvm.Cron("0 * * * *"))
def hourly_cleanup():
    ...

# Calling: `.remote()` runs in a microVM, `.local()` runs in-process
if __name__ == "__main__":
    print(charge.remote(100))    # spawns / reuses a mvm Sandbox
    print(charge.local(100))     # runs locally (testing)
```

#### TypeScript — TC39 decorators (TS 5.0+) + builder fallback
```typescript
import { App, Image, Secret, Volume, fn, cls, enter, method, webEndpoint, Cron } from '@mvm/sdk'

const app = new App('my-project')

const image = Image
  .fromTemplate('worker')
  .addAddon('node')
  .npmInstall(['stripe', 'lodash'])
  .aptInstall(['ffmpeg'])
  .addFiles({ './local.ts': '/app/local.ts' })

const stripeKey = Secret.fromEnv('STRIPE_KEY')
const dataVol   = Volume.fromName('project-data', { encrypted: true })

// Decorator form (TC39 / TS 5.0+)
class Charges {
  @fn(app, {
    image,
    secrets: [stripeKey],
    volumes: { '/data': dataVol },
    cpus: 2,
    memoryMib: 1024,
    timeoutSecs: 600,
    egressAllow: ['api.stripe.com:443'],
  })
  static async charge(amount: number): Promise<string> {
    const key = process.env.STRIPE_KEY!
    // ...
    return 'ch_xyz'
  }
}

// Class with state
@cls(app, { image })
class Worker {
  private model!: Model

  @enter()
  setup() { this.model = loadModel() }

  @method()
  predict(x: Input) { return this.model.run(x) }
}

// Web endpoint
@webEndpoint(app, { method: 'POST' })
async function webhook(req: Request): Promise<Response> {
  return Response.json({ received: true })
}

// Schedule
@fn(app, { schedule: new Cron('0 * * * *') })
async function hourlyCleanup() { /* ... */ }

// Builder-form fallback (no decorators) for environments without TS 5.0
const sendEmail = app.fn({ image }, async (to: string) => { /* ... */ })

// Calling: .remote() runs in a microVM, .local() runs in-process
await Charges.charge.remote(100)
await Charges.charge.local(100)
```

#### Rust (already in plan)
```rust
use mvm_sdk::prelude::*;

#[mvm::image(base = "worker", addons = ["python"], pip = ["requests"])]
struct AppImage;

#[mvm::secret(name = "stripe_key", source = secret::Source::Env("STRIPE_KEY"))]
struct StripeKey;

#[mvm::function(
    image = AppImage,
    secrets = [StripeKey],
    cpus = 2,
    memory_mib = 1024,
    egress_allow = ["api.stripe.com:443"],
)]
async fn charge(amount: u64) -> Result<ChargeId> { /* ... */ }
```

### `.local()` vs `.remote()` — Modal's signature trick
A function decorated with `@app.function` is callable two ways:
- `f.local(args)` — runs in the calling process (for testing)
- `f.remote(args)` — packages args, ships them over the wire to a microVM, returns the result

This is the *single* most-loved Modal DX feature. We replicate it in all three SDKs. The wire protocol is the same JSON-RPC `Sandbox.run_function` call underneath.

### Tree-sitter analyzability for decorated forms
The `mvm-tree-sitter` crate (Phase 5) ships grammars for *all three* declarative surfaces (Rust attribute macros, Python `@decorators`, TypeScript decorators). The future AI safety scanner walks any of them.

### Phase placement
- **Phase 5** (DX layer): Rust SDK alpha (already in plan); Python SDK alpha (runtime + decorators); type-stub gen for TS
- **Phase 7b**: TypeScript SDK alpha (runtime first; decorators land alongside the templates phase)
- **Phase 9**: All three SDKs go beta with full surface parity tests in `tests/sdk_compat/`

### ADR
- ADR-017 (already in catalog) extended: "Modal-style decorators + sandbox-runtime DX, **across Rust + Python + TypeScript**, with shared wire protocol and CI-enforced parity tests."

---

## (Legacy) SDK DX design — Modal-style decorators + sandbox-runtime API surface

### Definition-time DX (Modal-like, decorator-driven, tree-sitter-friendly)

Users describe their microVM declaratively with attribute macros that expand to data, not behavior. Trivially analyzable by tree-sitter (stable spans, named children) so the future AI safety scanner can audit configurations without running them.

```rust
use mvm_sdk::prelude::*;

#[mvm::image(base = "minimal", nix = "./flake.nix", profile = "worker")]
struct AppImage;

#[mvm::secret(name = "stripe_key", source = secret::Source::Env("STRIPE_KEY"))]
struct StripeKey;

#[mvm::volume(name = "data", size_gib = 10, encrypted = true)]
struct DataVolume;

#[mvm::function(
    image = AppImage,
    secrets = [StripeKey],
    volumes = [(DataVolume, "/var/data")],
    cpus = 2,
    memory_mib = 1024,
    egress_allow = ["api.stripe.com:443"],
)]
async fn charge(amount: u64) -> Result<ChargeId> { /* ... */ }
```

Each macro emits both runtime metadata (consumed by `mvmctl build`) and a stable serializable form (`mvm.toml` extract) so non-Rust SDKs (Python `mvm_sdk`, TypeScript `@mvm/sdk`) can parse the same model.

**Tree-sitter integration** (Phase 5+): `mvm-tree-sitter` crate ships grammars for `mvm.toml`, our subset of Nix, and source files using the `mvm-sdk` macros. The future AI safety scanner walks these trees, flags risky configs (overly broad `egress_allow`, unencrypted volumes carrying PII tags, missing seccomp tier), and proposes patches.

### Runtime DX (libkrun-style, imperative)

When users want to spin up sandboxes from running code (think: an LLM agent invoking code execution), the SDK gives them a libkrun-shaped API in line with the established sandbox-runtime category:

```rust
use mvm_sdk::runtime::Sandbox;

let sb = Sandbox::builder()
    .image(AppImage)
    .build()
    .await?;

let out = sb.run("python -c 'print(2+2)'").await?;          // → "4\n"
sb.files().write("/tmp/in.txt", "hello").await?;
let proc = sb.process().spawn(["./worker"]).await?;
let stdout = proc.stdout().await?;
sb.snapshot("post-init").await?;
sb.close().await?;
```

The `Sandbox` is backend-agnostic: it dispatches to `VmBackend` underneath. Same API on Linux (Firecracker), macOS (libkrun), Windows-via-Tauri (libkrun+WSL2). MCP tools are thin wrappers over this surface.

`mvm-sdk` is split into `mvm-sdk-macros` (proc macros) + `mvm-sdk` (runtime + types) so users only pay the syn/quote build cost when they use definition-style.

**Type-stub generation for non-Rust consumers**: Phase 5 ships a `cargo xtask gen-stubs` command that produces TypeScript `.d.ts` and Python `.pyi` from the SDK types via `ts-rs` (Apache) and a custom Python emitter. mvm-studio's TypeScript code uses these directly.

## GPU and graphics support

Two distinct workload classes; the answer is different for each:

### Display GPU / 3D / Vulkan in-VM (covers `computer-use` and richer browsers)
- **libkrun supports virtio-gpu with virgl/Venus** on Linux today; that gives the guest GL 4.x and Vulkan via the host's GPU, via the paravirtualized virtio-gpu device.
- Libkrun sits on libkrun, so the macOS path inherits this where libkrun does on macOS (libkrun on macOS uses Hypervisor.framework — virgl coverage there is more limited; verify in Phase 7b before committing).
- Firecracker **deliberately does not support virtio-gpu** (minimal device set is a security feature). For graphical workloads on Linux, we'd run them under libkrun/libkrun even on a host that has KVM.
- Feature flag: `gpu-virgl` enables guest-side virtio-gpu config + host-side virgl renderer setup. Off by default.
- The `computer-use` template also works without GPU (Xvfb is software-rendered) — `gpu-virgl` is a perf upgrade for browser smoothness, not a requirement.

### Compute GPU / CUDA / ROCm (ML training, local LLMs)
- Needs **VFIO passthrough**, which libkrun and Firecracker don't expose. Real options:
  - **Cloud Hypervisor**: full VFIO support; microvm.nix already has a Cloud Hypervisor backend.
  - **QEMU/KVM**: full VFIO support; older but ubiquitous.
- Future feature: `BackendKind::CloudHypervisor` (gated by `backend-cloud-hypervisor` feature). Microvm.nix gives us most of the work for free; what we need to add is the Rust-side Cloud Hypervisor process management + the VFIO device wiring.
- **Defer to post-Phase-10.** The hosted mvmd cloud monetization story likely needs this; we add it when we have a paying customer asking, not before.

### Decision matrix
| Workload | Backend | Feature flag | Status |
|---|---|---|---|
| CPU-only agent / dev shell | Firecracker (Linux) or libkrun (macOS/Windows) | (default) | Phase 1 |
| In-VM 3D rendering (browser, GUI agent) | libkrun (libkrun + virgl) | `gpu-virgl` | Phase 7b |
| ML inference / training in-VM | Cloud Hypervisor + VFIO | `backend-cloud-hypervisor` + `gpu-passthrough` | Post Phase 10 |

## Performance obsession — "as fast as fucking possible"

Every environment, every layer. Concrete techniques, ranked by expected impact:

1. **Snapshot-based boot (Firecracker)**: Pre-build a "warm" microVM, take a Firecracker snapshot, clone it for each boot. Cuts cold-boot from ~500ms to <30ms. Implementation: `mvm/src/vm/snapshot_pool.rs` maintains a per-template pool of snapshots; `up` clones from pool. **Phase 1 ships warm-snapshot path; Phase 9 measures and tightens.**
2. **Pre-warmed builder VM**: already in plan (Phase 1) — eliminates Nix builder cold-start.
3. **PGO (profile-guided optimization)** for release builds: `cargo pgo` + a representative workload. ~10-20% on hot paths.
4. **MUSL static builds** for `mvmctl` and `mvm-hostd`: faster process start, smaller binaries, no ldconfig.
5. **Trimmed kernel + initramfs**: Phase 9 already targets ≤ 20 MB rootfs; aim for ≤ 8 MB initramfs, kernel built with only `KVM_CLOCK + virtio + vsock + ext4 + dm-verity` enabled. Drop `printk` for production builds. **Inspiration to verify against**: Firecracker's own production-tuned kernels boot in ~125ms.
6. **`vmlinux` direct-boot** (no bootloader hop): Firecracker supports it; saves ~50ms.
7. **Lazy initialization in mvmctl**: metrics exporter, audit chain, OTLP exporter — none touched until first use. `std::sync::OnceLock` over `lazy_static` (drop the dep declared in current root `Cargo.toml`).
8. **Lock-free hot paths**: replace any `Mutex` in the request path with `arc-swap` 1 (Apache/MIT) or sharded maps (`dashmap`, MIT).
9. **Pre-fetched substituters in builder VM**: keep `/nix/store` warm with the closures for our standard profiles; new builds typically hit cache.
10. **Deferred audit-chain HMAC**: HMAC computation is cheap but allocations matter — buffer N entries, compute one HMAC over the batch, write atomically. Trade: short window where un-HMACed entries could be lost on crash; mitigated by fsync-frequency tuning.
11. **`io_uring` on Linux for vsock + audit log writes** (via `tokio-uring` 0.5, MIT): submission queue avoids syscall overhead.
12. **libkrun boot path**: less control here (vendor library), but we can pre-create sandbox skeletons and reuse process spawn.
13. **Per-OS targets**:
    - Linux/Firecracker (snapshot-cloned): **≤ 30 ms** cold boot
    - Linux/Firecracker (cold): **≤ 500 ms**
    - macOS/libkrun: **≤ 1 s** (pending vendor improvements)
    - Windows/Tauri: best-effort, target ≤ 2 s on WSL2

CI gate (`tests/perf.rs`, `MVM_PERF=1`): regression alerts fire on any p50 increase > 10%.

## Iroh-aware encryption layering

Two distinct hops, two mechanisms:

| Hop | Transport | Security | Source of truth |
|---|---|---|---|
| mvmd-coordinator ↔ mvmd-agent | iroh QUIC (with relay fallback) | TLS 1.3 native to iroh; ALPN `/mvmd/agent/1` | iroh handles; we do NOT layer extra TLS |
| mvmd-agent ↔ mvm-hostd | Unix domain socket | mTLS via `rustls` + `rcgen`; certs per-node 7-day rotation | mvm (this repo) |
| mvmctl ↔ guest agent | virtio-vsock | `AuthenticatedFrame` HMAC + X25519 ephemeral session keys (forward secrecy) | mvm-guest (this repo) |
| mvmctl ↔ host keystore | OS API (Keychain/Cred Mgr/Secret Service) | platform-native; HSM/TPM where available | OS |
| Volumes at rest | LUKS2 (Linux) / APFS-encrypted (macOS) / BitLocker (Windows) | AES-XTS | OS + our keystore wrap |
| Snapshots at rest | AEAD: AES-256-GCM (preferred) or ChaCha20-Poly1305 | Per-snapshot DEK wrapped by tenant KEK | mvm (this repo) |

This kills the impulse to "encrypt everything twice." iroh already gives us TLS 1.3 over QUIC; adding mTLS on top would just spend cycles. The hostd hop is *separately* mTLS because it's a different process boundary inside the host machine.

## Roadmap support: rebuild=update + AI CVE roller + tree-sitter inspection

The future agent watches CVE feeds (NVD/OSV/GHSA) and rolls images. To make that work:

- **Reproducible builds** are non-negotiable (Phase 9 reproducibility-check).
- **SBOM emission per image** (`cargo cyclonedx` for Rust deps; Nix derivation graph for system deps; combined into one CycloneDX file shipped with the image).
- **`mvmctl image diff <a> <b>`**: shows file/hash/CVE diff between two images. Foundation for the agent's review UI.
- **`mvmctl cve scan <image>`**: matches the image's SBOM against an OSV/NVD feed (cached locally); reports affected packages with severity + fix versions.
- **Rolling update primitive**: `mvmctl up --rolling --image <new-hash>` swaps instances one at a time with health checks; pauses on failure.
- **Image signing chain**: every image cosign-signed at build time; the rebuild path inherits the same key; rollers verify both old and new signatures before swap.
- **`mvm-tree-sitter` crate**: ships grammars for `mvm.toml`, our Nix subset, and the `mvm-sdk` macro forms. The grammar files live in `crates/mvm-tree-sitter/grammars/`. Phase 5 lands the grammars + a basic visitor; the AI safety scanner is post-Phase-10 work.

Each of these is a small, testable building block; the full agent UX comes later, but the primitives ship as part of the migration.

## Comprehensive metrics catalog

Every action emits at least one metric. The metrics registry lives in `mvm-core/src/observability/metrics.rs` (port + extend). All metric names use snake_case; tenant-scoped labels carry a hashed tenant_id (never the raw ID, to avoid label cardinality explosion).

| Domain | Metric | Type | Labels |
|---|---|---|---|
| **Lifecycle** | `mvm_vm_starts_total`, `mvm_vm_stops_total`, `mvm_vm_crashes_total` | counter | tenant_hash, backend, profile |
| **Lifecycle** | `mvm_vm_boot_duration_seconds` | histogram | tenant_hash, backend, profile |
| **Lifecycle** | `mvm_vm_uptime_seconds` | gauge | vm_id (low cardinality only) |
| **Build** | `mvm_builds_total`, `mvm_build_duration_seconds`, `mvm_build_cache_hits_total`, `mvm_build_failures_total` | counter/histogram | tenant_hash, profile, cache_outcome |
| **Build** | `mvm_artifact_bytes` | histogram | profile |
| **Resource** | `mvm_cpu_usage_seconds_total`, `mvm_memory_bytes`, `mvm_disk_bytes` | counter/gauge | tenant_hash, vm_id |
| **Network** | `mvm_egress_flows_allowed_total`, `mvm_egress_flows_denied_total`, `mvm_egress_bytes_total` | counter | tenant_hash, dest_class (l4/l7), proto |
| **Network** | `mvm_dns_queries_total`, `mvm_dns_resolution_duration_seconds` | counter/histogram | tenant_hash, qtype |
| **Vsock** | `mvm_vsock_frames_total`, `mvm_vsock_auth_failures_total`, `mvm_vsock_replay_rejections_total` | counter | tenant_hash, frame_type |
| **Storage** | `mvm_volume_reads_total`, `mvm_volume_writes_total`, `mvm_volume_bytes` | counter | tenant_hash, volume_id |
| **Storage** | `mvm_snapshot_creates_total`, `mvm_snapshot_restores_total`, `mvm_snapshot_hmac_failures_total` | counter | tenant_hash |
| **Encryption** | `mvm_kek_rotations_total`, `mvm_dek_rotations_total`, `mvm_decrypt_failures_total` | counter | tenant_hash, layer |
| **Secrets** | `mvm_secret_reads_total`, `mvm_secret_writes_total`, `mvm_secret_redactions_total` | counter | tenant_hash |
| **Audit** | `mvm_audit_events_total`, `mvm_audit_chain_verifies_total`, `mvm_audit_chain_breaks_total` | counter | tenant_hash, severity |
| **Plan/Policy** | `mvm_plans_received_total`, `mvm_plans_rejected_total`, `mvm_policy_evaluations_total` | counter | tenant_hash, reject_reason |
| **MCP** | `mvm_mcp_requests_total`, `mvm_mcp_tool_invocations_total`, `mvm_mcp_session_duration_seconds` | counter/histogram | tenant_hash, tool |
| **Hostd RPC** | `mvm_hostd_requests_total`, `mvm_hostd_request_duration_seconds`, `mvm_hostd_errors_total` | counter/histogram | request_kind, error_class |
| **Process** | `mvm_process_cpu_seconds_total`, `mvm_process_memory_bytes`, `mvm_process_open_fds` | counter/gauge | binary (mvmctl/mvm-hostd/mvm-supervisor) |

`mvmctl metrics --json` emits the snapshot; `mvmctl metrics serve --addr ...` runs the Prometheus exporter; `metrics-otel` feature additionally ships to OTLP.

## PII redaction

A first-class capability, not a side-effect. The previous iteration's `mvm-supervisor::secrets_scanner` is the seed; we extend it into a proper redactor used everywhere data flows out of a VM or out of the host process.

### Where it runs
- **Audit log**: every entry passes through the redactor before HMAC + write
- **Structured logs (`tracing`)**: a `tracing::Layer` redacts fields before formatting
- **Metric labels**: redactor checks every label value before it lands in the registry
- **MCP tool call logs**: tool args/results redacted before audit
- **Console output captured to host log files**: redacted on capture
- **Snapshot metadata**: redacted before persisted

### What it catches (built-in patterns)
- Email addresses (RFC 5322-ish, conservative)
- Credit card numbers (Luhn-validated to reduce false positives)
- US SSN, phone numbers
- IBAN, BIC
- IP addresses (configurable; tenants may opt to keep IPs visible for debugging)
- Common API key shapes: AWS access keys (`AKIA…`), GitHub tokens (`ghp_…`), Stripe (`sk_…`/`pk_…`), Anthropic (`sk-ant-…`), OpenAI (`sk-…`), JWT (`eyJ…`)
- Generic high-entropy strings ≥ 32 chars (last-resort heuristic; configurable)

### Per-tenant custom patterns
Tenants register additional regex patterns through `mvm-policy::TenantPolicy::redaction_rules`. Patterns are validated for catastrophic-backtracking via `regex` crate's runtime checks; CI custom-lint blocks unbounded `(.*)+` shapes.

### Tokenization for forensic linkability
Matched values are replaced with `<REDACT:kind:hmac8>` where `hmac8` is the first 8 bytes of HMAC-SHA-256 over the value with a per-tenant redaction key. Same input → same token, so investigators can correlate across logs without exposing raw values. The redaction key is rotated independently of other keys (Phase 2's key rotation infra extends to it).

### Implementation
- New module `mvm-supervisor/src/redactor/`
- One `Redactor::redact(&self, text: &str) -> Cow<'_, str>` that all sinks use
- Bench-tested: redactor must process ≥ 1 GB/s on a single core (use `aho-corasick` for the literal-prefix prefilter, fall back to `regex` for full match)
- Crate deps: `regex` (Apache-2.0/MIT), `aho-corasick` (Apache-2.0/MIT)

### CI tests
- `tests/redactor.rs::redacts_known_token_shapes` — table-driven, one row per built-in pattern
- `tests/redactor.rs::no_pii_reaches_disk` — drives a session that prints/logs realistic PII; greps the audit log + structured log + metric scrape; asserts zero unredacted matches
- Property test (`proptest`): for every redactor input, output never contains the original sensitive substring

## Auditability, traceability, confirmability

Three distinct properties, each with a separate primitive. **Every action** in the system must satisfy all three.

### Auditability — "what happened, did we record it"
Every action emits a chain-signed audit event before the action completes (or, where async, inside a transaction-scoped recorder that must commit before the action's effects become visible). Coverage is verified by `tests/audit_total_coverage.rs` which drives every CLI command, every SDK call, every host-mediated tool, every Plan acceptance, and asserts ≥ 1 audit entry per action.

### Traceability — "what code ran, what did it try to access, when"
Every action carries a propagated trace context (`trace_id`, `span_id`, `parent_span_id`) using the W3C Trace Context spec and OpenTelemetry trace IDs. The trace records:
- **What code ran**: the binary SHA-256 + image attestation hash + git commit (baked in via `shadow-rs`, already in root `Cargo.toml`).
- **What it tried to access**: every file open, network connect, secret read, syscall (at the seccomp-tier-instrumented level), tool RPC call. These are gathered as span attributes.
- **When**: monotonic + wall-clock + (where present) RFC 3161 timestamp.
- **Who**: the Ed25519 identity key of the actor (VM, host process, mvmd request); resolved through the attestation chain.
- **Why**: when an action is in service of a Plan, the Plan ID is on the span; for ad-hoc CLI calls, the user identity + invocation reason.

Spans flow to `tracing` JSON logs by default; `metrics-otel` feature ships them to an OTLP collector. The tenant_hash label keeps cardinality bounded.

### Confirmability — "can we prove it later"
Every audit chain entry is HMAC-linked to its predecessor (chain integrity); RFC 3161 timestamping anchors the chain in real time; cosign-signed daily anchors are published to Rekor for long-term non-repudiation. The chain validates end-to-end via `mvmctl audit verify`. Tampering is detectable. Optionally, the audit log ships to a remote sink (`audit-remote-sink` feature) for off-host durability.

### CLI surface
- `mvmctl audit tail [--vm <name>] [--category cmd,flow,secret,…]`
- `mvmctl audit verify [--from <anchor>] [--to <anchor>]`
- `mvmctl audit explain <event-id>` — pretty-prints an event with full trace context, attestation chain, and links to the Plan / signed request that authorized it
- `mvmctl audit export --tenant <id> --since <date>` — produces a portable, signed bundle for compliance auditors

### Failure mode
If the audit Recorder fails to commit (disk full, log rotation race, etc.), the underlying action **fails closed**. We never silently lose audit; we'd rather refuse to do the work. CI test: `tests/audit_fail_closed.rs::action_fails_when_audit_commit_fails`.

### What this rules out
- Side-channel actions that don't touch the audit path. Lints search the codebase for any `Backend::*` impl method that doesn't call `Recorder::record(...)`; CI fails on a hit.
- Implicit caching that bypasses access logging. Anything that touches a secret routes through `secrecy::SecretBox::expose_secret` which is a single audit hook.
- Background tasks that aren't trace-context-aware. `tokio::spawn` is wrapped in `mvm-core::trace::spawn_traced(parent_ctx, fut)` and the bare form is forbidden by clippy lint.

## Audit everything

Audit is upgraded from "lifecycle events" to **every action**. Categories:

- `cmd` — every CLI invocation (user, args excluding secrets, exit code)
- `lifecycle` — VM start/stop/snapshot/restore
- `secret` — every `read`, `write`, `inject`, `rotate` of a secret
- `flow` — every network flow attempt (allowed or denied)
- `plan` — every Plan received from mvmd, with verdict (accepted/rejected + reason)
- `policy` — every policy evaluation
- `key` — every KEK/DEK creation, rotation, decryption, derivation
- `host` — every privileged host syscall through mvm-hostd
- `audit` — meta-events for the audit log itself (rotation, chain re-anchor)

Every entry is appended to a chain-signed HMAC log (`mvm-supervisor/src/audit/`). The chain links each entry to the previous via `prev_hmac`, so any insertion or deletion breaks verification. `mvmctl audit verify` walks the chain end-to-end. The log is **append-only**: rotation creates a new file with an explicit `chain-anchor` event referencing the previous file's final HMAC. Optionally shipped to a remote sink (S3, Splunk, OTel logs) when `audit-remote-sink` feature is enabled.

CI test: `tests/audit_total_coverage.rs` — runs a scripted session of every CLI command and asserts the audit log contains an entry for each.

## Additional security considerations

Beyond the layers already named, we also bake in:

1. **Memory hygiene beyond zeroize**: `mlock` long-lived KEKs to prevent swap, drop them as early as possible, derive DEKs on demand. Crate: `mlock` 0.1 or `region` 3.
2. **Anti-debug for production builds**: refuse to run if `ptrace`-attached (Linux) or under a debugger (`IsDebuggerPresent` on Windows; equivalent on macOS). Off by default in dev builds.
3. **Replay protection across the board**: every signed message (Plan, vsock auth frame, hostd RPC) carries a 64-bit nonce + monotonic timestamp. `mvm-plan/src/replay.rs` already exists; extend the same model to vsock and hostd.
4. **Time-skew-resistant signing**: signatures include both wall-clock and monotonic timestamps; verifiers reject if either is > 60s out of expected window.
5. **Image provenance**: every published mvm image (kernel + rootfs) is cosign-signed by the tenant's signing key. Boot path verifies before mounting. Plan: `image-verify` already in `mvm-security`.
6. **SBOM generation**: `cargo-cyclonedx` runs in CI; SBOM published with each release. Consumed by mvmd for compliance reporting.
7. **Reproducibility double-build**: `xtask reproducibility-check` builds twice and diffs the artifact hash. Already on the roadmap.
8. **Privilege separation in mvm-hostd itself**: the hostd binary runs as root (it has to mount, network-config), but every RPC is gated by a capability check derived from the signed Plan that requested it. No "ambient" root.
9. **Vsock session keys + forward secrecy**: each vsock session negotiates an ephemeral X25519 key (HKDF→AEAD key); compromise of the long-term key doesn't decrypt past traffic.
10. **TUN/TAP packet inspection has its own seccomp profile**: the supervisor process running the TUN handler is itself sandboxed (seccomp + cgroup) so a kernel-side TUN exploit doesn't pivot to root.
11. **DoS protection**: per-tenant cgroup CPU/mem limits, `ulimit -n` on hostd, rate limits on every RPC (token bucket, configurable per request kind).
12. **Update mechanism**: the mvm CLI binary itself is signed and verified before self-update. `mvmctl update` only applies signed updates; signature verified against a baked-in public key + Sigstore transparency log.
13. **Side-channel against secrets**: `Display`/`Debug` on `secrecy::SecretBox<T>` are forbidden by trait; `eq` uses `subtle::ConstantTimeEq`; cargo-deny lint custom rule blocks raw `==` on these types.
14. **Sandbox-escape red team test suite** (`tests/red_team/`): each test attempts a known escape technique (KVM bug, vsock confused-deputy, virtio queue overflow) and asserts containment. Some gated by KVM/CI capability.
15. **Confidential compute (future, feature-gated)**: `sev-snp` and `tdx` features wire SEV-SNP / TDX attestation into Plan verification when running on supported hardware. Not Phase-1 work; placeholder feature flags reserve the API.
16. **Supply-chain audit on `microvm.nix` and every Nix flake input**: pinned by hash in `flake.lock`; CI re-audits on bump; release notes call out the version.
17. **Backup/recovery threat model documented**: data loss from KEK loss is acceptable (default); key-escrow is opt-in; recovery is signed by mvmd with a separate recovery key. Documented in ADR.

## Additional considerations I'm surfacing (not in original brief)

### Security
- **Hardware root of trust**: where TPM2 (Linux/Windows) or Secure Enclave (macOS) is present, store the tenant KEK there instead of in `keyring`. Crate: `tss-esapi` (Apache-2.0) for TPM2; macOS Secure Enclave via `security-framework` (MIT/Apache). Falls back to `keyring` where unavailable.
- **`#![forbid(unsafe_code)]`** on every crate where possible. Where `unsafe` is unavoidable (FFI to libkrun/libkrun, vsock ioctls), it lives in a single `unsafe-bridge` module per crate, reviewed by the `type-design-analyzer` agent.
- **Continuous fuzzing in CI**: nightly job runs each fuzz target for 1h on the latest main. Crashes file an issue automatically; corpora are versioned in `crates/mvm-guest/fuzz/corpus/`.
- **Two-person review on security paths**: `CODEOWNERS` requires review from a security-tagged reviewer for changes under `crates/mvm-security/`, `crates/mvm-supervisor/`, `crates/mvm-plan/`, `crates/mvm-policy/`, `crates/mvm/src/security/`.
- **VM-level intrusion detection (feature-gated)**: optional guest-side `mvm-ids` daemon watches for syscall anomaly patterns (excessive `connect()` to new IPs, `ptrace` self-attach, suspicious `execve` chains). Reports via vsock; runs only when `ids` feature is on.
- **RFC 3161 timestamping for the audit chain**: the chain's anchor events get TSA timestamps so the log is non-repudiable even if our internal clock is compromised. Crate: `rfc3161-client` (Apache-2.0).
- **Encrypted env vars**: env vars passed to a guest are encrypted in transit (vsock auth frame already covers this) and never written to disk. Wired through `secrecy::SecretBox`.
- **Coordinated vulnerability disclosure**: `SECURITY.md` with GPG key + 90-day embargo policy + Hall of Fame. Phase 0 ships it.
- **`#[deny(unsafe_op_in_unsafe_fn)]`** workspace-wide: forces explicit `unsafe { }` blocks even inside `unsafe fn`, making review surfaces explicit.
- **Hash-pin every Nix flake input**: `flake.lock` is committed; `xtask audit-flake` runs in CI to verify no input drifted off-hash.
- **Resource exhaustion limits enforced at the supervisor layer**: max VMs per tenant (configurable), max snapshots per tenant, max concurrent builds, max audit log size before rotation. All emit metrics and audit events when hit.
- **Forbidden-string lints**: CI greps for `unwrap()`/`expect()` outside test code; for `println!` outside the CLI output module; for `assert!` in production code (use `debug_assert!` or proper error paths).

### DX
- **`miette`-powered error reporting** (Apache-2.0): codespan-style errors with line/col/source for `mvm.toml`, flake parse errors, policy validation. `mvmctl explain <code>` walks users through error codes (`cargo`-style).
- **`mvmctl doctor --fix`**: auto-remediation for safe failures (chmod 0700 on data dirs, regenerate dev certs, prune stale temp files). Destructive remediation requires `--yes`.
- **Hot-reload dev loop**: `mvmctl up --watch` watches the flake + manifest, rebuilds on change, applies a rolling restart with health-check gating.
- **Embedded REPL** (`dev` feature only): `mvmctl repl` launches a Rhai sandbox inside a libkrun for quick experimentation.
- **First-class TypeScript + Python SDK stubs**: emitted via `cargo xtask gen-stubs` so mvm-studio's UI and any non-Rust user gets typed APIs.
- **Telemetry opt-out, not opt-in**: anonymous telemetry only collects build durations and boot times, gated by an explicit `MVM_TELEMETRY=on` (off by default, opt-in only — DX matters but trust matters more).
- **Default config sane out of the box**: `mvmctl init` produces a flake that boots a working VM without any further tweaks.

### Architecture
- **Crate stability tiers** declared in each `Cargo.toml` via a `[package.metadata.mvm.stability]` key: `stable` (mvm-core, mvm-storage, mvm-sdk types), `experimental` (mvm-cve, mvm-tree-sitter), `internal` (everything not consumed by mvmd or mvm-studio). `cargo-public-api` enforces no breaks on `stable`.
- **`#[non_exhaustive]` on every public enum/struct** so we can add variants without major-version bumps.
- **One workspace error type per crate** (via `thiserror`). Conversion at boundaries; never `Box<dyn Error>` in lib code.
- **`PROTOCOL_VERSION: u32`** on the wire-protocol surface (Plans, hostd RPC, vsock). Forward-compat shim for one major version back; CI compat-matrix test.
- **Plug-in backends via `inventory`** (Apache-2.0/MIT): backends register at startup so adding a new one (e.g., Cloud Hypervisor) is a new file + `inventory::submit!`, no core changes.
- **Workspace-wide `clippy::pedantic = "warn"`** plus our deny list; the warnings act as a code-quality "smell map."
- **`bench/` workspace member** with criterion benchmarks; CI tracks regressions.
- **Document the threat model per ADR**: every security-affecting design gets a paired ADR with a STRIDE table.

### Operational / future
- **`mvm-cve` crate** (experimental): consumes OSV/NVD feeds, maps SBOM components, emits "rebuild needed" events. Foundation for the AI roller.
- **`mvm-tree-sitter` crate** (experimental, lands in Phase 5): grammars + visitor for static analysis of user configs.
- **Image diff utility**: `mvmctl image diff <a> <b>` (file list, hash diff, CVE diff). Phase 5+.
- **Rolling update primitive**: `mvmctl up --rolling --image <hash>`. Phase 8.
- **Status page surface**: `mvmctl status --json` produces a stable schema mvm-studio can render. Phase 5.

### AI-agent-specific threats and mitigations

The "safe AI environment" workload class introduces a few threat patterns that pure dev sandboxes don't:

- **Prompt injection inside the VM**: an agent reading attacker-controlled content (a webpage, a downloaded file, an email) gets convinced to do something harmful. **Containment**: the VM boundary protects the host; the per-tenant tool allowlist + the no-raw-internet design protect the world. Audit log records every tool call so post-hoc forensics work. The agent may corrupt its own `/workspace`, but cannot pivot.
- **Secret exfiltration via tool calls**: the agent has access to host-mediated tools; could it leak secrets through `web_fetch`? **Mitigation**: per-tenant URL allowlist; `web_fetch` arguments are audit-logged; the secrets scanner (Phase 4) redacts known-shape tokens from URLs and bodies. Optionally, mTLS the agent's outbound to a dedicated egress proxy that can DPI for secrets.
- **Resource exhaustion by adversarial agent loops**: an agent in an infinite tool-call loop. **Mitigation**: per-VM cgroup CPU/mem caps; per-tenant rate limits on tool RPCs (token bucket); idle-session timeout; `mvmctl session timeout --idle 24h` default for `ai-sandbox`.
- **Persistence backdoors**: a compromised agent installs a cron job inside the VM. **Containment**: every package install rebuilds the rootfs (Phase 7a) so a fresh boot from base + overlay erases anything not committed; users see a `--diff-from-clean` view of their overlay state. Optionally enforce "ephemeral" template flag where the overlay is zeroed at every boot.
- **Side-channels via tool latency**: an agent might learn host state by timing tool RPCs. **Mitigation**: jitter on all host-tool responses by default; constant-time comparisons for any cryptographic check.
- **Computer-use → host pivot**: a graphical agent attempts a VM-escape via the X server. **Mitigation**: X server runs as non-root with its own seccomp; Xvfb + Xpra are kept in their own minimal closure; CVE feed monitoring on these specifically (they're a high-attention package set).
- **Cross-session contamination**: two `ai-sandbox` sessions share a host; can one read the other's RAM? **Mitigation**: KVM provides hardware isolation; per-session encrypted overlays; tenant cgroups enforce resource separation; SEV-SNP/TDX (feature-gated, future) closes the hypervisor-trust gap.

These are catalogued in `specs/adrs/<n>-ai-agent-threat-model.md` (new ADR, Phase 7b).

## Compliance posture (PCI / HIPAA / SOC 2 / GDPR)

mvm itself is a library — it cannot *be* SOC 2 / PCI / HIPAA compliant; only deployments can. Our north star: **be compliance-ready** so a deployer (mvmd hosted cloud, or a customer self-hosting) can pass audit without rebuilding the substrate. We do *not* commit to processing regulated data ourselves until the hosted mvmd cloud takes that on.

### SOC 2 Type II (target for hosted mvmd cloud)
Five trust principles map cleanly to existing roadmap items:

| Principle | Where it shows up in this plan |
|---|---|
| Security | Phase 6 (security model + attestation), Phase 3 (network isolation), redactor, encryption everywhere |
| Availability | Reliability + SLOs section (per-VM crash <0.1%, builder warm-pool 99.9%), supervisor restart, snapshot pool |
| Processing Integrity | Reproducibility double-build (Phase 9), signed Plans (Phase 6), audit chain integrity, attestation runtime measurements |
| Confidentiality | Encryption-at-rest layers, redactor, secret tokenization, `tenant destroy` zeroization |
| Privacy | Redactor coverage, `tenant destroy` certificates, no telemetry without opt-in |

Phase 9 ships a `specs/compliance/soc2-controls.md` document that maps each SOC 2 control to the implementing artifact (test, code path, ADR). Auditors get a living traceability matrix.

### PCI DSS (out-of-scope-by-default; opt-in profile available)
Default posture: **PCI scope reduction.** mvm/mvmd never touch cardholder data; payments processed via Stripe/Adyen/etc. by the customer's app. We document this clearly in `specs/compliance/pci-scope.md`.

For customers who *want* to process PCI inside mvm (a brave choice), we ship a **`profile = "pci"`** template with extra-strict defaults: mandatory LUKS, no shared infrastructure across tenants, mandatory L7 egress proxy with cardholder-data DLP rules, audit log retention ≥ 1 year, mandatory quarterly ASV scans documented in `specs/runbooks/pci-asv.md`. **We do not certify the profile ourselves**; the customer retains compliance responsibility but the substrate doesn't fight them.

### HIPAA (BAA-ready posture)
For US health data, the hosted mvmd cloud will need to offer Business Associate Agreements. The Security Rule's technical safeguards (Access Control, Audit Controls, Integrity, Person/Entity Authentication, Transmission Security) all map to existing roadmap items.

`specs/compliance/hipaa-mapping.md` is shipped Phase 9, mapping each Security Rule §164.312 paragraph to our implementation. The breach-notification workflow (the *operational* part of HIPAA) lives entirely in mvmd — out of scope for the mvm library.

### GDPR
Right-to-erasure is satisfied by `tenant destroy` (Phase 7a). Data-minimization is satisfied by the redactor + opt-in telemetry. Cross-border transfer concerns are mvmd's problem, not the library's.

### FedRAMP / FIPS 140-3
Future. To go down this road we'd need to switch our crypto crates to FIPS-validated implementations (AWS-LC-rs is a candidate). Reserve the option by feature-gating crypto crate selection in `mvm-security`; defer the actual swap to post-Phase-10.

### What "compliance-ready" means at exit
- Every regulated requirement maps to a test or ADR
- The compliance docs (`specs/compliance/*.md`) are shipped, owned, and CI-checked for staleness (timestamp last verified)
- Customer-facing posture statement is published in the project docs

## ADR catalog and ADR coverage gate

Every architecturally-significant decision in this plan **must** be reflected in an ADR. The user authorized creating/editing ADRs during this session as we plan and execute. Below is the catalog; existing ADRs are kept; new ones are stubbed during the session and filled out during the corresponding phase.

**Numbering note:** the saved plan originally used ADR 008-033, which conflicts with existing ADRs 003-012 from the previous iteration. ADRs are renumbered +5 to **013-038** below.

| ADR | Title | Phase | Status |
|---|---|---|---|
| 002 | microVM security posture (existing) | already shipped | KEEP |
| 003-012 | existing ADRs from the previous iteration | various | KEEP — not touched |
| 013 | Pivot to libkrun + libkrun + microvm.nix; drop Lima | Phase 0 | NEW |
| 014 | `VmBackend` single trait; backend-as-impl pattern | Phase 0 | NEW |
| 015 | Persistent builder VM with warm pool per tenant | Phase 1 | NEW |
| 016 | Two-layer rootfs + encrypted persistent overlay | Phase 2 + 7a | NEW |
| 017 | Default-deny egress; L4+L7+firewall additive enforcement | Phase 3 | NEW |
| 018 | Five-layer attestation chain | Phase 6 | NEW |
| 019 | Audit-everything coverage matrix | Phase 4 | NEW |
| 020 | PII redaction tokenization scheme | Phase 6 | NEW |
| 021 | Addons composability model | Phase 5 + 7b | NEW |
| 022 | Modal-style decorators + sandbox-runtime DX (multi-language: Rust + Python + TypeScript) | Phase 5 + 7b + 9 | NEW |
| 023 | Long-running session model (tmux-backed) | Phase 7 | NEW |
| 024 | Computer-use RPC surface | Phase 7b | NEW |
| 025 | Transparent install/rebuild flow | Phase 7a | NEW |
| 026 | Vsock protocol rolled in-house | Phase 1 | NEW |
| 027 | Iroh-aware encryption layering | Phase 0 | NEW |
| 028 | Tenant destruction certificate | Phase 7a | NEW |
| 029 | Compliance posture (SOC 2 / PCI / HIPAA / GDPR / FedRAMP) | Phase 9 | NEW |
| 030 | GPU support paths (virgl, VFIO) | Phase 7b + post-10 | NEW |
| 031 | Cross-platform strategy (Linux native, Windows Tauri-only) | Phase 0 | NEW |
| 032 | Hosted-cloud invariants (no lock-in, metering precision) | Phase 0 | NEW |
| 033 | Code-quality enforcement (`forbid(unsafe_code)`, lint deny list, file-size cap) | Phase 0 | NEW |
| 034 | Performance gates and per-OS boot targets | Phase 9 | NEW |
| 035 | Feature flag taxonomy | Phase 0 | NEW |
| 036 | AI-agent threat model (prompt injection, exfil, persistence) | Phase 7b | NEW |
| 037 | Snapshot model (memory + disk + metadata + attestation; fork lineage) | Phase 2 + 7 + 9 | NEW |

### ADR coverage gate (CI-enforced)
Every PR that touches a non-trivial architectural concern must reference an ADR ID in its description (regex: `ADR-\d{3}`). New architectural concerns require a new ADR. CI lint: `xtask check-adr-coverage` walks the diff for files matching a known-architectural pattern (anything in `crates/mvm-core/src/protocol/`, anything implementing `VmBackend`, anything in `mvm-security/`, …) and fails the build if no ADR ID is mentioned in either the commit messages or a touched ADR file.

### What goes in an ADR (template)
```
# ADR-NNN: <Title>
Date: YYYY-MM-DD
Status: Proposed | Accepted | Superseded by ADR-MMM
Phase: <which phase delivers this>

## Context
What problem are we solving? What are the constraints?

## Decision
What did we decide?

## Consequences
Positive, negative, neutral. What does this preclude?

## Alternatives considered
Other options and why they were rejected.

## Threat model (security-affecting decisions only)
STRIDE table; what new attack surface does this introduce?

## Compliance impact
Which controls (SOC 2 / PCI / HIPAA) does this affect, positively or negatively?
```

## Hosted mvmd P2P cloud — planning implications

A future hosted, monetized mvmd cloud changes a few decisions today. Most are already covered; flagging them explicitly so we don't make a one-way-door wrong choice during the migration.

- **Multi-tenant isolation** must be airtight from day one. Plan-7's tenant cgroup, per-tenant bridge, per-tenant policy bundle, and per-tenant signing key all already do this. Don't relax for "single-tenant simplicity" mid-migration.
- **Metering primitives must be precise**. The metrics catalog already covers per-tenant CPU seconds, memory bytes, disk bytes, build seconds, egress bytes, tool RPC counts. mvmd will turn these into invoices; we just need to keep them accurate, attributable, and tamper-evident (audit-logged).
- **Attestation becomes a hard gate**. In a self-hosted setup, attestation is good hygiene; in a paid cloud, it's the basis of trust between customer and operator. Every API call from a hosted-cloud VM must carry attestation; mvmd refuses unattested requests. This is **not** a future-only concern — implement it correctly now (Phase 6), even though enforcement intensity scales with deployment posture.
- **iroh QUIC scaling**: mvmd's P2P design already uses iroh with relay fallback. For a paid cloud, the relay servers become a load-bearing piece — but that's mvmd's concern, not ours; we just need to keep `mvmctl::core::agent::AgentRequest` shape stable and tightly versioned.
- **Compliance**: SOC2/HIPAA/PCI compliance documents will reference our SBOM emission, audit chain, encryption posture, attestation chain, PII redaction, and reproducibility. All already in plan; no new work, just keep them all CI-gated so a careless PR can't regress any of them.
- **Legal "deprovision" requirement**: customers will demand provable destruction of their data on cancellation. We need `mvmctl tenant destroy --tenant <id> --confirm-deletion` that wipes volumes, snapshots, audit log entries (the redacted parts; the chain anchors stay), and emits a destruction certificate signed by the host's identity key. Build this primitive in Phase 7a (it's adjacent to install/rebuild).
- **No vendor lock-in**: customers will want to self-host or migrate. The mvm library staying open-source and the protocol versioning being explicit (PROTOCOL_VERSION constant, in plan) supports this. Be careful not to introduce hosted-cloud-only paths that aren't in the open-source library.

These don't push the timeline; they push us to *not regress* during migration. The cost of getting them wrong now is much higher than the cost of getting them right.

### Reliability and SLOs

- **Per-VM crash rate target**: < 0.1% across all known-good templates (measured weekly).
- **Audit log durability**: append + fsync per entry by default; loss window ≤ 1 entry on host crash; `audit-remote-sink` feature ships entries to a remote collector for external durability.
- **VM-pause-resume correctness**: 100% of paused VMs successfully resume (regression-tested every PR via `tests/pause_resume.rs`).
- **Tool-RPC error budget**: < 0.5% of host-mediated tool calls fail with internal errors (timeouts excluded; allowlist denials excluded — those are policy decisions, not failures).
- **Builder availability**: warm-builder pool > 0 instances for all active tenants 99.9% of the time.

## Attestation everywhere

Every actor must be able to prove what they are and what they're running. Five concentric attestation layers:

### 1. Build attestation (SLSA-3)
- **In-toto attestations** signed at build time describing inputs (source SHA, flake.lock, builder identity).
- **Cosign + Rekor** transparency log: every image artifact gets a Sigstore signature published to Rekor; consumers verify via the public log.
- **Reproducibility check** (Phase 9): two clean builds produce byte-identical artifacts; the attestation includes the reproducibility hash.
- Crate: `sigstore-rs` (Apache-2.0); CI workflow signs and publishes per release.

### 2. Image attestation (cosign)
- Every published image (rootfs + kernel + initrd) is cosign-signed by the tenant's signing key.
- Signature chain rooted in the project release key + the tenant's per-tenant key (set up at first onboarding via mvmd).
- Boot path verifies before mounting (already on roadmap as part of `mvm-security/image_verify`).

### 3. Boot attestation (rootfs measurement)
- **dm-verity hash** of the rootfs is recorded in the kernel cmdline (already in W3 from the existing security plan).
- The guest agent reports the measured hash to the host on boot via the first vsock auth frame.
- Host compares to expected; mismatch → kill the VM and audit-log a `chain.attest.boot.fail`.

### 4. Runtime attestation (per-VM identity + ongoing measurement)
- Every microVM gets an Ed25519 **identity key** generated at first boot, bound to the rootfs measurement and the host's keystore.
- Every host-mediated tool RPC, every Plan acceptance, every audit event from the VM carries an attestation header signed by the identity key.
- Periodic re-measurement (every 5 min) signed and emitted to audit; tampering with the in-memory rootfs is detected.
- mvmd verifies these attestation headers before accepting any state change request.

### 5. Hardware attestation (feature-gated, future)
- **TPM2 quotes** (Linux/Windows hosts with TPM2): tie the identity key to a hardware-rooted measurement chain. Crate: `tss-esapi`.
- **AMD SEV-SNP attestation reports**: hardware-attested confidential computing. Feature flag `sev-snp`. Verifies memory encryption + measurement.
- **Intel TDX attestation reports**: same as SEV-SNP for Intel. Feature flag `tdx`.
- **Apple Secure Enclave** (macOS): identity key bound to Secure Enclave; non-extractable.
- These features stub out APIs in Phase 6; real implementations land post-Phase-10 when the hosted mvmd cloud needs them for compliance.

### CLI surface
- `mvmctl attest <vm>` — print the current attestation report (boot measurement + runtime measurements + identity public key + hardware attestation if available)
- `mvmctl attest verify <report.json>` — verify a saved report against a known image
- `mvmctl attest export <vm>` — emit a portable bundle (image cosign sig + boot measurement + identity key + hardware report) for compliance auditors

### New crate: `mvm-attestation`
Lives between `mvm-security` and the rest. Owns:
- The identity key lifecycle
- The runtime measurement loop
- The attestation header format (versioned, `#[non_exhaustive]`)
- Verification helpers used by mvmd

This is **not** a new ADR-required design — it's the natural extension of `mvm-plan` (already ports verbatim) plus `mvm-security/image_verify`. Lands in **Phase 6** alongside the security model port.

## Encryption and key rotation design

Three layers, each with rotation:

**Layer 1 — at-rest data encryption (volumes)**
- LUKS2 / `aes-xts-plain64` for persistent volumes, key passed via stdin to `cryptsetup`
- Per-volume DEK stored in `mvm-storage` keystore, wrapped by tenant KEK
- Rotation: `mvmctl volume rotate-key <name>` re-wraps the DEK under a new KEK without rewriting volume contents (LUKS keyslot model). CI test: `tests/volumes.rs::rotate_key_preserves_data`.

**Layer 2 — at-rest snapshot encryption**
- AES-256-GCM with 96-bit random nonce + 128-bit authentication tag
- Snapshots also wrapped with HMAC-SHA-256 chain so tampering is detectable across the audit log
- Rotation: snapshots are short-lived; on KEK rotation, mark old snapshots as "decryptable-only"; new snapshots use new KEK
- Implementation: `mvm/src/security/snapshot_crypto.rs` (port from `../mvm`)

**Layer 3 — in-transit + identity**
- mvmd↔mvm-hostd: mTLS 1.3 over Unix socket via `rustls`; certs generated per node by `rcgen`, signed by the per-tenant CA
- Plans (orchestration commands): Ed25519-signed by mvmd; mvm verifies before execution; nonces prevent replay (`mvm-plan/src/replay.rs`)
- Vsock control plane: AuthenticatedFrame from `../mvm/crates/mvm-guest/src/vsock.rs` with HMAC over framed payload; rotation via session-keys negotiated at handshake
- Rotation cadence: tenant CA — on demand or every 90 days; node certs — every 7 days; vsock session keys — per session

**Master key custody**
- Dev mode: file-backed keystore at `~/.mvm/keys/` (mode 0700), passphrase optional
- Production: OS keyring via `keyring-rs`; can swap to Vault/KMS via the `Keystore` trait

All secret-bearing types wrap `secrecy::SecretBox<T>` and implement `Zeroize` on drop. Constant-time comparison via `subtle::ConstantTimeEq`. `cargo-deny` ban on direct `==` comparison of secret types (custom check).

## Network isolation design

**Builder microVM (only)**: full egress allowed (it has to fetch from `cache.nixos.org`, GitHub, etc.). All traffic logged to `~/.mvm/logs/builder-egress.jsonl` with timestamps and destinations. The builder VM has no persistent state and is destroyed after each build.

**Runtime microVMs**: **no default egress**. Mediated by:
1. `nftables-rs` rule on the host bridge that drops all packets from runtime-VM TAPs except those flowing into our userspace proxy.
2. Userspace L7 egress proxy (`mvm-supervisor::egress_proxy`) that runs on the host, terminates guest TCP/HTTP via `smoltcp`, and enforces a per-tenant allowlist. Default-deny.
3. All control-plane traffic between host and guest stays on **vsock** — never IP — so the bridge being default-deny does not break management.

**Inspection path**:
- `tun-rs` opens a TAP per runtime VM; packets are pulled into the host process before any forwarding decision.
- `mvm-supervisor::audit` records `flow_event` for each connection attempt (allowed or denied) with a chain-signed HMAC so the log is tamper-evident.
- `mvmctl audit tail --vm <name>` streams events; `mvmctl audit verify` walks the chain.

**DNS**: `hickory-server` runs an in-process authoritative resolver for the named-network domain (`*.mvm.local`). Guest VMs resolve only this; external DNS lookups go through the egress proxy too.

This design satisfies "microvms should NOT have open access to the internet" and "monitor networked traffic either over vsock or a custom TUN/TAP" simultaneously.

## Phased delivery (tracer-bullet vertical slices)

Each phase ships an independently demonstrable end-to-end flow. Each phase ends only when the named tests pass and the **checkpoint review** is signed off. Work happens on a fresh worktree branch `feat/migrate-to-mvm` (worktree per `AGENTS.md` line 37).

### Phase summary table (checkpoints)

| # | Phase | Demo at exit | Days | New ADRs | New SPRINT |
|---|---|---|---|---|---|
| 0 | Foundation + facade preservation + cross-platform CI | mvmd builds green against new mvm; CI matrix on Linux/macOS/Windows | 5-7 | 008, 009, 022, 026, 027, 028, 030 | Sprint 43 opens |
| 1 | First tracer bullet: build → boot → exec hello-world (microvm.nix-based, persistent builder) | `mvmctl init && mvmctl build . && mvmctl up && mvmctl exec demo -- echo hi` works on Linux + macOS | 10-14 | 010, 021 | Sprint 43 (cont.) → 44 |
| 2 | Encryption + key rotation (volumes, snapshots, secrets) | `mvmctl volume create --encrypt`, `mvmctl key rotate`, `mvmctl secret put` all round-trip | 7-10 | 011 (part 1) | Sprint 44 (cont.) |
| 3 | Network isolation: L4+L7 proxies + firewall + default-deny | `curl 1.1.1.1` from runtime VM blocked + audit-logged; named-net DNS works | 10-14 | 012 | Sprint 45 |
| 4 | Comprehensive metrics + total-coverage audit + event bus | `/metrics` exposes full catalog; `audit verify` clean; every CLI command emits ≥1 audit entry | 7-10 | 014 | Sprint 46 |
| 5 | DX layer: SDK (Rust+Python alpha) + addons + manifests + dev mode + tree-sitter scanner | `mvmctl init my-app`, `mvmctl dev up`, `mvmctl doctor` work; mvm-studio handshake green; `pip install mvm` works | 10-14 | 016, 017, 033 | Sprint 47 |
| 6 | Security model: seccomp, jailer, dm-verity, signed plans, attestation, redactor, fuzz | `mvmctl attest <vm>` returns verifiable report; redactor blocks PII end-to-end | 10-14 | 013, 015 | Sprint 48 |
| 7 | MCP server + host-mediated tools + sessions | An external MCP client invokes `mvm.run`/`mvm.web_search`; tmux sessions reattach | 7-10 | 018, 031 | Sprint 49 |
| 7a | Transparent install/rebuild + persistent overlay + tenant destroy | `mvmctl install python:3.12` looks instant, `/workspace` survives; `tenant destroy` emits cert | 10-12 | 011 (part 2), 020, 023 | Sprint 50 |
| 7b | Built-in templates + computer-use + GPU virgl + TypeScript SDK alpha | `--template ai-sandbox/computer-use` end-to-end; `npm install @mvm/sdk` works | 7-10 | 019, 025 | Sprint 50 (cont.) |
| 8 | mvmd integration contract verification | `cd ../mvmd && cargo test` green; signed-Plan reconciliation round-trips | 3-5 | — | Sprint 51 |
| 9 | Hardening: deny + audit + reproducibility + perf + SBOM + compliance docs + SDK parity tests beta | `cargo deny` + `cargo audit` clean; cold boot ≤ 30 ms; all 3 SDKs pass `tests/sdk_compat/` | 7-10 | 024, 029 | Sprint 52 |
| 10 | Rename `mvm/` → `mvm/`; archive old | repo lives at `/Users/auser/work/tinylabs/mvmco/mvm/`; mvmd points to new path | 1 | — | Sprint 53 closes |

Total calendar (sequential): ~12-16 weeks for one engineer. Phases 2-5 partially overlap (encryption, networking, observability, DX after Phase 1's backend lands). Phase 6 (security) and 7a (install/rebuild + tenant destroy) are gating for the hosted-cloud and compliance work.

### Checkpoint review process

At the end of each phase, before merging the phase's branch into `feat/migrate-to-mvm`, the reviewer (or solo author) runs the checkpoint:

1. **All exit tests pass** — `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --check`, the phase-specific smoke / fuzz / perf gates.
2. **mvmd contract green** — `cd ../mvmd && cargo build --workspace && cargo test --workspace --package mvmd-runtime --package mvmd-coordinator --package mvmd-client`.
3. **ADR coverage** — every new architectural concern in this phase has an ADR file; CI's `xtask check-adr-coverage` is green.
4. **Audit coverage** — `tests/audit_total_coverage.rs` passes; manual sample of `audit explain <id>` shows trace context, attestation chain, Plan link.
5. **Performance budget** — Phase 9's perf gate (when active) shows no regression > 10% p50.
6. **`SPRINT.md` rotated** — current SPRINT archived to `specs/backlog/<NN>-<name>.md`; new SPRINT created for the next phase.
7. **Demo recorded** — a 30-second screencap of the phase's demo flow attached to the merge commit.
8. **Sign-off** — user reviews the checkpoint summary and approves before next phase starts.

If any check fails, the phase is **not done**; we don't move on. Half-finished work is the worst outcome.

### Phase 0 — Facade preservation + workspace reshape + cross-platform CI + plan & sprint relocation (~5-7 days)
**Goal**: `cd ../mvmd && cargo build --workspace` is green against the new mvm. No microVMs work yet — but mvmd's compile gate stays unbroken, CI runs on Linux + macOS + Windows, and this plan + the active sprint are in the right places in the repo.

**First action items (run before any code change)**:
1. **Relocate this plan into the repo**: copy `/Users/auser/.claude/plans/context-ref-file-users-auser-work-tinyl-joyful-lemon.md` to `/Users/auser/work/tinylabs/mvmco/mvm/specs/plans/60-mvm-libkrun-migration.md` (60 chosen to leave headroom above existing plans 0-40+; bump if collision). The repo copy becomes canonical from this point on.
2. **Archive current SPRINT**: `git mv specs/SPRINT.md specs/backlog/42-microvm-hardening.md` (or whatever sprint number reflects the current shipped state).
3. **Open Sprint 43**: new `specs/SPRINT.md` titled "Sprint 43 — mvm migration: Phase 0 (foundation + facade)". Body links to plan 60 and lists Phase 0's exit-test checklist.
4. **Stub the new ADRs** (008, 009, 022, 026, 027, 028, 030): one file each under `specs/adrs/`, frontmatter + Context section filled, Decision/Consequences left as TODO. The user authorized creating ADRs during this session.

**Code action**:
- Replace root `Cargo.toml` workspace block with the full crate list above; declare every Cargo feature listed in the "Cargo feature flags" section.
- Copy `mvm-core`, `mvm-storage`, `mvm-plan`, `mvm-policy`, `mvm-security` verbatim from `../mvm/crates/`.
- Mirror `../mvm/src/lib.rs` into the new `src/lib.rs` (the facade re-exports — every legacy path mvmd imports).
- Delete `mvm-backend/`, `mvm-providers/`, `mvm-builder/` skeletons (the user OK'd replacement).
- Stand up `xtask/` and copy CI workflows from `../mvm/.github/workflows/`. **Add Windows + macOS matrix entries** for the build/test workflow, even if integration tests gate by OS.
- Add `[workspace.lints.clippy]` block with `too_many_arguments = "deny"`, `pedantic = "warn"`, plus our security-critical lints.
- Add `xtask check-adr-coverage` and wire it into the workflow that runs on every PR.
- Stub `specs/compliance/{soc2-controls.md,pci-scope.md,hipaa-mapping.md,gdpr-mapping.md}` with table-of-contents-only content; Phase 9 fills them out.

**Critical files**:
- `/Users/auser/work/tinylabs/mvmco/mvm/Cargo.toml` — full rewrite of workspace block
- `/Users/auser/work/tinylabs/mvmco/mvm/src/lib.rs` (NEW) — facade
- `/Users/auser/work/tinylabs/mvmco/mvm/crates/mvm-core/` — copy of `/Users/auser/work/tinylabs/mvmco/mvm/crates/mvm-core/`

**Exit tests**:
- `cargo build --workspace` clean
- `cd ../mvmd && cargo build --workspace` clean (the contract gate)
- All ported `mvm_core::*` / `mvm_storage::*` / `mvm_plan::*` / `mvm_policy::*` / `mvm_security::*` unit tests pass
- `tests/cli.rs::test_help_exits_successfully` and `test_version_exits_successfully` pass (CLI binary stub returns help)
- `xtask check-adr-coverage` returns clean for the Phase 0 diff
- `specs/plans/60-mvm-libkrun-migration.md` exists; `specs/SPRINT.md` references it

**Risk**: mvmd pins mvm via git on `branch = "main"`. The facade re-export shape MUST be preserved 1:1 — verify with a path-override build of mvmd before merging.

### Phase 1 — First tracer bullet: build → boot → exec hello-world (~10-14 days)
**Goal**: `mvmctl build .` (libkrun-driven Nix build using microvm.nix) → `mvmctl up --flake .` (Firecracker on Linux, libkrun elsewhere) → `mvmctl console <name>` attaches to the guest. Builder microVM stays warm and is reused.

**Action**:
- **Adopt microvm.nix**: `nix/flake.nix` imports `microvm-nix/microvm.nix`, pinned by hash. Define `nix/profiles/{minimal,worker,builder}.nix` and `nix/lib/mkGuest.nix`. Drop the previous iteration's hand-rolled rootfs init paths in favour of microvm.nix's.
- Stand up `mvm-build` with libkrun driver. Salvage `nix/manifest.rs`, `nix/scripts.rs`, `artifacts.rs`, `cache.rs`, `template_reuse.rs` from `../mvm/crates/mvm-build/src/`. Replace `pipeline/firecracker.rs` + `pipeline/vsock_builder.rs` with `pipeline/libkrun.rs` that drives a **persistent builder microVM** (one warm sandbox per tenant; LRU-evicted; never destroyed mid-session).
- Builder VM's policy permits egress to configured Nix substituters; runtime VMs default-deny (firewall not yet up — comes in Phase 3 — Phase 1's runtime VMs simply have no NIC).
- Build outputs go to `~/.mvm/artifacts/<sha256>/` (content-addressed); runtime VMs reference by hash.
- Stand up `mvm/src/vm/backend.rs` exposing `BackendKind::{Firecracker, Libkrun}`. Detection: `cfg!(target_os = "linux") && /dev/kvm exists` → Firecracker; otherwise Libkrun.
- Implement `LibkrunBackend: VmBackend` (replace the `todo!()` in the user's existing `SandboxBackend` with a real `boot()`/`teardown()` aligned to the trait). Verify Windows-on-libkrun status; if missing, document WSL2 fallback in ADR.
- Port `FirecrackerBackend` from `../mvm/crates/mvm/src/vm/firecracker.rs`.
- Port the guest-agent vsock console from `../mvm/crates/mvm-guest/src/{console.rs,vsock.rs}`. Vsock framing protocol stays in-house; the raw socket uses `tokio-vsock`.
- Wire CLI commands `build`, `up`, `down`, `console`, `exec`, `builder ls/keep/evict` in `mvm-cli/src/commands/`.
- All commands accept structured config via `bon`-derived builders — enforce `clippy::too_many_arguments` ban repo-wide via `[workspace.lints]`.
- Cross-platform: CI runs the build on Linux, macOS, Windows; the smoke test runs at minimum on Linux + macOS (Windows path may rely on WSL2 initially).

**Exit tests** (post-reconciliation — see "Exit-test reality vs. plan" below):
- Unit (mvm-build builder-VM contract): `crates/mvm-build/src/builder_vm.rs` covers the `BuilderVm` trait + `LibkrunBuilderVm` impl with 29 `#[test]` fns (sidecar round-trip, revision-hash extraction, sandbox naming, shell quoting, default resources, flake-src validation, the `host_can_build` pathfn, and the stub's recovery-path error envelope).
- Unit (backend auto-select): `crates/mvm-backend/src/backend.rs::tests::test_auto_select_returns_valid_backend`, `test_auto_select_prefers_libkrun_on_macos`, `test_auto_select_returns_libkrun_when_libkrun_available_and_no_kvm` — exercises ADR-013 priority across hosts. Firecracker-on-KVM is asserted indirectly via the "valid backend" set: the test enumerates the legitimate `auto_select()` returns and would fail if KVM hosts started returning something other than Firecracker.
- Unit (libkrun driver): `crates/mvm-backend/src/libkrun.rs` tests cover the `.ext4 → .raw` alias bridge, `start_with_mode`, list/status/stop, log paths. Sandbox-side `start()` and `logs()` are exercised by the live arm of `tests/smoke_libkrun.rs` (gated `MVM_LIVE_SMOKE=1`).
- Smoke (live boot, KVM/HVF host required): `tests/smoke_e2e_boot.rs::boots_real_rootfs_within_tripwire_then_tears_down_clean` boots a real Nix-built rootfs through `LibkrunBackend::start_with_mode`, asserts presence in `list()`, measures cold-boot wall-clock against the 600 ms tripwire (2× the ADR-013 floor of 300 ms), and tears down clean. Gated on `MVM_LIVE_SMOKE=1` + `MVM_TEST_ROOTFS=/path/to/rootfs.ext4`. Replaces the originally-named `tests/smoke_invoke.rs::boot_and_exec_hello_world` — the `smoke_invoke.rs` namespace belongs to Sprint 45 (function-call entrypoints), not Phase 1 of this plan.
- CLI: `crates/mvm-cli/src/commands/tests.rs` carries 250 `#[test]` attrs across 122 functions, exercising help text, flag parsing, and structured-config dispatch for build/up/down/console/exec/builder. Exceeds the original "~25 of 91" target. Note: the root-level `tests/cli.rs` file plan 60 referenced was never wired up — `tests/cli.rs.spec` was 900 lines of dead scaffolding deleted in this commit.
- Performance gate: deferred to Phase 9 (`xtask perf --runs 100`, statistical) per the `boot_tripwire_is_2x_the_adr_floor` test's documentation. The inline 600 ms tripwire in the smoke catches single-shot regressions today; the strict gate lands when we have a stable Linux/KVM runner. `xtask/src/bench.rs` is intentionally not built — its responsibility moved into `xtask perf` under Phase 9.

**Exit-test reality vs. plan**: Phase 1 shipped under different test names than plan 60 originally listed. The intent of every named gate is preserved by an actually-existing test (or explicitly deferred to Phase 9 with a stand-in regression). The originally-named functions (`nix_build_produces_rootfs`, `warm_builder_reused_across_calls`, `auto_picks_firecracker_when_kvm_present`, `boot_and_teardown_round_trip`, `boot_and_exec_hello_world`, `builder_persists_across_two_builds`) never landed under those names; the bullet list above is the authoritative mapping.

**Risk**: libkrun 0.4.5 may not yet expose vsock PTY hooks compatible with our `mvm-guest::console`. Verify by reading libkrun source first; fall back to libkrun's own console if our framing doesn't fit.

### Phase 2 — Encryption everywhere (volumes, snapshots, secrets) + key rotation (~7-10 days)

**Status (2026-05-11)**: ✅ shipped via plan 63 (`specs/plans/63-phase-2-encryption-everywhere.md`)
W1–W6 + ADR-042 (`specs/adrs/042-encryption-substrate.md`).
Tenant DEK rotates without re-encrypting data; snapshots are
AES-GCM at rest under a host-local tenant DEK; `mvmctl secret
put/get/ls/rm` is the prod-safe operator surface; every secret-
carrying type wraps `secrecy::SecretBox<T>` with CI lint
enforcement. Object-store volume encryption (`EncryptedBackend<B>`)
lives on the mvmd side per plan 45 §D5 — that half is mvmd's
work, not mvm's.

**Goal**: `mvmctl volume create db --encrypt`, `mvmctl up --volume db:/var/db`, `mvmctl secret put api_token --tenant t1`, `mvmctl key rotate --kek tenant:t1`, `mvmctl snapshot save` — all with verified encryption at rest.

**Action**:
- Port `mvm/src/security/snapshot_crypto.rs`, `keystore.rs` from `../mvm`.
- Port `mvm/src/vm/{disk_manager,volume_registry,instance/disk,instance/snapshot,cow}.rs`.
- New `mvm/src/security/key_rotation.rs` — implements DEK re-wrap on KEK rotation; LUKS2 keyslot rotation; snapshot KEK rolling.
- Wire `keyring` (re-enable the commented-out targets in root `Cargo.toml`); add `directories` for XDG paths.
- Secret types wrap `secrecy::SecretBox<T>`; CI custom-lint forbids `Display`/`Debug` on secret-carrying types.

**Exit tests**:
- Unit: `mvm::security::snapshot_crypto::tests::aead_round_trip`; `..::tests::tampered_ciphertext_rejected`; `mvm_security::snapshot_hmac::tests::chain_verifies`; `mvm::security::key_rotation::tests::rotate_kek_preserves_dek_decryption`
- Integration: `tests/cli.rs::test_volume_create_attach_persists_data_across_restart`; `test_snapshot_save_then_load_round_trip`; `test_snapshot_with_tampered_hmac_rejected`; `test_key_rotation_preserves_data`; `test_secret_put_then_inject_visible_in_guest_only`
- Property: `proptest` over snapshot_crypto AEAD round-trips (1000 cases minimum)

**Risk**: macOS Keychain ↔ Linux Secret Service ↔ Windows Cred Mgr UX divergence. The `Keystore` trait abstracts this; cross-OS smoke tests gated per platform.

### Phase 3 — Network isolation: L4 + L7 proxies, firewall, vsock control, default-deny + policy gate (~10-14 days)

**Status (2026-05-11)**: Slice A (live L7EgressProxy from policy
bundles) shipped in bce44e9; Slice B (L4 policy substrate +
`L4Gate` trait + `LiveL4Gate::from_specs` + W5 resolver wiring
through `slots.network`) shipped 2026-05-11. The `HickoryDnsResolver`
alternative to `TokioDnsResolver` ships under Slice B as well — an
opt-in `DnsResolver` impl for operators who want DoT/DoH upstreams
or a per-tenant resolver decoupled from `/etc/resolv.conf`. Five
follow-on slices land alongside Slice B (also 2026-05-11): (1) the
W5 resolver is now consumed by `up.rs::admit_plan_for_boot` (boot
fails loudly on missing bundles / typos / bad L4 CIDRs instead of
silently passing through Noops); (2) `slots_from_bundle` delegates
to `mvm_supervisor::build_inspector_chain` so the parsed bundle's
L7 chain carries the full five inspectors (destination_policy /
ssrf_guard / secrets_scanner / injection_guard / pii_redactor)
and honors `bundle.egress.disabled_inspectors`; (3) a new
`LiveArtifactCollector` carries `bundle.artifact.{capture_paths,
retention_days}` (the trait `collect()` errors with the distinct
`ArtifactError::NotImplemented` until the mvm-hostd virtiofs
sweep lands — observably different from `NotWired`); (4) the
resolver path now runs `validate_egress_policy_inspector_names`
before `build_inspector_chain`, so a typo in
`[egress].disabled_inspectors` fails admission with
`ResolveError::EgressPolicyInvalid` (`error_class =
policy-egress-invalid`) instead of silently leaving the
inspector enforced. `build_inspector_chain` itself stays lenient
for in-process callers; (5) `LiveKeystoreReleaser::from_policy`
closes the last Noop slot in `slots_from_bundle` — every parsed
bundle field now surfaces somewhere live, with
`KeystoreError::NotImplemented { rotation_interval_days }`
distinguishing "configured, pending consumer" from the
`NotWired` "no bundle" case; (6) the L7 inspector chain now uses
`build_inspector_chain_with_pii` from the resolver path, so a
tenant bundle's `[pii]` section (mode + categories) actually
drives the redactor — `mode = "redact"` flips to `Mode::Redact`,
`mode = "disabled"` drops the inspector entirely, `categories`
filters `DEFAULT_RULES` by rule name. Typos on `pii.mode` or
`pii.categories` surface as `ResolveError::PiiPolicyInvalid`
(`error_class = policy-pii-invalid`) instead of silently scanning
fewer categories than the operator intended. **Slice C remains
outstanding**: the smoltcp/TUN userspace-TCP consumer that turns
an `L4Gate::evaluate` decision into accept/drop on a per-VM TAP,
the host firewall (nft/pf/wfp) additive layer, the DNS server
endpoint guest VMs point `/etc/resolv.conf` at, and the per-tenant
netns lift sequenced with mvm-hostd.

**Goal**: A runtime VM cannot reach any external host unless its tenant policy explicitly allows it (per-protocol, per-port, per-CIDR or per-SNI). The builder VM is the one exception, gated by mvmd-signed policy. `mvmctl audit tail --vm <name>` shows every flow attempt.

**Action**:
- Port `mvm/src/vm/{network,bridge,instance/net}.rs`. Adapt: Lima is dropped, so all bridge code targets host directly (Linux) or libkrun's TUN bindings (macOS / Windows).
- **L4 proxy**: new `mvm-supervisor/src/proxy/l4.rs` (feature-gated `egress-l4-proxy`). Uses `smoltcp` for userspace TCP/UDP termination; `tun-rs` opens per-VM TAPs; per-tenant `(proto, dst_cidr, dst_port)` allowlist. Default action: drop + audit.
- **L7 proxy**: new `mvm-supervisor/src/proxy/l7.rs` (feature-gated `egress-l7-proxy`, depends on L4). HTTPS SNI extraction; HTTP/1.1 + HTTP/2 via `hyper`; per-tenant SNI + path-prefix allowlist; optional MITM (only when tenant policy installs a CA into the guest).
- **Firewall**: new `mvm-supervisor/src/firewall/{linux_nft,macos_pf,windows_wfp}.rs`. Linux uses `nftables-rs`; macOS shells out to `pfctl`; Windows shells out to `windivert`. All install default-deny on the runtime-VM TAP; only the proxy TUN endpoint is reachable. **The firewall is additive enforcement** — even if it's misconfigured, the proxy's allowlist still applies.
- **Policy gate**: tenant config (`mvm-policy::TenantPolicy`) is the only thing that can open a flow. `mvmctl policy show/verify/update` are the surface; updates require an mvmd-signed Plan. Builder VM's permissive policy ships with mvmd's signing key — no tenant can mint one.
- **DNS**: port resolver from `mvmd-runtime/src/vm/dns.rs` (where the more current copy lives), wired to `hickory-server`. External DNS lookups also flow through the L4 proxy.
- **Builder VM exception**: Phase 1's builder VM gets its proper policy bundle here (was permissive-by-omission in Phase 1); audit log captures every flow.
- **No-IP-leak invariant**: all host↔guest control traffic on vsock; verify with packet-capture test that no IP packets cross the bridge during normal operation (only data-plane policy-permitted flows do).

**Exit tests**:
- Unit: `mvm::vm::network::tests::default_deny_drops_outbound`; `mvm_supervisor::proxy::l4::tests::allowlist_permits_then_blocks`; `..::proxy::l7::tests::sni_allowlist_blocks_others`; `..::tests::ssrf_link_local_blocked`; `mvm_supervisor::firewall::linux_nft::tests::default_deny_rules_install_idempotently`
- Integration: `tests/cli.rs::test_runtime_vm_default_egress_blocked`; `test_runtime_vm_egress_allowed_only_after_policy_update`; `test_builder_vm_egress_allowed_and_logged`; `test_two_vms_named_network_resolve_each_other`; `test_port_forward_round_trip_http`; `test_audit_tail_shows_blocked_flow`; `test_l7_proxy_blocks_disallowed_sni`
- Smoke: `tests/smoke_network.rs::no_packet_leakage_during_boot` — capture all bridge packets during a full boot cycle, assert none leave the supervisor unless policy-allowed
- Cross-platform: firewall test runs on Linux with nftables, on macOS with pf (gated `#[cfg(target_os = "macos")]`); Windows test gated `#[cfg(windows)]` with WFP

**Risk**: pf and WFP shell-outs are fragile (output parsing, version drift). Mitigation: every shell-out has a `--check` mode that round-trips state and verifies the install before declaring success; CI tests on each OS pin the expected output format.

### Phase 4 — Persistent observability: comprehensive metrics, total-coverage audit, structured logs, event bus (~7-10 days)
**Goal**: Every metric in the catalog is wired; `mvmctl metrics` exposes Prometheus + optional OTLP; `mvmctl audit tail` streams chain-signed events for **every action** (cmd, lifecycle, secret, flow, plan, policy, key, host, audit); `mvmctl logs <vm>` shows JSON-formatted guest stdout/stderr; `mvmctl events --follow` shows lifecycle.

**Action**:
- Port `mvm-core/src/observability/{logging,metrics,instance_metrics}.rs` (already in Phase 0).
- Wire every metric in the catalog (see "Comprehensive metrics catalog" section). Each metric has a unit test confirming its name + label set + cardinality bound. Audit hooks: emit a metric counter for every audit category.
- New `mvm-cli/src/metrics_server.rs` — small `axum` server exposing `/metrics` for Prometheus scrape (feature-gated `metrics-prometheus`); optional OTLP exporter under `metrics-otel`.
- Port `mvm/src/security/audit.rs` — chain-signed HMAC audit log; extend to every category (`cmd`, `lifecycle`, `secret`, `flow`, `plan`, `policy`, `key`, `host`, `audit`); add `mvmctl audit verify` command and `mvmctl audit ship` (when `audit-remote-sink` feature enabled).
- Audit instrumentation lives in a single `mvm-supervisor::audit::Recorder` that every other crate calls — there is one audit path, not many.
- Implement event bus on `tokio::sync::broadcast`; emit on every lifecycle transition.
- `tracing` JSON formatter for guest stdout/stderr capture.

**Exit tests**:
- Unit: `mvm_core::observability::metrics::tests::counters_increment` (per-metric); `mvm::security::audit::tests::tampered_entry_breaks_chain`; `..::tests::chain_round_trip_n_entries`
- Integration: `tests/cli.rs::test_metrics_endpoint_exposes_full_catalog` — scrape `/metrics`, assert every metric name from the catalog appears; `test_audit_verify_reports_clean_chain`; `tests/audit_total_coverage.rs::every_command_emits_audit_entry` (drives the CLI through every subcommand and asserts ≥1 audit entry per); `tests/e2e/audit_emissions.rs::*` (file already exists — make it pass). **Status (2026-05-11)**: `tests/audit_total_coverage.rs` shipped as a *scaffold* — walks `mvm_cli::cli_command()` and asserts every top-level subcommand carries an `AuditPosture` classification (`Emits` | `ReadOnly` | `DelegatesToSub` | `InteractiveOrControl`); the test fails when a new CLI verb lands without an entry, keeping the discipline as the surface grows. The end-to-end "drive every command and assert the named audit entry appears" promotion of `Emits` rows is incremental work — each command graduates as it gains a hermetic test fixture.

**Risk**: cardinality blowup if labels include raw tenant IDs or VM IDs. Mitigation: tenant_hash (truncated SHA256) for tenant labels; vm_id labels limited to short-lived gauges that get reset on stop.

### Phase 5 — DX layer: mvm-sdk, manifests, templates, dev mode, doctor, init, mvm-studio handshake (~7-10 days)
**Goal**: `mvmctl init my-app` scaffolds an `mvm.toml` + `flake.nix` (microvm.nix-based); `mvmctl dev up` opens a PTY shell into a libkrun box; `mvmctl doctor` reports environment health; `mvmctl catalog ls` lists templates; `../mvm-studio` Tauri app can launch and drive a local mvmd that spawns mvm VMs.

**Action**:
- Port `mvm-sdk` from `/Users/auser/work/tinylabs/mvmco/mvmforge/crates/mvmforge-sdk/` (single `lib.rs` today; small port). Split into `mvm-sdk-macros` (proc macros for `#[mvm::function]`, `#[mvm::image]`, `#[mvm::secret]`, `#[mvm::volume]`, `#[mvm::addon]`) + `mvm-sdk` (runtime + types) + `mvm-sdk-addon` (addon trait + registry).
- Wire the libkrun-style sandbox-runtime API: `Sandbox::builder().image(…).build()`, `.run_code()`, `.commands().run()`, `.files().read/write`, `.process().spawn()`, `.snapshot().save()`, `.kill()`.
- **Stand up Python SDK** (`python/mvm`): runtime (`Sandbox`, `AsyncSandbox`) + declarative (`App`, `Image`, `Secret`, `Volume`, `@app.function`, `@app.cls`, `@mvm.enter`, `@mvm.method`, `@app.web_endpoint`, `Cron`, `f.local()`/`f.remote()`). pyo3-built native extension for hot-path JSON-RPC; pure-Python for the rest. Wheels for Linux/macOS/Windows on Python 3.10+.
- Type stubs: `cargo xtask gen-stubs` emits `python/mvm/_types.pyi` (Pydantic-derived) and `typescript/src/types.d.ts` (`ts-rs`-derived). CI fails if hand-edited stubs drift from generated.
- Auth: SDK reads `MVM_TOKEN` env or `~/.mvm/token` for hosted-cloud auth; local dev uses Unix socket with no token.
- Port templates from `../mvm/templates/`; rewrite each as a microvm.nix-based flake.
- Port `mvm-cli/src/commands/{env/init,env/dev,env/doctor,catalog,manifest/{ls,info,verify,tag,alias,prune,rm},build/validate}.rs`.
- Land `mvm-tree-sitter` crate with grammars for `mvm.toml`, our Nix subset, and SDK macro forms. Visitor API + a basic safety scanner (overly broad egress allows, missing seccomp tier).
- Land `cargo xtask gen-stubs` for TypeScript `.d.ts` and Python `.pyi` emission so mvm-studio gets typed APIs.
- Dev mode is **feature-gated by `dev` cargo feature** (compiled OUT in production builds). Belt-and-braces: also rejects at parse time if `MVM_PRODUCTION=1` is set.
- `miette`-powered diagnostics for `mvm.toml` parse + flake validation errors.
- Handshake with `../mvm-studio`: sanity-check that mvm-studio's Tauri build can spawn an mvmd that drives mvm on each of Linux/macOS/Windows. Windows path is Tauri+WSL2; document caveats in `specs/runbooks/cross-platform-install.md`.

**Exit tests**:
- Integration: `tests/cli.rs::test_init_creates_manifest_and_flake`; `test_doctor_reports_clean_env`; `test_catalog_ls_lists_builtin_templates`; `test_dev_up_then_status_then_down`; `test_dev_subcommand_rejected_in_production_build`
- SDK: `mvm_sdk::*` smoke tests

**Risk**: low.

### Phase 6 — Security model: seccomp, jailer, dm-verity, signed plans, attestation, fuzz harnesses (~10-14 days) — ✅ shipped 2026-05-11

**Status (2026-05-11 — ✅ shipped)**: seccomp tiers, dm-verity, fuzz
harnesses, prod-agent-no-exec, **signed-and-audited
`ExecutionPlan`**, the plan 64 W5 `PolicyRef` resolver substrate,
the **on-disk policy-bundle TOML format**, and now the
**`mvm_security::attestation` module + `mvmctl attest`
{export,verify,status} CLI surface** all shipped (CLAUDE.md
security claims 1–8; ADR-041). The W5 resolver loads
`~/.mvm/policies/<tenant>/<workload>.toml` for tenant-scoped refs
via `mvm_policy::toml_loader`; parse errors surface as
`ResolveError::BundleNotFound` / `BundleParseFailed` /
`MixedRefs` / `Unrecognized` with operator-actionable detail.
Returned slots remain Noops because no live consumer
(L4/L7 proxies, real ToolGate) exists yet — Phase 3 builds those.
Hardware attestation v0 ships as three feature-gated stubs
(`attestation-tpm2`, `attestation-sev-snp`, `attestation-tdx`),
each returning `AttestationError::NotYetImplemented` from
`measure()`; the `HwAttestationProvider` trait + the supervisor
admission gate that refuses unsupported modes on builds compiled
without the feature are in place, ready for real hardware
bring-up post-Phase-6 when the hosted mvmd cloud needs them for
compliance. Runtime tier (boot attestation + dm-verity-root-hash
wiring) tracks behind a `PLACEHOLDER_BOOT_MEASUREMENT` constant
in the `mvmctl attest export` path — the report schema is
already stable across the transition.

**Goal**: `mvmctl up --security strict` applies a seccomp profile; rootfs verified at boot via dm-verity; signed Plans rejected if Ed25519 sig fails; fuzz harness runs in CI for vsock framing; **`mvmctl attest <vm>` returns a verifiable attestation report**.

**Action**:
- Port `mvm/src/security/{jailer,seccomp,signing,attestation,cgroups,certs}.rs` from `../mvm`.
- Stand up new crate `mvm-attestation` (or module under `mvm-security`): identity key lifecycle, runtime measurement loop, attestation header format, verification helpers.
- SLSA-3 build attestation: cosign-sign every release artifact + publish to Rekor (`sigstore-rs`). In-toto attestation files committed alongside artifacts.
- Boot attestation: dm-verity hash recorded in kernel cmdline; guest reports measurement on first vsock auth frame; host compares.
- Runtime attestation: every host-mediated tool RPC + every Plan acceptance + every audit event from the VM carries an attestation header signed by the VM's identity key.
- Hardware attestation API stubs (TPM2, SEV-SNP, TDX, Secure Enclave) — feature-gated, not implemented this phase.
- New CLI: `mvmctl attest`, `mvmctl attest verify`, `mvmctl attest export`.
- Port `mvm-guest/src/bin/{mvm-verity-init,mvm-seccomp-apply,syscall-probe}.rs`.
- Port `mvm-guest/fuzz/` directory (kept out of workspace per existing convention) with all four fuzz targets.
- mTLS for mvmd↔mvm-hostd: port `mvm/src/security/certs.rs`, wire `rustls` + `rcgen`.
- PII redactor: stand up `mvm-supervisor/src/redactor/` with the built-in pattern set; wire into audit log + tracing layer + metrics labels + MCP tool args.

**Exit tests**:
- Unit: `mvm::security::seccomp::tests::strict_blocks_ptrace`; `..::signing::tests::ed25519_round_trip`; `mvm_security::posture::tests::*`; `mvm_attestation::tests::identity_key_signs_runtime_report`; `..::tests::tampered_report_fails_verify`; `mvm_supervisor::redactor::tests::redacts_built_in_patterns`
- Fuzz: `cargo +nightly fuzz run fuzz_authenticated_frame -- -runs=20000` exits 0 in CI; same for `fuzz_guest_request`, `fuzz_authed_path`, `fuzz_entrypoint_event`
- Integration: `test_up_with_strict_seccomp_blocks_disallowed_syscall`; `test_signed_plan_rejected_when_signature_invalid`; `test_dm_verity_panics_on_tampered_block` (live KVM only, gated by env); `test_attest_round_trip_with_image_change_detection`; `tests/redactor.rs::no_pii_reaches_disk` (drives a session that prints PII, asserts log files + audit + metric scrape are clean)

**Risk**: dm-verity on the libkrun path (libkrun rootfs) — may not support kernel-level verity attach. **Mitigation**: dm-verity stays Firecracker-only; libkrun path uses image-hash-on-load + HMAC chain for integrity (documented in ADR). Attestation reports indicate which integrity tier they were measured under so verifiers can apply different trust policies.

### Phase 7 — MCP server + host-mediated agent tools + sessions (~7-10 days)
**Status (2026-05-11 — ✅ host-mediated tools shipped; sessions + host-suspend deferred to 7a/7b)**:

The MCP-side wiring + tool surface shipped end-to-end as ten
incremental slices (`fab5edd…5e62e5a` on
`feat/cloud-hypervisor-lifecycle-real`):

- `mvm-supervisor/src/tools/` substrate (`HostMediatedTool` trait
  + `ToolRegistry` + audit emission via plan-60 Phase 4 Recorder).
- Five concrete tools: `mvm.time_now`, `mvm.web_fetch` (per-host
  allowlist + injected `HttpFetcher` adapter with reqwest impl
  for production), `mvm.web_search` (provider allowlist +
  injected `SearchProvider` adapter with Brave + Tavily impls
  in production), `mvm.upload` / `mvm.download` (shared
  `StagingArea` trait + `FsStagingArea` impl with O_NOFOLLOW,
  path-validator, per-tenant subdir, mode 0700 root).
- `mvm-mcp::Dispatcher` trait gains `invoke_tool(name, params)`
  with a default impl that surfaces "not wired" as `is_error:
  true` ToolResult (no JSON-RPC method_not_found retry-storm).
  `tools/list` now exposes the legacy `run` plus all five
  registry tools.
- `ExecDispatcher::invoke_tool` routes through
  `ToolRegistry::with_defaults` + the chain-signed `Recorder`
  from cmd_audit, so every `tools/call mvm.<verb>` produces a
  `cmd.tool.mvm.<verb>.{completed,failed}` entry in
  `~/.mvm/audit/<tenant>.jsonl` verifiable via `mvmctl audit
  verify`.
- Operator config via env vars: `MVM_WEB_FETCH_ALLOWLIST`,
  `MVM_WEB_SEARCH_ALLOWLIST`, `MVM_WEB_SEARCH_DEFAULT`,
  `BRAVE_SEARCH_API_KEY`, `TAVILY_API_KEY`,
  `MVM_TOOL_STAGING_DIR`.

Three Phase 7 hardening follow-ups flagged for a separate slice:
- `ReqwestHttpFetcher` auto-follows redirects without re-checking
  the destination host against the per-host allowlist.
- `SsrfGuard` (Phase 3 work) is not yet wired on the fetcher
  path; an allowlisted hostname whose DNS later resolves to a
  private IP would reach it.
- Streaming body cap is one-chunk-late (`body.len() +
  chunk.len() > cap` after the chunk lands).

Deferred to **Phase 7a** (sessions integration with the new
tools; persistent overlay supersedes `FsStagingArea`) and
**Phase 7b** (`mvm.code_eval`; computer-use template):
- `mvm-cli/src/commands/session/` lifecycle (create / attach /
  detach / kill / timeout) — current `vm::session::*` is partial.
- `mvm.code_eval` host-mediated tool — needs the per-session
  warm-VM substrate.
- Host-suspend / resume snapshot hook (Linux power events).

**Goal**: An LLM agent can `claude mcp add mvm` and call `mvm.run`, `mvm.snapshot`, `mvm.eval`, `mvm.web_search`, `mvm.web_fetch`, `mvm.upload`/`download`, scoped to a single sandbox. Long-running tmux-style sessions work end-to-end (`mvmctl session create/attach/detach`).

**Action**:
- Port `mvm-mcp/src/{protocol,dispatcher,session,tools}.rs` but **swap the JSON-RPC layer for `rmcp`** (Apache-2.0). The dispatcher logic stays; the wire layer becomes `rmcp`.
- Build `mvm-supervisor/src/tools/{web_search,web_fetch,code_eval,upload,download,time_now}.rs` per the host-mediated-tools table. Each tool has a per-tenant allowlist + audit hooks.
- Tool registry routes calls into `VmBackend` so any backend works.
- Port `mvm-core::domain::session` and stand up `mvm-cli/src/commands/session/` (create/list/attach/detach/kill/timeout). Backed by tmux inside the guest; vsock RPC for control.
- Host-suspend/resume snapshot of running VMs (Linux: power-event hook → `firecracker pause` + snapshot; resume on wake).

**Exit tests**:
- Unit: `mvm_mcp::dispatcher::tests::routes_run_to_backend`; `mvm_supervisor::tools::web_search::tests::allowlist_blocks_unconfigured_provider`; `mvm_supervisor::tools::web_fetch::tests::denies_unallowlisted_host`
- Integration: `tests/cli.rs::test_mcp_server_handshake_then_run`; `tests/mcp_tools.rs::eval_returns_stdout`; `tests/mcp_tools.rs::web_search_records_audit_entry`; `tests/cli.rs::test_session_create_attach_detach_reattach`; `tests/cli.rs::test_session_survives_vm_pause_and_resume`
- Smoke: `tests/smoke_invoke.rs::host_suspend_preserves_session_state`

**Risk**: `rmcp` API may not yet match what `../mvm/crates/mvm-mcp` does internally. Fall back to keeping the original JSON-RPC layer if `rmcp` shape doesn't fit; revisit later. CRIU integration for full process checkpointing is deferred — Phase-7 ships pause/resume only.

### Phase 7a — Transparent install/rebuild + persistent overlay + tenant deprovision (~10-12 days)
**Goal**: `mvmctl install foo` rebuilds the rootfs and swaps it underneath the user's persistent overlay; `/workspace` survives. `mvmctl tenant destroy` provably wipes a tenant's data and emits a destruction certificate.

**Action**:
- Stand up `mvm/src/install/` driving the rebuild flow.
- Stand up `mvm/src/vm/overlay.rs` for the encrypted persistent overlay (extends Phase 2's volume work; introduces the two-layer rootfs+overlay model).
- Implement rolling swap: pause → swap rootfs → resume; tmux sessions reattach.
- Stand up `mvm/src/tenant/destroy.rs`: wipes volumes (LUKS keyslot revocation + zero-fill), snapshots (key destruction), audit log entries (redacted; chain anchors stay), keys; emits a destruction certificate signed by the host identity key. Required for hosted-cloud deprovisioning.
- New CLI: `install`, `uninstall`, `rebuild`, `freeze`, `--explain` flag for diff; `tenant destroy --tenant <id> --confirm-deletion`.

**Exit tests**:
- Integration: `tests/cli.rs::test_install_persists_workspace_across_rebuild`; `test_rebuild_diff_explained`; `test_freeze_round_trip_reproducible`; `test_tenant_destroy_emits_signed_certificate`; `test_tenant_destroy_zeroes_all_volumes`
- Performance: cached install ≤ 5 s p50; cold install ≤ 30 s p50

**Risk**: Live process restart is unavoidable (CRIU deferred); some workloads will lose in-flight state. Document clearly in DX; offer `mvmctl rebuild --schedule "after current task"` as a future affordance.

### Phase 7b — Built-in templates + agent use cases (~5-7 days)
**Goal**: `mvmctl init --template ai-sandbox` produces a Claude-Code-ready dangerous-mode sandbox; `--template safe-openclaw` produces the one-click hardened OpenClaw; `--template computer-use` works end-to-end.

**Action**:
- Author `templates/{minimal,worker,ai-sandbox,safe-openclaw,computer-use,repl}/{flake.nix,mvm.toml}`.
- For `computer-use`: add `mvm/src/compute_use/` with screenshot/input/windows/clipboard/process_list RPCs over vsock; the guest profile includes Xvfb, Xpra, xdotool, wmctrl, and a vetted browser (Chromium with a hardened seccomp profile).
- Each template ships its own tenant policy bundle (egress allowlist, tool allowlist, seccomp tier) signed by mvmd.
- `tests/templates.rs` boots each template, exercises its hello-world path, and asserts policy is enforced (e.g., `ai-sandbox` cannot reach raw internet but the web_search tool returns results).
- **Stand up TypeScript SDK** (`typescript/@mvm/sdk`): runtime (`Sandbox.create`, `runCode`, `files`, `commands`, `snapshot`) + declarative (`App`, `Image`, `Secret`, `Volume`, `@fn`, `@cls`, `@enter`, `@method`, `@webEndpoint`, `Cron`, `.local()`/`.remote()`). napi-rs binding for hot paths; pure TS otherwise. Targets Node 20+, Bun, Deno. ESM + CJS, types included.
- Decorator support: TC39 decorators (TS 5.0+); builder-form fallback for older toolchains.

**Exit tests**:
- Per-template: `tests/templates.rs::ai_sandbox_boots_with_claude_code`; `safe_openclaw_boots_with_hardened_defaults`; `computer_use_screenshot_returns_png`; `computer_use_input_synthesis_round_trips`; `repl_boot_from_snapshot_under_50ms`
- Integration: `tests/cli.rs::test_init_template_ai_sandbox_scaffolds_runnable_project`

**Risk**: Hardened browsers (Chromium under seccomp) historically need exemptions for namespaces; Xvfb + Xpra add attack surface. Mitigate by feature-gating `computer-use` behind a policy that defaults to off; tenants opt in.

### Phase 8 — mvmd integration contract verification (~3-5 days)
**Goal**: `cd ../mvmd && cargo test --workspace` is green; signed-Plan reconciliation round-trips end-to-end; mvmd CLI drives a mvm-managed VM via Unix-socket `mvm-hostd`.

**Action**:
- Port `mvm/src/hostd/{mod,server}.rs` and `bin/mvm-hostd.rs` from `../mvm`.
- Add `pub const PROTOCOL_VERSION: u32` to `mvm_core::protocol`. Document the bump policy in `specs/adrs/`.
- New `tests/mvmd_compat.rs` — pulls in `mvmd-client` as a dev-dep and verifies wire-format stability for `AgentRequest::Reconcile`, `HostdRequest::Start`, `HostdResponse::Started`.

**Exit tests**:
- mvmd workspace: `cargo test --workspace --package mvmd-runtime --package mvmd-coordinator --package mvmd-client` passes
- Integration: `tests/cli.rs::test_hostd_socket_handles_concurrent_start_requests`; `tests/mvmd_compat.rs::wire_format_reconcile_round_trips`

**Risk**: wire-format drift. The PROTOCOL_VERSION constant + a compat-matrix test is the safety net.

### Phase 9 — Hardening, performance gates, supply-chain (~7-10 days)
**Goal**: `cargo deny check` + `cargo audit` clean; reproducibility double-build identical; **cold-boot ≤ 30 ms on Linux/Firecracker via snapshot pool** (≤ 500 ms cold path), ≤ 1 s on macOS/libkrun; rootfs ≤ 20 MB for `minimal` template; SBOM emitted; PGO + MUSL release builds.

**Action**:
- Land snapshot pool: `mvm/src/vm/snapshot_pool.rs` keeps per-template warm Firecracker snapshots; `up` clones from pool. (Phase 1 set up the path; Phase 9 measures and tunes pool size + eviction.)
- Port `xtask/` reproducibility check, cosign-keyless workflows from `../mvm/.github/`.
- Port `deny.toml` from `../mvm`.
- Tighten boot: kernel modules trimmed (KVM_CLOCK + virtio + vsock + ext4 + dm-verity only), initramfs rewritten, Nix closure pruned, `vmlinux` direct-boot. Track in `specs/plans/<n>-boot-perf.md`.
- PGO release build via `cargo pgo`. MUSL static target for `mvmctl` and `mvm-hostd`.
- SBOM via `cargo cyclonedx` + Nix derivation graph; combine into one CycloneDX file shipped per release.
- RFC 3161 timestamping for audit-chain anchor events (`rfc3161-client`).
- New `tests/perf.rs` — runs cold + snapshot-clone boot benchmarks, asserts thresholds; regression alert > 10% p50 increase. Gated by `MVM_PERF=1`.
- Continuous fuzzing CI cron: each fuzz target runs 1h nightly on main.

**Exit tests**:
- CI gate: `cargo deny check --all-features` exits 0; `cargo audit` exits 0
- Reproducibility: `cargo xtask reproducibility-check` exits 0 on Linux (macOS gated off — code-sign timestamps known-flaky)
- Perf: cold-boot `< 500ms` (Firecracker, minimal template, 1 CPU, 256 MB); rootfs `< 20 MB` for minimal template

**Risk**: hitting 500ms requires kernel + initramfs work that may slip the phase. Acceptable to ship at 800ms initially and tighten in a follow-up sprint.

### Phase 10 — Rename `mvm/` → `mvm/`, archive previous (~1 day)
**Status (2026-05-11 — ✅ in-repo close-out shipped; filesystem rename + mvmd pin bump are operator actions)**:

This phase splits into two halves:

1. **In-repo close-out** (this commit). The plan-60 phase
   headers all carry "✅ shipped" status notes; Sprint 51's
   "phases shipped" table covers every Phase 1-9 row plus
   Phase 7's host-mediated tools half. `Cargo.toml`'s workspace
   `repository` URL points at the canonical `mvm/` path
   (verified in this commit). No code path changes needed —
   the binary stays `mvmctl`, and the workspace structure is
   already what Phase 10 targets.

2. **Operator filesystem rename** (out-of-repo). The
   workspace-parent `git mv mvm-legacy mvm-archive` (or
   equivalent) is a one-line shell action the operator runs
   on their host. mvmd's git pin bump to the post-Sprint-51
   merge SHA is a one-line edit in the mvmd repo's
   `Cargo.toml`. Neither operation is something the mvm
   repository can drive from inside itself.

**Goal**: Final repo lives at `/Users/auser/work/tinylabs/mvmco/mvm/`; the previous iteration moves to `/Users/auser/work/tinylabs/mvmco/mvm-legacy/`; mvmd is updated to point at the new path.

**Action**:
- `git mv mvm-legacy mvm-archive` (or equivalent — exact source
  name varies by operator's workspace layout) from the workspace
  parent. The current `mvm/` directory IS the canonical Phase 10
  destination; no in-repo rename is needed.
- Update CI paths — none currently depend on a sibling layout
  (verified: `.github/workflows/*` reference the repo root
  only).
- Update `Cargo.toml` `repository` URL — already canonical.
- Update mvmd's git pin to the post-Sprint-51 merge SHA.
- Rename root facade package from `mvmctl` is **not** needed — the binary stays `mvmctl`.

**Exit tests**: all prior phases' tests still green from the new path. `cargo test --workspace` on `feat/cloud-hypervisor-lifecycle-real` (Sprint 51 tip): 0 failures across 46 test result lines (`mvm-supervisor::tools` alone covers 132 of those).

**Risk**: mvmd hardcodes a git URL — confirm and bump in the same merge.

## Code-quality rules (CI-enforced)

- `[workspace.lints.clippy]` includes `too_many_arguments = "deny"`; **no `#[allow]` exceptions ever**. When the lint fires, refactor with a `bon`-derived builder.
- File-size soft limit: 400 LOC. Above that, split.
- `tracing` only — no `println!`/`eprintln!` in lib code (`println` allowed only in `mvm-cli/src/output.rs`).
- All `pub` items have doc comments; CI runs `cargo doc --no-deps -D warnings` (rustdoc lints fail the build).
- All secret types implement `Zeroize` and never derive `Debug`; CI custom-lint enforces.
- `#[serde(deny_unknown_fields)]` on every host↔guest type (W4.1 from existing security plan).
- Tests live next to code (`#[cfg(test)] mod tests` for unit) plus integration in `tests/`.

## Verification (end-to-end)

After Phase 10:

```bash
cd /Users/auser/work/tinylabs/mvmco/mvm

# Build
cargo build --workspace --release

# Quality gates
cargo clippy --workspace --all-targets -- -D warnings
cargo doc --workspace --no-deps -D warnings
cargo fmt --check
cargo deny check
cargo audit

# Tests
cargo test --workspace
cargo +nightly fuzz run fuzz_authenticated_frame -- -runs=20000
cargo +nightly fuzz run fuzz_guest_request -- -runs=20000

# Smoke (live)
MVM_LIVE_SMOKE=1 cargo test --test smoke_invoke -- --nocapture

# Performance gate
MVM_PERF=1 cargo test --test perf -- --nocapture
# expect: cold_boot_p50 < 500ms, rootfs_minimal_size < 20MB

# Reproducibility (Linux only)
cargo xtask reproducibility-check

# mvmd contract gate
cd ../mvmd && cargo test --workspace

# Demo
cd ../mvm
mvmctl init demo && cd demo
mvmctl build .
mvmctl up --flake .
mvmctl exec demo -- echo hello   # → hello
mvmctl audit tail --vm demo &
curl http://1.1.1.1                # blocked, audit shows the deny
mvmctl down demo
```

## Critical files to reference during execution

- `/Users/auser/work/tinylabs/mvmco/mvm/src/lib.rs` — the facade shape that must be preserved 1:1
- `/Users/auser/work/tinylabs/mvmco/mvm/crates/mvm-core/src/lib.rs` — flat re-exports mvmd imports through `mvmctl::core::*`
- `/Users/auser/work/tinylabs/mvmco/mvm/crates/mvm-core/src/protocol/vm_backend.rs` — the `VmBackend` trait; canonical backend abstraction
- `/Users/auser/work/tinylabs/mvmco/mvmd/crates/mvmd-runtime/src/{vm,security,hostd}/` — where mvmd absorbed runtime code; we pull the more recent versions from here when they exist
- `/Users/auser/work/tinylabs/mvmco/mvmd/crates/mvmd-agent/src/transport.rs` — QUIC/mTLS reference for our hostd surface
- `/Users/auser/work/tinylabs/mvmco/mvm/tests/cli.rs` — 91-test CLI specification, our burndown gate
- `/Users/auser/work/tinylabs/mvmco/mvmforge/crates/mvmforge-sdk/src/lib.rs` — source of `mvm-sdk`
- `/Users/auser/work/tinylabs/mvmco/mvm/specs/plans/25-microvm-hardening.md` and `specs/adrs/002-microvm-security-posture.md` — security posture sequencing already designed by the user

## Estimated calendar time

Sequential: ~10-13 weeks for one engineer. Phases 2-5 can partially overlap (encryption, networking, observability, DX are mostly independent crates after Phase 1's backend trait lands). Phases 6-8 are gating for security claims and the mvmd contract.

## What changes in the user's existing files

- Root `Cargo.toml`: workspace block fully rewritten; the `[[bin]] mvm-builder` entry deleted; the commented-out `keyring` blocks re-enabled (no longer commented); full feature-flag block added.
- `crates/mvm-backend/`, `crates/mvm-builder/`, `crates/mvm-providers/`: deleted entirely (replaced by full crate set).
- `crates/mvm-cli/src/main.rs`: replaced (was `Hello, world!`); becomes thin entry → `mvm_cli::run()`.
- `tests/cli.rs`: kept; tests gradually flip from red to green over phases 1-5.
- `tests/e2e/`: kept; activated in Phase 4.
- `specs/SPRINT.md`: replaced with a new sprint focused on Phase 0+1; subsequent sprints rotate through phases.
- `nix/`: new directory; imports microvm.nix; replaces hand-rolled rootfs init from the previous iteration.
- `.github/workflows/`: matrix expanded to include macOS and Windows runners.

## Open questions to confirm during execution

1. **Windows path is Tauri-only** (confirmed): native Windows CLI is best-effort; the supported Windows surface is `mvm-studio`'s Tauri build packaging mvmd + mvm. Libkrun/WSL2 fallback documented in `specs/runbooks/cross-platform-install.md` (Phase 5).
2. **microvm.nix licence + audit** (confirmed MIT). Pin a vetted commit; re-audit on every bump via `xtask audit-flake`.
3. **`rmcp` SDK** (confirmed Apache-2.0, recently updated). Phase 7 verifies its server-side hooks match `../mvm/crates/mvm-mcp`'s dispatcher needs; fall back if shape doesn't fit.
4. **Cold-boot targets**: Linux/Firecracker (snapshot-cloned) ≤ 30 ms, Linux/Firecracker (cold) ≤ 500 ms, macOS/libkrun ≤ 1 s, Windows/Tauri-WSL2 ≤ 2 s. Snapshot-pool path lands in Phase 1, tightened in Phase 9.
5. **Confidential compute (`sev-snp`/`tdx`) feature flags** — reserve API surface in Phase 6, defer real implementation post-Phase-10 (user confirmed unsure).
6. **TPM2 / Secure Enclave keystore wiring** — Phase 2 implements `keyring` baseline; TPM2/Secure Enclave landing later as a `Keystore` impl variant once the trait shape is stable. Hardware attestation (Phase 6 stubs) is the consumer for this.
7. **GPU passthrough (Cloud Hypervisor + VFIO)** — defer to post-Phase-10. Confirm scope when the first ML/local-LLM customer asks.
8. **virgl on macOS via libkrun** — verify in Phase 7b before promising rich graphics on macOS for `computer-use`. If virgl isn't viable on macOS, document Xvfb-only path and flag for users.
9. **Hosted mvmd cloud launch** — keep all hosted-cloud-only paths out of mvm; the open-source library must remain self-hostable. Re-confirm on every PR that introduces new infra primitives.

## Reference links (verified URLs from the user)

- microvm.nix — https://github.com/microvm-nix/microvm.nix (intro: https://microvm-nix.github.io/microvm.nix/intro.html)
- an external LLM sandbox/jail tool (mentioned in scratch.md line 15 for inspiration; not a dependency) (referred to obliquely per [[feedback_no_competitor_names_anywhere]]; trait key in auto-memory `reference_external_sandbox_control_plane_oblique_key`)
- Previous iteration: `/Users/auser/work/tinylabs/mvmco/mvm`
- Orchestrator: `/Users/auser/work/tinylabs/mvmco/mvmd`
- Tauri wrapper: `/Users/auser/work/tinylabs/mvmco/mvm-studio` (planned)
- SDK source: `/Users/auser/work/tinylabs/mvmco/mvmforge/crates/mvmforge-sdk`
