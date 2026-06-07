# Gap analysis: mvm vs. libkrun

**Date:** 2026-05-12
**mvm version surveyed:** 0.14.0 (post v1→v2 cutover)
**Comparator:** libkrun (`docs.libkrun.dev`, introduction + quickstart + CLI overview + sandbox overview)

---

## Context

The user pointed at libkrun's "introduction" docs. Both projects build microVM-based sandboxes for code execution, but they're shaped for different audiences and the surface gap is wide enough that it's worth pinning down before either side commits to a roadmap. This doc captures: (1) what libkrun sells and how, (2) where mvm already overlaps, (3) where mvm leads, (4) where mvm trails and what closing each gap would cost, (5) the strategic decisions that fall out of the comparison.

Out of scope: mvmd (multi-tenant fleet) lives in a sibling repo and is not the same axis of comparison.

---

## What libkrun actually ships

One-liner: **"every agent deserves its own computer"** — a local, daemonless microVM runtime that boots in <100ms, ingests OCI images, and exposes three first-class SDKs (Python/TS/Rust) with a tight builder API. The Python flow is roughly:

> `Sandbox.create(name, image=..., memory=...)` returns a sandbox handle. The handle exposes a command-running method (`.exec` in the docs) that takes an interpreter + args and returns captured stdout/stderr. A `.stop()` method tears the VM down. Same builder pattern in TS and Rust.

Pitched at AI-agent authors: untrusted code, secret exfiltration, network egress. Marketed differentiators are (a) "no daemon, no server" — runtime is a child process of the SDK, (b) **secret placeholders that never enter the guest** (host swaps them on egress to allowed hosts), (c) programmable network layer, (d) snapshots of the writable upper layer as portable, restartable artifacts, (e) cross-platform parity (macOS Apple Silicon + Linux KVM, same CLI/SDKs).

CLI is Docker-shaped: `msb run|start|stop|rm|ls|ps|inspect|logs|metrics` plus a command-runner in a running sandbox, `msb pull`, `msb image ls/rm`, `msb volume create/ls/rm`, `msb snapshot create`, `msb self update`. No project/init file documented.

---

## Capability matrix

| Capability | libkrun | mvm (0.14.0) | Status |
|---|---|---|---|
| Sub-100ms cold boot | Claimed | Not measured / not advertised | **Gap** |
| Daemonless runtime | Yes (child of SDK process) | Mostly (CLI-spawned FC, optional supervisor) | Parity-ish |
| OCI image as primary rootfs source | Yes (Docker Hub, GHCR, ECR, GCR) | Round-trip only — Nix flake → `dockerTools.streamLayeredImage` → OCI tar → `docker load` (`crates/mvm-backend/src/docker.rs:3-5`). No upstream `docker pull <image>` ingest. Upstream-pull ingest tracked as plan 74 W1; cross-repo handoff to mvmd via mvmd ADR-0020 (OCI images as microVM workloads). | **Partial — round-trip yes, upstream pull planned** |
| Nix-built reproducible rootfs | No | Yes (catalog, flakes, Mvmfile) | **Lead** |
| Python SDK | Yes | Build-time decorator surface ships in `crates/mvm-sdk` (declarations + IR emission); runtime lifecycle surface (`create` / run / `snapshot` / `stop`) tracked as plan 74 W4. pyo3 binding planned. | **Partial (decorator yes, runtime lifecycle planned)** |
| TypeScript SDK | Yes | Build-time decorator surface ships via the Rust core in `crates/mvm-sdk`; runtime lifecycle surface tracked as plan 74 W4. napi-rs binding planned. | **Partial (decorator yes, runtime lifecycle planned)** |
| Rust SDK | Yes (`libkrun` crate) | Build-time SDK ships as `crates/mvm-sdk` + `crates/mvm-sdk-macros` (ported from the previous `mvmforge-sdk` per [migration guide](../public/src/content/docs/guides/mvmforge-migration.md)). Runtime lifecycle surface tracked as plan 74 W4. | **Partial (build-time yes, lifecycle planned)** |
| Snapshots (capture writable layer, restart) | Yes (`msb snapshot create`) | Yes — instance pause/resume with HMAC + replay-store seal | **Lead** (stronger) |
| Templates (pre-baked rootfs) | Implicit via image layers | Yes, first-class (`template build/list/...`) | **Lead** |
| Volumes (named, persistent) | Yes (`volume create/ls/rm`) | virtio-fs mounts via `vm volume`, no named-volume CRUD | Partial |
| Bind mounts | Yes | Yes (`--add-dir`, `--volume`) | Parity |
| Networking — NAT/bridge | Yes | Yes (`network create/ls/remove`, per-tenant bridges) | Parity |
| Programmable egress (per-packet host control) | Coming soon | L3 allow-list today; L7 proxy is plan 34 (not shipped) | Partial |
| Secret placeholders (never enter guest) | Yes — flagship differentiator | No — `ops secret put/get` is keystore-backed, injected as plain env | **Gap** |
| Audit trail | Not documented | Chain-signed `~/.mvm/audit/*.jsonl`, `mvmctl audit verify` | **Lead** |
| Signed execution plans | Not documented | Ed25519-signed `ExecutionPlan`, replay-protected | **Lead** |
| dm-verity rootfs | Not documented | Yes (W3 shipped 2026-04-30) | **Lead** |
| Project/init file | None | `mvm init` → `mvm.toml` + `flake.nix`; `up --manifest` | **Lead** |
| Multi-backend hypervisor | libkrun only (under the hood) | Firecracker / Apple Container / libkrun / libkrun / Cloud Hypervisor / microvm.nix / Docker fallback | **Lead** |
| Live metrics | `msb metrics` | `ops metrics` | Parity |
| Logs streaming | `msb logs -f` | `vm logs` | Parity |
| `install` as system command | Yes | Not surfaced | Minor gap |
| Snapshot fan-out for parallel workers | Marketed use case | Possible mechanically; no documented workflow | **Gap** in story |
| Marketed cold-boot benchmark | <100ms | None | **Gap** in story |

---

## What we already have that this comparison understates

Two things deserve to be called out before the lead/gap sections, because the first survey of the codebase missed them:

- **A round-trip OCI path exists.** `crates/mvm-backend/src/docker.rs:3-5`: "Runs Nix-built microVM images as Docker containers. Uses the OCI `image.tar.gz` produced by `mkGuest` (via `dockerTools.streamLayeredImage`), loaded with `docker load`. Falls back to `docker import` for raw ext4." This isn't upstream registry pull, but it does mean a Nix-built workload can be handed to a host that only has Docker. Worth documenting in `public/src/content/docs/` so users know it's there.
- **The SDK design is fully specified, just not ported.** Plan 60 Phase 5 (`specs/plans/60-mvm-libkrun-migration.md:1820-1824`) ports `mvm-sdk` back from `../mvmforge/crates/mvmforge-sdk/` and splits it into `mvm-sdk` + `mvm-sdk-macros` + `mvm-sdk-addon`. The Python/TS bindings sit on top of the same Rust core (lines 568-608: pyo3 for hot paths + pure-Python over JSON-RPC; napi-rs for hot paths + pure-TS otherwise). Phase 5 estimate is ~7-10 days for the Rust port alone. The previous iteration shipped this; the rewrite just hasn't carried it over yet.

---

## Where mvm clearly leads

These are real, shipped advantages that libkrun doesn't claim:

1. **Provable, signed admission path.** Every workload routes through a typed `ExecutionPlan`, signed under a host Ed25519 key, replay-protected, and audited to a chain-signed JSONL log. CI proves these properties on every PR (claim 8 in the security model). libkrun's docs make no equivalent claim.
2. **Verified boot.** dm-verity sidecar + initramfs panics on tamper. Asserted in CI with a live-KVM tamper regression. libkrun doesn't talk about rootfs integrity.
3. **Reproducible Nix-built images.** Catalog + flakes + double-build CI lane. libkrun's OCI-pull model inherits whatever the upstream image author shipped.
4. **Multi-hypervisor abstraction.** Seven backends behind a trait. Worth a roadmap line: it lets mvm meet workloads where they live (KVM datacenter, Apple Silicon laptop, Docker fallback) without a rewrite.
5. **Template ergonomics.** Versioned, reusable, GC'd. libkrun has implicit image-layer reuse but no first-class template object.
6. **Snapshot durability semantics.** Instance snapshots are HMAC-sealed with a monotonic epoch and refuse downgrade replays. libkrun snapshots are documented as artifacts but the integrity story isn't.
7. **Project file.** `mvm.toml` + `mvmctl init` presets give a declarative, checked-in surface. libkrun is imperative-only.

---

## Where libkrun leads (the real gaps)

Ranked by strategic weight, not effort:

### G1. No Python / TypeScript / Rust SDK shipped yet — biggest adoption gap

libkrun is fundamentally **SDK-shaped**: the install path is `pip install libkrun` or `npm install libkrun`, and three lines of code give you a running VM. mvm is **CLI-shaped**: you `mvmctl up --manifest ./mvm.toml --detach` and then shell out for everything else. The agent-framework audience (LangChain, LlamaIndex, Mastra) lives in Python and TypeScript and will not adopt a CLI-only tool.

The good news: the design is already written. Plan 60 Phase 5 specs the full surface (`Sandbox.builder(...)`, `.commands.run(...)`, `.commands.run(..., background=True)`, etc.) and the previous iteration's `mvm-sdk` exists at `../mvmforge/crates/mvmforge-sdk/` ready to port. The bad news: it isn't in this repo's `crates/` and Phase 5 hasn't been started.

- **Effort:** Phase 5 estimate ~7-10 days for the Rust SDK port + macros + addon. Python and TS bindings on top are mechanical once the Rust core exists (pyo3 / napi-rs wrapping).
- **Decision needed:** Is "agent-framework adoption" a goal? If yes, this is the #1 investment and Phase 5 should jump the queue. If no, libkrun keeps that audience.

### G2. Upstream OCI ingest is missing (round-trip is present)

mvm can already round-trip a Nix-built image through OCI (`mkGuest` → `dockerTools.streamLayeredImage` → `image.tar.gz` → `docker load`, used by the Docker backend at `crates/mvm-backend/src/docker.rs:3-5`). What's missing is **upstream registry pull**: a user with a working `Dockerfile` (or a reference to `python:3.12`) cannot point mvm at it. There is no `fn pull` in the workspace today; the Docker backend only loads images we built.

- **Effort:** Moderate. Need an `mvmctl image pull <ref>` that fetches OCI layers, assembles ext4 (or equivalent), respects entrypoint/env/workdir, and registers the result as a template so cached pulls behave like Nix-built templates.
- **Trade-off:** Once you accept upstream OCI input, the reproducibility + verified-boot story has to be re-derived per image. The current claim 7 (deterministic double-build CI) doesn't apply to a pulled image. Worth a separate ADR before any code.

### G3. No marketed cold-boot number

libkrun leads with "<100ms." mvm has no published number. Could be that mvm is already there (Firecracker + CoW clone is fast) — we just don't measure or advertise. Could be that template hydration + plan signing + audit append + supervisor admission stack up to noticeably more.

- **Effort:** Trivial to measure (a benchmark harness on a couple of canonical paths: `up` of a cold template, `up` from warm template, snapshot restore). Effort to *improve* depends on what the measurement shows.
- **Decision needed:** Is sub-100ms a goal we're willing to hold the admission path to? If yes, plan-signing/audit-append latency becomes a constraint to design against.

### G4. Secret placeholders

This is libkrun's flashiest differentiator: the guest literally never receives the real value, and the host swaps placeholders on egress to allow-listed hosts. mvm has good secret *storage* (keystore + SecretBox + audit), but injection is plain env / mounted file. A compromised guest exfiltrates whatever it can read.

- **Effort:** Large. Needs an egress proxy that terminates TLS (or at minimum knows the placeholder→secret map per allowed host), tight integration with the network policy layer, and a defensible threat model for what counts as "allowed host."
- **Strategic note:** mvm's existing security claims (signed plans, verified boot, audit) are arguably stronger overall, but they don't reach this specific failure mode. Worth a deliberate decision: do we counter, or do we cede this lane?

### G5. Daemonless ergonomics for the SDK path

libkrun's "no daemon" pitch is really "the SDK *is* the runtime owner." mvm's `mvmctl up --detach` leaves a Firecracker process owned by no parent, which is fine for CLI use but awkward for SDK use (who reaps the VM when the Python process dies?). Pairs with G1.

### G6. Snapshot-spawned worker fan-out

libkrun markets a workflow: "snapshot the sandbox after `pip install`, then spawn N parallel workers from the snapshot." mvm has snapshots and templates but no documented worker-fan-out workflow. Mechanically possible; not a featured story.

### G7. Programmable network layer

Both are partial. libkrun lists it "coming soon"; mvm has L3 allow-lists today, L7 stubbed (plan 34). Realistic parity, not a real gap — but worth tracking whose ships first.

---

## Strategic decisions this surfaces

1. **Audience.** Is mvm chasing the agent-framework developer (Python/TS, "give me a sandbox in 3 lines") or the platform operator (Nix, signed plans, audit, fleet-via-mvmd)? Today the codebase is firmly operator-shaped. libkrun is firmly developer-shaped. Picking both is possible but expensive (G1 alone is multi-quarter).
2. **Reproducibility vs. ergonomics on rootfs.** Nix-first is a moat for the operator story (claim 7 reproducibility CI) and a wall for the developer story (G2). An OCI ingest path widens the funnel but bifurcates the security claims. Needs an ADR.
3. **Threat model for secrets.** Either commit to a placeholder/swap design (G4) or document explicitly that mvm's posture is "guest sees the secret, but admission is auditable and the rootfs is verified." Today this isn't written down as a deliberate choice.
4. **Boot-latency budget.** If we want to publish a number, the admission path becomes a hot path. Today plan signing + audit append is not optimized for the <100ms window.

---

## Suggested next steps (ordered by leverage-per-effort)

**Fast wins (days):**

1. **Execute plan 60 Phase 5 for the Rust SDK port.** Pull `mvmforge-sdk` into `crates/mvm-sdk/` as specified. The code already exists, the design is signed off, and this unlocks every downstream SDK story. Without it the Python/TS bindings have nothing to bind to. ~7-10 day estimate per plan 60.
2. **Measure cold-boot latency** on the four canonical paths (cold template, warm template, snapshot restore, plan-admit overhead). One afternoon. Either we already match the <100ms claim and just don't advertise it, or we have a real budget conversation to have.
3. **Document the round-trip OCI path** in `public/src/content/docs/`. We have it; users don't know it. Pure docs.

**Medium (1-3 weeks each):**

4. **Python SDK over the same Rust core** (plan 60 Phase 5 follow-on). Once #1 lands, pyo3-wrapping the Rust client is mechanical. The surface is specified at plan 60 lines 575-608 and 620-728. Single biggest adoption move.
5. **TypeScript SDK over the same Rust core.** napi-rs binding of the same surface. Pairs with #4.
6. **Spec upstream OCI ingest** as an ADR that answers "what does verified-boot mean for a `docker pull`'d image?" then ship a small `mvmctl image pull <ref>` that lands layers, assembles ext4, and registers as a template. Don't ship code until the ADR has answers — the security claims are the moat.

**Strategic (multi-quarter):**

7. **Write the threat-model decision** as an ADR: "mvm's secret-injection posture vs. placeholder-swap." Either we commit to G4 or we explicitly cede that lane. A "we are not chasing this" ADR is valuable.
8. **Snapshot worker-fan-out story.** Mechanically the primitives are already there; this is mostly a documented workflow + maybe a `mvmctl vm spawn-from-snapshot --copies N` helper.

---

## Verification

This doc is descriptive, not executable. To check its claims:

- mvm CLI surface: `cargo run -- --help` and `crates/mvm-cli/src/commands/mod.rs`.
- Security claims: `CLAUDE.md` "Security model" section + `specs/adrs/002-microvm-security-posture.md` + `specs/adrs/041-signed-audited-execution-plans.md`.
- libkrun claims: `https://docs.libkrun.dev/getting-started/introduction`, `/getting-started/quickstart`, `/cli/overview`, `/sandboxes/overview` (fetched 2026-05-12).
- Backend inventory: `crates/mvm-backend/src/` (firecracker, apple_container, libkrun, libkrun, cloud_hypervisor, docker, microvm_nix).
