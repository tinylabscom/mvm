# Manifest-driven template DX

## Context

Today's `mvmctl template` surface forces three discrete steps to go from "I have a flake" to "I have a built template":

1. `template init NAME` — scaffold flake + NixOS config (optional)
2. `template create NAME --flake . --profile … --role … --cpus … --mem …` — write `~/.mvm/templates/NAME/template.json`
3. `template build NAME [--snapshot]` — read the spec, run `nix build` via the same `dev_build()` machinery, store artifacts under `artifacts/revisions/<hash>/`.

`template create` does no build work — it just stashes CLI args as JSON. The flake is the actual source of truth (kernel, rootfs, services); resource defaults and policy are bookkeeping the user has to retype on every new template. The template *name* is invented at the command line and exists only as a registry path key.

There is also an existing `Mvmfile.toml` flow on `mvmctl build` (`crates/mvm-runtime/src/vm/image.rs`) that is conceptually adjacent.

Goal: **make a manifest file the user-facing primitive, identified by path.** Commands operate on a manifest. The registry continues to exist (it's the indexed artifact store), but its keys are derived from the canonical manifest path — there is no user-visible "name." `Mvmfile.toml` and `mvm.toml` collapse into one schema with one parser.

## Approach

### 1. One manifest, two accepted filenames

Per-directory file: **`mvm.toml`** preferred, **`Mvmfile.toml`** also accepted. Same parser, same schema. If both exist in one directory, error: *"Found both mvm.toml and Mvmfile.toml in `<dir>`; pick one."*

Schema (replaces today's `TemplateConfig` and the older `Mvmfile.toml`):

```toml
flake = "."                  # default ".", any flake ref accepted
profile = "default"          # selects packages.<system>.<profile>
vcpus = 2
mem = "1024M"
data_disk = "0"

name = "openclaw"            # optional; display name in `template list` and S3 channel key
```

That's the entire surface. Build inputs + dev sizing. Nothing else.

`name` is **optional** and is **not** the registry key — the manifest is identified by its canonical filesystem path; `name` is purely display + the S3 channel hint for push/pull. If unset, displays fall back to `dirname(manifest_path)`. No `[[variants]]` — multi-variant builds become multi-manifest directories. No `dependencies` field (see §6 boundary discussion).

**Boundary statement:** `mvm.toml` describes how this dev tool builds and runs **one** microVM from **one** flake. Anything multi-VM, multi-tenant, pool-shaped, or fleet-scheduling lives in `mvmd`'s separate config (in the `mvmd` repo) and is **out of scope** for this manifest.

Field rationale — what's in the manifest and why:

| Field | Owner | In manifest? |
|---|---|---|
| `flake` | mvmctl (input pointer) | **Yes** |
| `profile` | flake defines, mvmctl selects (`packages.<system>.<profile>`) | **Yes**, as selector |
| `vcpus` | mvmctl — Firecracker host-side sizing for the dev VM | **Yes** |
| `mem` | mvmctl — Firecracker host-side sizing | **Yes** |
| `data_disk` | mvmctl — host-side block device sizing | **Yes** |
| `name` | mvmctl — display in `template list`, optional S3 channel key for push/pull | Optional |

Explicitly **removed** from the manifest (were in the old `template create` flag set):

- **`role`** — fleet concept. Role-shaped flake variants live behind `profile` (`packages.<system>.gateway` vs `packages.<system>.worker`) or `passthru` inside the flake. `mvmctl` doesn't need to know.
- **`[network]`** — runtime policy, not a build input. Network policy is enforced at launch by the host (L7 proxy + tap), and `mvmd` will own per-tenant/pool egress rules. Default for dev `mvmctl up` comes from CLI flags → user-global `~/.mvm/config.toml` → built-in default. Putting it on the manifest would create two sources of truth once `mvmd` lands. Supersedes ADR-004 Decision 6 ("per-template default network policy") — note follow-up below.

Explicitly **NOT** in the manifest (mvmd or flake territory):

- What's installed in the rootfs / NixOS config / systemd services → flake (via `mkGuest`).
- Kernel cmdline tweaks beyond mvmctl's required ones → flake (kernel package).
- Build-time deps on other flakes → flake `inputs` + `flake.lock`.
- Tenants, pools, instances, scheduling, multi-VM topology → `mvmd`.
- Runtime deps on other VMs (lifecycle ordering, health gates) → `mvmd`.
- Per-tenant network bridges, tap names, IP allocation → `mvmd`.
- Secrets / env vars at boot → `mvmctl up`-time injection or `mvmd` instance config.

The manifest's job is *how this dev tool builds and runs this flake*, not *what the flake contains* and not *how a fleet schedules it*.

Existing `Mvmfile.toml` consumers in `mvm-runtime/src/vm/image.rs` migrate to this schema; legacy fields stay readable for one release with a deprecation hint.

### 2. Manifest discovery

When no manifest path is given, walk up from cwd (Cargo-style) looking for `mvm.toml` then `Mvmfile.toml` in each directory. Stop at filesystem root or a `.git` boundary. If nothing found, error with a hint to run `mvmctl template init` or pass `--mvm-config <path>`.

`--mvm-config <path>` accepts either a file path or a directory (resolved as above). Available on every template subcommand.

### 3. Registry layout — keyed by manifest path hash

Today: `~/.mvm/templates/<name>/template.json` + `artifacts/revisions/<hash>/...`.

After: `~/.mvm/templates/<sha256(canonical_manifest_path)>/manifest.json` + `artifacts/revisions/<hash>/...`. The `manifest.json` records:

```json
{
  "schema_version": 1,
  "manifest_path": "/abs/path/to/mvm.toml",
  "manifest_hash": "<sha256 of canonical path>",
  "flake_ref": "...",
  "profile": "...",
  "vcpus": 2,
  "mem_mib": 1024,
  "data_disk_mib": 0,
  "name": "openclaw",
  "backend": "firecracker",
  "provenance": {
    "toolchain_version": "0.13.0",
    "builder_image_digest": null,
    "host_arch": "x86_64-linux",
    "built_at": "<iso-8601>",
    "ir_hash": null
  },
  "created_at": "...",
  "updated_at": "..."
}
```

Revisions inside the slot are content-hashed by `flake.lock + profile` (today's cache key drops the `role` component). Moving/renaming a manifest creates a new slot; the old slot is orphaned and surfaced in `mvmctl template list --orphans` for explicit cleanup. This trade is intentional: path = project identity; content-addressed revisions live inside that identity.

A manifest's canonical path normalisation: resolve symlinks, strip trailing slash, lowercase the drive on Windows (n/a here), use absolute path. Codified as a `Manifest::canonical_key()` helper.

### 4. Commands revolve around the manifest path

The word "template" disappears from the user-facing surface. The user model becomes: **edit `mvm.toml`, run `mvmctl build`, run `mvmctl up`.** The implementation nouns (slot, registry slot hash) stay internal.

#### Top-level verbs (everyday user flow)

| Command | Behaviour |
|---|---|
| `mvmctl init [DIR] [--preset …] [--prompt "…"]` | Scaffold `mvm.toml` + `flake.nix` (+ NixOS config). Default `DIR=.`. `--preset` and `--prompt` work as today (existing heuristic + LLM planner in `crates/mvm-cli/src/template_cmd.rs:505-948`); the planner is extended to populate `mvm.toml` resource defaults from the prompt's inferred preset/features. Promotes today's `mvmctl template init NAME` to a top-level command; the optional `name` field in `mvm.toml` defaults to `dirname(DIR)`. |
| `mvmctl build [PATH] [--force] [--snapshot] [--update-hash] [resource overrides]` | Discover manifest at `PATH` (file or directory; defaults to cwd walk-up); merge CLI overrides; persist `manifest.json` in the slot keyed by canonical path; `nix build` artifacts. Existing `mvmctl build --flake .` flag-flake mode and the older `Mvmfile.toml` flow are subsumed by this verb. |
| `mvmctl up [PATH]` / `mvmctl run [PATH]` / `mvmctl exec [PATH] -- <cmd>` | All accept a manifest path or its directory (replacing today's `--template <NAME>`). The manifest-keyed slot is looked up; if no current revision, error with a hint to `mvmctl build`. |

The existing top-level `mvmctl ls` / `mvmctl down <vm>` / `mvmctl logs <vm>` etc. continue to operate on **running VMs** — unchanged from today, no breaking change. Slot-registry operations live under `mvmctl manifest` to disambiguate (see below).

#### `mvmctl manifest` namespace (registry / inspection / object-storage ops)

| Command | Behaviour |
|---|---|
| `mvmctl manifest ls [--json] [--orphans]` | List built slots — `manifest_path`, last-built timestamp, optional `name`. `--orphans` flag shows slots whose manifest is missing on disk. (Pre-refactor name-keyed slots are silently ignored — see §8a.) |
| `mvmctl manifest info [PATH]` | Print manifest, slot path, current revision, snapshot, provenance. |
| `mvmctl manifest rm [PATH] [--force] [--manifest-file]` | Remove the slot from the registry. `--manifest-file` also deletes the source `mvm.toml` on disk (off by default). |
| `mvmctl manifest push [PATH] [--revision <hash>]` | Publish a slot's artifacts + signed bundle to the configured remote (S3/OCI). S3 channel key derived from `name` if set, otherwise the manifest hash. |
| `mvmctl manifest pull <NAME-OR-HASH>` | Fetch a slot from the remote. Resolves to an existing slot if the manifest hash matches; otherwise creates a new slot keyed by the pulled manifest's canonical path. |
| `mvmctl manifest verify [PATH] [--check-signature]` | Verify checksums (today) and cosign signatures (post plan 36). |
| `mvmctl manifest prune [--orphans]` | Cleanup. `--orphans` removes slots whose manifest file is gone. |

#### Removed (gone in plan 38)

The entire `mvmctl template *` namespace is removed outright — no alias, no deprecation period. mvmctl is pre-v1 dev tooling; we don't ship back-compat shims. Users with existing scripts/CI invocations of `mvmctl template …` get a clear "command not found" error from clap; the docs point at the new verbs.

| Today | Replacement |
|---|---|
| `mvmctl template init NAME` | `mvmctl init [DIR]` |
| `mvmctl template create NAME --flake …` | `mvmctl init` → edit `mvm.toml` → `mvmctl build` |
| `mvmctl template create-multi` | One manifest per directory; multiple directories for multi-variant builds |
| `mvmctl template build NAME` | `mvmctl build [PATH]` |
| `mvmctl template build NAME --config <toml>` | The TOML *is* `mvm.toml`; `--config` flag retired |
| `mvmctl template edit NAME` | Open `mvm.toml` in `$EDITOR` directly |
| `mvmctl template list` / `info` / `delete` | `mvmctl manifest ls` / `info` / `rm` |
| `mvmctl template push` / `pull` / `verify` | `mvmctl manifest push` / `pull` / `verify` |
| `mvmctl up --template NAME` etc. | `mvmctl up [PATH]` |

#### Unchanged

| Command | Note |
|---|---|
| `mvmctl ls` / `mvmctl down <vm>` / `mvmctl logs <vm>` / `mvmctl console <vm>` / `forward` / `diff` | Operate on running-VM names; today's behaviour preserved. Slot-registry ops live under `mvmctl manifest *` instead, to avoid colliding with these. |
| `mvmctl image *` | Image catalog (`mvm-core/src/catalog.rs`) — curated bundled images, distinct concept. |
| `mvmctl cache prune` | Build-cache cleanup; gains `--orphan-builds` flag delegating to `mvmctl manifest prune --orphans` for ergonomic chaining. |

### 5. Refuse silent drift

Identity-shaping fields (`flake`, `profile`) in the manifest must agree with the persisted `manifest.json` on rebuild. Mismatch aborts:

> Manifest at `<path>` declares flake=`<X>`, profile=`<Y>`. The slot at `<sha256>` was last built with flake=`<X'>`, profile=`<Y'>`. Pass `--force` to overwrite, or `mvmctl template edit` for a surgical change.

`--force` overwrites; resource fields (`vcpus`, `mem`, `data_disk`) update silently.

**`template edit` semantics:** edits the **manifest file on disk** (the user's source of truth, version-controlled), not the persisted slot JSON. After editing, the next `template build` will re-read the manifest and either build cleanly (if only resource fields changed) or trip drift refusal (if `flake`/`profile` changed). Today's implementation in `crates/mvm-cli/src/template_cmd.rs:328-376` mutates the slot JSON directly — that path goes away. The slot JSON is **only ever written by `template build`** post-refactor, never directly by the user.

### 6. Manifest scope — what's NOT in it

Two categories of "dependency" come up; neither belongs in the manifest:

- **Build-time deps** (this image needs another flake's output / NixOS module / shared rootfs layer). **Nix's job.** The flake already expresses these via `inputs` and `flake.lock` already pins them. Duplicating in `mvm.toml` would diverge.
- **Runtime deps** (this microVM needs Postgres up before it boots, or service X reachable). **`mvmd`'s job** — fleet orchestration, lifecycle ordering, health gating live in the separate `mvmd` repo's tenant/pool config. `mvmctl` is single-VM dev tooling.

Frozen kernel/rootfs contract: the manifest references one flake and produces one `(vmlinux, rootfs.ext4[, initrd])` triple per revision. That's what `revision_hash` content-addresses; what push/pull/verify guarantee; what `mvmctl up` boots.

**Future follow-up (deferred):** an optional `[dev]` block for local orchestration ergonomics (e.g. `before_start = ["mvmctl up ../db"]`). Not in this redesign — file as a separate plan if it proves needed.

### 7. Update agent/MCP-facing strings

LLM clients learn from these:
- `crates/mvm-mcp/src/server.rs:126`
- `crates/mvm-mcp/src/env.rs:27`
- `crates/mvm-cli/src/commands/ops/mcp.rs:517`
- `nix/images/examples/llm-agent/flake.nix:13-16`
- `crates/mvm-cli/resources/template_scaffold/README.md:6` and `resources/template_scaffold/README.md:6`
- `QUICKSTART.md:114`

Rewrite to: `mvmctl init && $EDITOR mvm.toml && mvmctl build && mvmctl up`. The old `mvmctl template *` namespace is removed outright; LLM clients learn the new flow from these strings (no deprecation alias to fall back to).

### 7b. Edge cases and robustness

The following corners are addressed so they don't bite later:

- **Backend mismatch at boot.** Slot's `manifest.json` records the `backend` it was built on (Firecracker/AppleContainer/Docker). `mvmctl up`/`run`/`exec` on a different host backend prints a warning (e.g. "slot built with Firecracker; current backend is AppleContainer; snapshot ignored, cold-boot only") and proceeds. Hard-error only when the artifact shape is incompatible. Same path the existing `template_cmd.rs:301-310` snapshot-capability check uses.

- **Concurrent builds.** Slot lockfile `<slot>/.lock` (POSIX flock) acquired by `template build`. Second concurrent invocation prints "another build is in progress for `<manifest_path>` (pid=<n>)" and aborts. Released on drop / process exit.

- **Snapshot staleness from sizing changes.** If `mvmctl up` finds the persisted slot's `vcpus`/`mem` differ from the current manifest, warn and fall back to cold-boot from rootfs (don't restore the snapshot). The snapshot is taken at specific resource sizes; restoring on a different shape is unsafe.

- **Manifest parse-time validation.** `Manifest::validate()` runs immediately after TOML parse, fails before any I/O. Checks: `flake` non-empty + `validate_flake_ref`, `vcpus >= 1`, `mem` parses to ≥ 64MiB, `data_disk` parses to ≥ 0, `name` (if set) is `validate_template_name`-compatible.

- **Schema versioning.** `mvm.toml` gains a top-level `schema_version = 1` (optional, default 1; persisted slot JSON mirrors it). Future fields are additive via `#[serde(default)]`. Reading a manifest with `schema_version > supported` errors with "this manifest declares schema_version=N; this mvmctl supports M; upgrade mvmctl."

- **Atomic slot writes.** All slot JSON writes use write-temp-then-rename (`tempfile::NamedTempFile::persist`). No half-written `manifest.json` after a crash mid-write.

- **`--mvm-config` short form.** `-c <path>` accepted on every subcommand that takes `--mvm-config <path>`. Trivial clap `#[arg(short, long)]`.

- **CI ergonomics for legacy banner.** `MVM_NO_LEGACY_BANNER=1` env var or `--quiet` global flag suppresses the §8a one-time banner. CI users get no surprise output on first invocation post-upgrade.

- **Push channel collisions.** `template push` checks the registry's S3 channel namespace before overwriting. If `name = "openclaw"` already points at a different slot hash, refuse with "channel `openclaw` already points at slot `<other-hash>`; pass `--force-channel` or rename." Manifest-hash addressing always works as a non-collision fallback.

- **Stable slot layout as a contract.** Doc-comment the slot path layout in `mvm-core/src/domain/template.rs` as a stable public-ish API. Third-party tools should prefer `mvmctl template list --json`, but the layout is documented for emergencies / debugging. Mirrors how `~/.mvm` is documented today.

- **NFS/shared-filesystem behaviour.** Unchanged from today. `~/.mvm` is assumed local; `flock` semantics inherit OS behaviour. Documented as an assumption, not a regression.

### 7c. Signing and attestation

Layered story; this refactor only touches the structural piece.

**(a) Build-input signing (the flake).** Already covered by Nix `flake.lock` + content-addressed inputs. No mvmctl-side work.

**(b) Output artifact signing (rootfs/kernel/initrd/snapshot).** Existing `template push`/`pull`/`verify` machinery (`crates/mvm-cli/src/template_cmd.rs:316-326`) already enforces `checksums.json` integrity. With plan 36 (sealed-signed-builder-image) in flight, pushed artifacts will gain cosign signatures. **This refactor is orthogonal** — slot artifacts are bytes-on-disk regardless of how the slot is keyed. The verify path just needs to consume slot-hash-keyed paths instead of name-keyed ones (already in §4 / Critical files).

**(c) Manifest signing.**
- `mvm.toml` is **not** signed by mvmctl. It's a source file the user version-controls; signing belongs to git (signed commits / GPG / sigstore git-signing). Document the boundary.
- `manifest.json` in the slot is a derivation summary, not a security boundary. Local tampering at worst recorded-field-stale; artifact integrity is enforced separately by content hashes + (post-plan-36) cosign signatures on the artifact bundle.
- For pushed channels, **the signed bundle includes `manifest.json` alongside `checksums.json` + artifacts** so `pull` can rehydrate the slot record from a verified source. Bundle-level signing is out of scope here; tracked under plan 36's signing follow-up.

**Provenance block in `manifest.json`** (in scope for this plan — small serde addition):

```json
"provenance": {
  "toolchain_version": "<mvmctl version>",
  "builder_image_digest": null,
  "host_arch": "x86_64-linux",
  "built_at": "<iso-8601>",
  "ir_hash": null
}
```

`builder_image_digest` is populated when plan 36's sealed builder image is in use; `ir_hash` is populated when the manifest came from mvmforge. Both default to `null` in the hand-rolled case. This block ties artifacts back to the build environment without introducing a new signing scheme.

**`template verify` evolution.** Today verifies checksums. Post-plan-36, gains `--check-signature` flag (cosign verify against the bundle). Both this plan and plan 36 land independently; the slot record is structured to accept signature metadata cleanly when it arrives.

### 8. Out of scope (file as follow-up)

- Reading defaults from a flake `passthru.mvm` attribute (extending `mkGuest` + `nix eval --json` in `mvm-build`).
- `[dev]` runtime-dependency block.

### 7a. Preserving `template init --prompt` (LLM-assisted scaffolding)

The existing prompt-driven scaffolder (`crates/mvm-cli/src/template_cmd.rs:505-948`) is **kept**. It currently:

1. Heuristically infers preset/features from the prompt (Python/HTTP/Postgres/Worker — `infer_prompt_preset`/`infer_prompt_features` at L765-830).
2. Optionally refines via LLM — auto-detects provider (Ollama probe at 127.0.0.1:11434/8080, then OpenAI if `OPENAI_API_KEY` set) with `MVM_TEMPLATE_PROVIDER` override (auto/openai/local/heuristic).
3. Uses OpenAI Responses API with structured-output JSON Schema (L832-930) for deterministic plan output.
4. Renders flake.nix from a fixed preset corpus (`flake_content_for_preset`).

Under the new design the planner gets one small extension: it also populates `mvm.toml` with prompt-derived resource defaults. The structured-output schema gains an optional `resources` object (`vcpus` 1-16, `mem_mib` 64-32768, `data_disk_mib` 0-102400). Heuristic fallback ships with a lookup table:

| Preset | vcpus | mem | data_disk |
|---|---|---|---|
| minimal | 1 | 256M | 0 |
| http / python | 2 | 1024M | 1024M |
| worker | 1 | 512M | 512M |
| postgres | 2 | 2048M | 4096M |

LLM mode can refine these per-prompt. No new providers, no new dependencies.

**Considered but rejected: nixai.** The discourse-recommended `nix-ai-help` (CLI `nixai`) was evaluated as an alternative LLM backend. It's archived as of 2025-08-23, written in Go (subprocess-only integration), targets full NixOS system configs (not microVM flakes / no `mkGuest`-shaped output), and does not validate generated Nix before returning. Integrating it would replace a working in-process planner with a dead Go subprocess for a worse target shape. Skip.

### 8a. Existing user data: just delete

mvmctl is pre-v1 dev tooling; we don't ship a migration step. Users with `~/.mvm/templates/<name>/` directories from before the refactor see them ignored by all new commands (the slot path-hash logic doesn't recognise them). Templates are cheap to rebuild from source.

Recommended cleanup, surfaced once in the README and the `manifests.md` guide:

```bash
rm -rf ~/.mvm/templates    # nuke all old + new state; rebuild what you need
```

The `is_slot_hash_dirname` helper from slice 2 is still useful (it lets `mvmctl manifest ls` skip non-hash directories cleanly without erroring on legacy entries), but we don't add `--legacy` flags or `prune --legacy` verbs for them. They'll be invisible to the user.

### 9. mvmforge integration contract (no code changes here)

`mvmforge` (sibling Rust project at `/Users/auser/work/rust/mine/decorationer`, crate name `mvmforge`, owned by the same author) is an upstream code-generator: decorated Python/TypeScript source → Workload IR (RFC 8785 canonical JSON, content-hashed, schema-versioned) → `flake.nix`. It is the layer *above* `mvm.toml`, not a competitor.

**Integration model:** mvmforge writes only what mvmctl needs to build. mvmforge translates the IR into `mvmctl` flags at invocation time, not into a sidecar file.

| Path | Files emitted by mvmforge | What reads the runtime side |
|---|---|---|
| Hand-rolled flake (no mvmforge) | none — user writes `mvm.toml` + `flake.nix` | `mvmctl up` CLI flags |
| mvmforge + mvmctl (dev) | `flake.nix` + `mvm.toml` | `mvmforge up` translates IR → `mvmctl up --cmd … --env …` flags |
| mvmforge + mvmd (prod) | `flake.nix` + `mvm.toml` (or omitted if mvmd derives sizing from IR) | `mvmd` reads the IR directly for instance spec |

**Why no `launch.json`:**

- The IR already is the canonical declarative artifact (RFC 8785, schema-versioned, content-hashed). A second sidecar file derived from it just adds drift surface.
- For dev, `mvmforge up` is the integrator — it has the IR in hand, it can spawn `mvmctl up` with the right flags. No third file involved.
- For prod, `mvmd` reads the IR directly (it's the "single source of truth for every downstream artifact" per the IR design). It doesn't need a derived sidecar.
- Each tool owns one file:
  - mvmctl owns `mvm.toml` (build/sizing).
  - mvmforge owns the IR (everything declarative about the workload).
  - Nix owns `flake.nix` (rootfs/kernel content).
  - mvmd will own its own instance specs (derived from IR).

`mvm.toml` shape emitted by `mvmforge compile`:

```toml
# mvm.toml — generated by mvmforge compile
flake = "."
profile = "default"
vcpus = 1
mem = "256M"
data_disk = "512M"
name = "<workload-ir-id>"
```

Resource fields come straight from the IR's `Resources` block (`cpu_cores`, `memory_mb`, `rootfs_size_mb`). `flake = "."` because `flake.nix` lives in the same emitted directory. From `mvmctl`'s perspective there's no special case — it discovers `mvm.toml` like any other.

**Coordination tickets (file separately, not in this plan):**

- mvmforge `compile` learns to emit `mvm.toml`; stops emitting `launch.json` as a peer artifact.
- mvmforge `up` translates IR → `mvmctl up` flags (cmd, env, mounts, source, network).
- `crates/mvm-runtime/src/vm/exec.rs`: existing `launch.json`-reading accommodations are deprecated and removed once mvmforge stops emitting it. Out of scope for this plan; flag as a follow-up cleanup.

**No code changes required in mvmctl for this plan to support mvmforge.** The minimal `mvm.toml` schema (5 fields) is in fact what makes mvmforge integration clean — anything richer would force mvmforge to duplicate logic about how to derive it from the IR.

**Crate dependency strategy (mvm vs mvmd vs mvmforge):**

mvmforge stays in its **own repository** and is published as separate crates. Reasoning:

- The IR is the contract between three projects (mvm dev tooling, mvmd production daemon, mvmforge code-generator). If mvmforge lived inside mvm, then mvmd would transitively depend on the mvm workspace just to read the IR — a dev-CLI becoming a production-daemon dependency. Wrong direction.
- mvmforge has Python and TypeScript SDK plumbing with their own release pipelines (PyPI, npm). Folding into mvm bloats the Rust workspace with non-Rust release machinery.
- mvm is in active churn (this refactor, security hardening, mvmd split). mvmforge benefits from independent build velocity.

Recommended structure (mvmforge repo's responsibility, noted here for cross-repo coordination):

- `mvmforge-ir` — small stable crate of IR types + canonicalize/validate/hash helpers. **The contract.** Published to crates.io (or private registry).
- `mvmforge` — CLI + SDK plumbing. Depends on `mvmforge-ir`.

Dependency graph stays acyclic and minimal:

```
mvmforge-ir  ←  mvm   (dev-dep, tests only — initial state)
            ←  mvmd  (runtime-dep — when mvmd lands)
            ←  mvmforge-cli
```

Pull-in plan:

- **mvm (this repo)**: `mvmforge-ir` as a `dev-dependency`, used only by tests that exercise mvmforge-emitted directories (verification step 11). mvmctl proper does not need to understand the IR — mvmforge translates IR → `mvmctl up` flags. **Promote to runtime dep later only if** `mvmctl up` learns to consume the IR directly to replace the deprecated `launch.json` accommodations in `crates/mvm-runtime/src/vm/exec.rs`. Revisit at that point; until then, dev-dep keeps the workspace lean.
- **mvmd (separate repo)**: `mvmforge-ir` as a **runtime dependency**. mvmd is the natural consumer — it reads the IR for instance specs. This is where the IR's value compounds.
- **mvmforge-cli stays independent.** Neither mvm nor mvmd ever depends on the CLI crate, only on `mvmforge-ir`.

For dev-time velocity (when iterating on the IR + mvm/mvmd in lockstep), use `[patch.crates-io]` in mvm's workspace `Cargo.toml` to point at a local mvmforge clone. No monorepo merge required.

**Reversal trigger:** if the IR becomes load-bearing for the `mvmctl up`/`run`/`exec` runtime path *and* changes in lockstep with mvm's runtime, the monorepo case strengthens. Until then, the IR's stable schema (v0.1, explicit MAJOR/MINOR via ADR per the survey) makes separate-repo the right shape.

## Plan-file delivery

This plan is currently at `/Users/auser/.claude/plans/dazzling-meandering-garden.md`. As part of execution:

0. **Work in a git worktree.** Create a worktree at `~/work/personal/microvm/kv/mvm-manifest` (or via the Agent tool's `isolation: "worktree"` mode) on branch `feat/manifest-driven-template-dx` off `main`. All commits below land there; main checkout stays clean. After merge, `git worktree remove` cleans up.

   **Dev-time isolation of `~/.mvm`:** the worktree shares `~/.mvm` with the main checkout. To avoid stomping on real templates during development, set `MVM_DATA_DIR=<worktree>/.mvm-test/` in shell + CI for the worktree. Existing `mvm_core::config::mvm_data_dir()` already honours this env override (verify before relying on it).

0a. **Codify the worktree rule in AGENTS.md.** Add a new section "Worktree Workflow for Features" between "Lima VM Requirement" and "Definition of Done" so future contributors / agents always start a feature in a worktree. Wording (drafted to paste verbatim):

   ```markdown
   ## Worktree Workflow for Features

   Every feature, refactor, or non-trivial bug fix MUST be developed in a git worktree, never on the main checkout. This isolates in-flight work from the main checkout's `~/.mvm` registry, build cache, and dev VM state.

   ### Creating the worktree

       git worktree add ../mvm-<feature-slug> -b feat/<feature-slug>
       cd ../mvm-<feature-slug>

   Branch names follow the existing pattern (`feat/<slug>`, `fix/<slug>`, `chore/<slug>`).

   ### Isolating mutable state

   Worktrees share `~/.mvm`, `~/.cache/mvm`, the Lima VM, and any pushed registries with the main checkout. To prevent stomping on real artifacts during development, redirect mvmctl's data dir into the worktree:

       export MVM_DATA_DIR="$PWD/.mvm-test"

   `mvm_core::config::mvm_data_dir()` honours this override, so all `~/.mvm/templates/`, `~/.mvm/dev/builds/`, and `~/.mvm/runs/` paths redirect into the worktree-local directory. CI on the worktree branch should set the same env.

   **Canonical: wrapper script + just recipes.** `bin/dev <args>` and the `just dev-*` recipes (e.g. `just dev-build`, `just dev-test`, `just dev-clippy`) source the dev env (`scripts/dev-env.sh`) automatically before invoking cargo/mvmctl. Zero tools to install — works on any POSIX shell, any OS the project already targets. New contributors run `bin/dev template build` and the env is set correctly without ceremony.

   Files committed to the repo:

       scripts/dev-env.sh       # sourceable: exports MVM_DATA_DIR + MVM_NO_LEGACY_BANNER
       bin/dev                  # executable wrapper: source scripts/dev-env.sh && exec cargo run -- "$@"
       justfile                 # gains `dev-build`, `dev-test`, `dev-clippy`, etc. recipes
       .envrc.example           # opt-in for direnv users (not required)

   `scripts/dev-env.sh` shape:

       export MVM_DATA_DIR="${MVM_DATA_DIR:-$PWD/.mvm-test}"
       export MVM_NO_LEGACY_BANNER=1

   **Optional: direnv.** Users who prefer auto-load can `cp .envrc.example .envrc && direnv allow`. Not required; not the default. Documented as a convenience for users who already have direnv installed.

   **Why not `.env` / `.env.local` consumed by mvmctl directly:** mvmctl does NOT auto-load dotenv files. Adding that would risk (a) leaking dev overrides into release/CI builds, (b) test pollution from stray `.env` files in unrelated checkouts, and (c) coupling mvmctl's runtime to a config-file loader it doesn't otherwise need. Env vars remain the contract; loading them is the wrapper script's (or direnv's) job.

   ### Lima VM sharing

   The Lima VM (`mvm-builder`) is shared across worktrees by design — it's expensive to boot and Nix builds benefit from a warm store. The `MVM_DATA_DIR` override above keeps mvmctl's per-feature state isolated; Nix store reuse is intentional.

   ### Cleaning up

   After the feature merges:

       git worktree remove ../mvm-<feature-slug>

   If the worktree was unused (no commits), `git worktree prune` removes it automatically.

   ### When NOT to use a worktree

   Trivial single-line changes (typo fixes, doc word swaps, dependency bumps) can land directly on a topic branch in the main checkout. The worktree rule applies to anything that touches code, runtime state, or the registry.
   ```

   **Verify before pasting:** confirm `MVM_DATA_DIR` is actually consumed by `mvm_core::config::mvm_data_dir()` (grep for it). If the env var name differs, adjust the AGENTS.md text to match.

1. **Move/copy** the contents to `specs/plans/38-manifest-driven-template-dx.md` (37 was claimed by the in-flight whitepaper-alignment plan during the planning conversation, so this plan landed at 38).
2. **Update `specs/SPRINT.md`** — add a new "Sprint 44 — manifest-driven template DX" section (or append to the existing Sprint 44 draft if it's still relevant, replacing the stub at `specs/plans/35-sprint-44-draft.md`). Sprint section should include:
   - Pointer to `plans/38-manifest-driven-template-dx.md`.
   - Coordination tickets for mvmforge `compile` to emit `mvm.toml` and stop emitting `launch.json`.
   - Followup: deprecate `crates/mvm-runtime/src/vm/exec.rs` `launch.json` accommodations once mvmforge stops emitting it (cross-references existing follow-up [#5](https://github.com/tinylabscom/mvm/issues/5) which marked launch.json consumption as shipped).
   - Followup: extract `mvmforge-ir` as a published dependency consumable by mvm (dev-dep) and mvmd (runtime-dep).
3. The two ADR-relevant supersedences are noted inline in the plan but not opened as ADR amendments here:
   - ADR-004 Decision 6 ("per-template default network policy") superseded by user-global config + mvmd tenant config.
   - The "template name as registry key" implicit decision superseded by canonical-manifest-path-as-key.

## Critical files to modify

| File | Change |
|---|---|
| `crates/mvm-core/src/domain/template.rs` | New `Manifest` struct + parser + `discover_from_cwd_or_path` + `canonical_key`; `TemplateSpec` renamed/repurposed to `PersistedManifest` (slot-resident JSON), gains `manifest_path`, `manifest_hash`, optional `name`. Reuse `parse_human_size` from `mvm-core/src/util.rs`. Drop `template_id` field. |
| `crates/mvm-core/src/domain/template.rs` (paths) | `template_dir(slot_hash: &str)` replaces `template_dir(name: &str)`. New `slot_dir_for_manifest_path(path: &Path)` helper. |
| `crates/mvm-cli/src/commands/build/template.rs` | **Deleted.** No alias / no deprecation period. Clap will return "command not found" if a user tries `mvmctl template …`. |
| `crates/mvm-cli/src/commands/init.rs` (new) | New top-level `Init` action — moved from `template init`, takes optional `dir` positional, `--preset`, `--prompt` flags. Same scaffolding logic. |
| `crates/mvm-cli/src/commands/build/build.rs` | Existing `mvmctl build` becomes the manifest-aware build verb. Accepts optional `[PATH]` (file or dir; defaults to cwd walk-up). Manifest discovery + spec merge + slot persist + `dev_build` invocation all live here. The legacy `--flake` flag-flake mode and `Mvmfile.toml` path collapse into the one parser. |
| `crates/mvm-cli/src/commands/manifest/mod.rs` (new) | New `Manifest` subcommand group with `Ls`, `Info`, `Rm`, `Push`, `Pull`, `Verify`, `Prune` actions. Single namespace for all slot-registry / object-storage operations. |
| `crates/mvm-cli/src/template_cmd.rs` | Split: `init.rs` (new) absorbs the prompt planner (L505-948); the rest becomes thin wrappers behind the deprecated `template` alias. Extend `OpenAiTemplatePlan` (L485-496) and the JSON Schema (L832-930) with optional `resources` block; have the renderer emit `mvm.toml` alongside the scaffolded `flake.nix`. Remove `create_single`/`create_multi`/`edit`. |
| `crates/mvm-runtime/src/vm/template/lifecycle.rs` | `template_create` → `template_persist` (writes the slot JSON keyed by hash); `template_load(slot_hash)`; `template_list` returns `(manifest_path, optional_name, last_revision_at)` tuples; `template_build` (L198) takes a slot key + persisted manifest instead of `id`. |
| `crates/mvm-runtime/src/vm/image.rs` | Existing `Mvmfile.toml` parsing folded into the new `Manifest` parser. |
| `crates/mvm-build/src/template_reuse.rs` | (Missed in earlier draft.) Today calls `template_current_symlink()` / `template_revision_dir()` with `template_id` and computes a 3-component cache key (`flake_lock + profile + role`, L47-56). Update to slot-hash arg + 2-component cache key (drop role). |
| `crates/mvm-core/src/domain/template.rs` (cache key) | `TemplateRevision::cache_key()` (L156-167) currently mixes in `role`. Drop the role component; update tests at L212-223 that assert role-sensitivity. |
| `crates/mvm-build/tests/pipeline.rs` | `test_template_reuse_skips_build()` (and any sibling) — update fixtures to new slot layout + cache-key shape. |
| `crates/mvm-cli/src/fleet.rs` | Already walks for `mvm.toml` from cwd — unify with the new `Manifest::discover_from_cwd_or_path` so there's one walk-up implementation, not two. |
| `crates/mvm-mcp/src/tools/mod.rs` and `crates/mvm-mcp/src/tools/run.rs` | Sole MCP tool `run` takes `env: String` describing a template name (L25-26, schema L57-87). Update schema + dispatcher to accept manifest path or directory; describe presets (`shell`, `python`, `node`) as named manifests shipped under `~/.mvm/builtins/<preset>/mvm.toml` (or equivalent built-in path) so the existing LLM-client UX keeps working. |
| `crates/mvm-cli/src/commands/build/build.rs` | `mvmctl build` (Mvmfile path) consumes the new manifest parser; flag-flake path unchanged. |
| `crates/mvm-cli/src/commands/ops/up.rs` (or wherever `up` lives) | Drop the `--template <NAME>` lookup. Take optional `[PATH]` positional that resolves through `Manifest::discover_from_cwd_or_path` then `slot_dir_for_manifest_path`. Same change in `run.rs` and `exec.rs`; share a manifest-resolution helper. |
| `crates/mvm-cli/src/commands/ops/cache.rs` | New `--orphan-builds` flag on `cache prune`; delegates to `mvmctl manifest prune --orphans` for ergonomics. |
| `crates/mvm-mcp/src/server.rs`, `crates/mvm-mcp/src/env.rs`, `crates/mvm-cli/src/commands/ops/mcp.rs` | Update MCP **tool input schemas** (not just hint strings) — any tool that took a template name takes a manifest path; `list_templates` returns `manifest_path` + `name`; `template_build`, `up`, `run`, `exec` all switch keys. |
| `public/src/content/docs/guides/manifests.md` (new — replaces `templates.md`, which is deleted) | Full guide to the `mvm.toml` model: schema, discovery, `init`/`build`/`up` flow, drift detection, `manifest *` namespace. |
| `public/src/content/docs/reference/cli-commands.md:91-93` | Update template command reference. |
| `crates/mvm-mcp/src/server.rs:126`, `crates/mvm-mcp/src/env.rs:27`, `crates/mvm-cli/src/commands/ops/mcp.rs:517` | (See MCP row above for tool-schema work.) Hint-string copy here — replace name-based recipe text with manifest-based. |
| `crates/mvm-cli/resources/template_scaffold/README.md` (L6-7) and `resources/template_scaffold/README.md` (mirror) | Both copies hard-code `mvm template create {{name}}` / `mvm template build {{name}}`. Rewrite to `mvmctl init && $EDITOR mvm.toml && mvmctl build`. |
| `QUICKSTART.md` (L114-121) | Replaces the `template create base-worker && template build base-worker && up --template base-worker` recipe with the manifest flow. |
| `nix/images/examples/llm-agent/flake.nix` (L13-16 header) | Update header recipe comment. |
| `crates/mvm-cli/tests/cli.rs` (and unit tests in `mvm-core`) | New tests below. |

Reuse:
- `mvm_core::util::parse_human_size` — memory/disk sizes
- `mvm_core::naming::validate_flake_ref` — flake validation
- `commands::shared::resolve_optional_network_policy` — `--network-preset` / `--network-allow`
- `mvm_runtime::vm::template::lifecycle::{template_build, template_build_with_snapshot}` — runtime build primitives stay; only their key argument changes from `id` to slot hash.

## Verification

1. `cargo test --workspace` — all green; new tests cover manifest discovery (cwd walk-up, `--mvm-config` file/dir), both filename forms, dual-file conflict, canonical-path normalisation (symlink resolution, trailing slash), drift refusal, override merge, persisted `manifest_path` round-trip, orphan detection.
2. `cargo clippy --workspace -- -D warnings` — clean.
3. Manual: `cd nix/examples/hello && cargo run -- template init && cargo run -- template build` — manifest written, slot created at `~/.mvm/templates/<hash>/`, artifacts built.
4. Manual: from a sub-directory of the example, `cargo run -- template build` walks up and finds the manifest.
5. Manual: `cargo run -- template build --mvm-config nix/examples/openclaw` — resolves the manifest in that directory.
6. Manual: edit `flake = "."` to a different ref and re-run `build` — refused with drift message; `--force` succeeds.
7. Manual: drop a `Mvmfile.toml` next to a flake (instead of `mvm.toml`) — same behaviour. Drop both → conflict error.
8. Manual: `mv nix/examples/hello/mvm.toml /tmp/elsewhere.toml && cargo run -- template list --orphans` — shows the original slot as orphaned.
9. Manual: `cargo run -- up --template ./nix/examples/hello` — boots from manifest path.
10. Manual: `cargo run -- template create old --flake .` — clean removal message; documented migration path.
11. Manual (mvmforge integration smoke, after coordination ticket on mvmforge lands): `mvmforge compile <ir.json> --out /tmp/wf` generates `flake.nix` + `mvm.toml`; `cargo run -- template build --mvm-config /tmp/wf` builds; `mvmforge up` translates the IR into `mvmctl up --cmd … --env …` flags. No `launch.json` involved.
12. Migration smoke: with a populated `~/.mvm/templates/openclaw/` legacy slot, `cargo run -- template list` prints the legacy banner; `cargo run -- template list --legacy` lists it; `cargo run -- template prune --legacy` removes it; new flow continues to work.
13. Cache-key change: `cargo test -p mvm-build` exercises `template_reuse.rs` with the 2-component key (`flake_lock + profile`); old role-bearing tests in `mvm-core/src/domain/template.rs:212-223` are rewritten or removed.
14. MCP `run` tool: with the new schema, an LLM client passing `env: "shell"` resolves to the built-in preset manifest; passing `env: "/abs/path/to/mvm.toml"` resolves to a user manifest; passing a non-existent name returns a clear error.
15. Prompt-driven init: `cargo run -- template init /tmp/scaffold --prompt "fastapi app with postgres"` (with `MVM_TEMPLATE_PROVIDER=heuristic` for offline determinism) emits `flake.nix` + `mvm.toml`; `mvm.toml` carries resource defaults from the lookup table (Python web → 2 vcpu/1G mem/1G disk). With `OPENAI_API_KEY` set, the structured-output schema accepts a `resources` block and overrides apply.
16. Concurrent build refusal: launch two `cargo run -- template build --mvm-config <path>` against the same manifest in parallel; second invocation aborts with "another build is in progress" before any `nix build` work runs.
17. Sizing-vs-snapshot staleness: build a slot, edit `mvm.toml` to change `vcpus = 4`, then `cargo run -- up --template <path>`; warning emitted, cold-boot from rootfs proceeds, snapshot is not restored.
18. Backend mismatch warning: build a slot on Firecracker (Lima), then run `cargo run -- up --template <path>` on macOS with Apple Container default; warning emitted, no hard failure.
19. Schema-version forward-compat: hand-write `mvm.toml` with `schema_version = 99`; `cargo run -- template build` errors with the upgrade-mvmctl hint.
20. Atomic slot writes: simulate a crash (kill -9 mid-build); subsequent `template list` does not show a half-written `manifest.json` — either the new state or the old state, never partial.
21. Provenance block: `cargo run -- template info --mvm-config <path>` prints the provenance block (toolchain version, host arch, built_at). `manifest.json` deserializes round-trip with provenance present.
