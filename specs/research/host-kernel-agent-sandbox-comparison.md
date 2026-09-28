# Research — a host-kernel agent sandbox, compared at the source level

Backing: preview
Validation: none — a research note read from the external project's public source and docs; the work it motivates is tracked in `specs/plans/2026-09-25-agent-sandbox-product-surface.md`

**Date:** 2026-09-25
**Owner:** mvm
**Source:** An open-source (Apache-2.0) agent sandbox that confines a local process with host-kernel primitives rather than a VM. Read from its public repositories (core library, CLI, proxy, C binding, Python/TypeScript/Go bindings, profile packs, docs) at its 0.78 release. Named obliquely throughout, per the house convention: no product, organization, or crate proper names appear here, in the plan, or in any branch, commit, or PR.

## TL;DR

Its security mechanisms are mostly thinner than ours; its product surface is
better. It confines a process on the host kernel (Landlock + seccomp on Linux,
Seatbelt on macOS), so its boundary is the host kernel we deliberately put a
VM in front of. What it does well is the experience around that boundary:
composable profiles, signed per-agent packs, live permission prompts, a
restore prompt after every run, denial-to-profile drafting, credential
placeholders, and packaging on every channel. The plan adopts the experience
and keeps our primitives (microVM, NIC-less guest, vsock-only egress, signed
and audited `ExecutionPlan`).

Its CLI is ~143k lines over a ~37k-line core: most of the product is the
policy layer, not the isolation. That is the part worth studying.

## Architecture

- **Core library**: a pure sandboxing primitive. `CapabilitySet` builder
  (`allow_path(path, mode)`, `allow_file`, `block_network`, `proxy_only(port)`)
  applied irreversibly to the *calling* process. Linux: Landlock with ABI
  probing V6→V1 as a hard requirement, a seccomp TCP-only filter to close the
  non-TCP gap, and a seccomp user-notify fallback below Landlock network ABI
  V4. macOS: a generated SBPL profile passed to `sandbox_init`, keychain Mach
  services denied unless granted. The return type of the apply call differs by
  platform, so the public API is not portable.
- **Exec strategies**: `direct` (sandbox self, exec, tool disappears — no
  proxy, audit, or rollback) and `supervised` (fork; child sandboxes and
  execs; the parent stays unsandboxed and runs the proxy, audit, rollback, and
  approvals). The supervisor sets non-dumpable / deny-attach but is not itself
  confined.
- **Proxy**: runs unsandboxed in the supervisor on loopback; the kernel pins
  the child to that one port. Modes: CONNECT tunnel with host filtering,
  reverse proxy with credential injection, upstream proxy chaining.

## What each headline feature actually is

| Feature | Mechanism | Strength | Weakness |
|---|---|---|---|
| Kernel isolation | Landlock/seccomp or Seatbelt on the calling process | zero boot cost | shares the host kernel; `PartiallyEnforced` Landlock accepted with a debug log |
| Undo & rollback | two snapshots per session (before exec, after exit) into a per-session SHA-256 content store; macOS clonefile CoW, plain copy on Linux; RFC 6962-style Merkle root per snapshot; exit prompt "Restore to initial state? [y/N]"; `rollback show --diff`, `restore --dry-run` | excellent UX | no mid-session points; per-file restore with no journal; capped at 300k files / 2 GiB; manual restore rebuilds exclusions without the session's own, so it can delete gitignored files; a file edited mid-snapshot can leave a manifest hash with no stored object |
| Audit trail | NDJSON with domain-separated SHA-256 chain + Merkle root per session, a hash-chained ledger of session digests; optional keyed DSSE attestation; `audit verify` prints VERIFIED/MISMATCH | on by default, simple UX | log, session metadata, and ledger all sit in one user-writable directory; self-attested unless the signer key is pinned externally; proxy network events held in memory until session end and lost on crash; no fsync |
| Provenance | Sigstore (keyless Fulcio/Rekor or keyed P-256) over **agent instruction files** selected by a trust policy; pre-exec scan refuses unsigned or tampered files; Linux user-notify intercepts mid-session opens; macOS adds write-deny rules for verified files | a real prompt-injection control we lacked | only as strong as the policy globs the user writes |
| Runtime supervisor | Linux only: seccomp user-notify on `openat`/`openat2`; the supervisor opens the path itself and injects the fd (`SECCOMP_ADDFD`); prompt `Grant access? [y/N]` on `/dev/tty` with an arming window; webhook and chain backends; rate-limited; every decision audited | genuinely dynamic filesystem grants | no macOS equivalent; no allow-always or decision memory |
| Network filtering | host allow-list with IDNA normalization, resolve-once (anti-rebinding), link-local and metadata denied; selective TLS interception with a per-session CA only for routes that inject credentials or carry L7 rules; method + path rules | good route model | no RFC 1918 or loopback deny by default; proxy auth lenient in sandboxed runs; macOS mDNSResponder reachable (a DNS side channel) |
| Credential injection | child gets `<PREFIX>_BASE_URL` plus a placeholder; the proxy swaps it for the real secret as header, URL path, query parameter, or Basic auth; OAuth2 client-credentials exchange in the proxy; OAuth token responses rewritten to placeholders; secret sources `op://`, `bw://`, `keyring://`, `apple-password://`, `env://`, `file://` | best-in-class UX | one session token doubles as the placeholder for every route; an `--env-credential` mode hands the raw value to the child |
| Detachable sessions | a PTY proxy behind a uid-checked Unix socket; `run --detached`, `ps`, `attach`, `detach`, `logs -f`; 8 MiB in-memory scrollback replayed on attach; single client | clean verbs | nothing survives supervisor death; no process checkpoint |
| Resource limits | cgroup v2 `memory.max` + `pids.max`, child self-attaches before it can fork | no uncapped window | Linux only; no CPU or wall-clock bound |
| Env hygiene | host env inherited minus a denylist: loader, shell-startup, interpreter-option variables, password-manager meta-secrets | cheap, effective default | denylist, not allowlist |

## Capability manifest and profiles

Two formats, both JSON (profiles accept JSONC):

- **Resolved manifest** — schema-first (JSON Schema is the source of truth;
  Rust types generated from it). Sections: `filesystem`, `network` (mode,
  domains, per-endpoint method/path rules, ports, DNS), `credentials` (source,
  upstream, inject mode), `process`, `rollback`, `resources`. Semantic checks
  the schema cannot express are validated separately. Passed with a flag that
  excludes every other sandbox flag, so the manifest is the whole policy.
- **Authored profile** — `extends` (string or list, cycle-checked, depth 10),
  `groups.include` / `exclude` over ~43 built-in named permission groups
  (deny groups for credentials, keychains, browser data, shell history; runtime
  groups per language; per-agent groups), `when:` platform predicates, and
  `platform_overrides`. Merge: lists union, child scalars win, network block is
  OR-ed so a child cannot unblock, `required` groups cannot be excluded.
  Converted to the resolved form by a `profile show --format manifest` verb.
- **Discovery** — explicit only (`--profile NAME_OR_PATH`); a user profile
  directory, installed packs, then built-ins. No automatic project-local
  profile.
- **Learn** — the old trace-based learn command was deleted. Replacement:
  after a failed run, denials from the supervisor, the macOS sandbox log
  stream, and stderr heuristics are offered as Grant / Suppress / Skip and
  written into the profile or a draft. A `why` verb answers "would this be
  allowed?" without running anything.

## Signed packs

- Per-agent profiles are not built in; they ship as registry packs (about 15
  agents). `pull ns/name` verifies one multi-subject Sigstore bundle, checks
  the signer against the namespace, checks each artifact digest against both
  the registry and the bundle, and records it in a lockfile that is re-checked
  at every launch; a missing artifact is a hard error.
- Pack and built-in profiles have their escape hatches (raw platform rules,
  binary overrides) stripped; only user-authored profiles keep them.
- A pack's "wiring" can write, symlink, or JSON-merge into the agent's own
  host config (e.g. its settings file). We do not copy this: our agent runs in
  the guest, so wiring belongs inside the image.

## Bindings and packaging

- **Bindings** — a C ABI generated by cbindgen with a CI diff gate on the
  checked-in header; Python via PyO3 + maturin (the only full SDK: spawn,
  proxy, snapshots, audit verify; hand-written stubs; sync only, buffered
  output); TypeScript via napi-rs and Go via cgo over the C ABI (both
  current-process-only and both announced for archival). Bindings lag the core
  by 4–17 minor versions; only the C header and Go have drift checks. No shared
  schema across languages. Worth copying: the header diff gate, Go examples
  whose output the test runner verifies, strict type checking, diagnostic codes
  that carry a remediation.
- **Release** — lockstep version across core/proxy/CLI; conventional-commit
  version computation; git-cliff changelog with per-release security
  advisories; matrix of Linux gnu (built on an older glibc base), Linux musl,
  and macOS arm/x86; macOS codesign + notarization before packaging; GitHub
  build-provenance attestations over tarballs, `.deb`, `.rpm`; no per-blob
  cosign signature. Channels: `curl | sh`, Homebrew, `.deb` via cargo-deb,
  `.rpm` via a spec template, Fedora COPR, AUR, nixpkgs and a repo flake with a
  `#prebuilt` output whose hashes a release job refreshes by opening a PR,
  crates.io (published in dependency order, idempotently), a container image.
- **Developer surface** — a short Makefile mirroring CI, a `scripts/`
  directory with release preparation, RPM build, and downstream-bump templates.

## Where we are stronger

- A separate guest kernel with no NIC; the host endpoint originates every
  connection, so there is no in-guest path around the gate.
- A chain-signed audit log under a host signer, with rotation handoffs,
  inclusion proofs, receipts, and `explain`.
- Per-blob cosign signatures on releases plus provenance.
- VM checkpoints and forks with audited lineage.
- Nothing phones home.

## Where they were ahead (the gaps the plan closes)

Composable profiles and packs, credential UX and secret sources, runtime
prompts, working-tree undo with a restore prompt, denial feedback and
drafting, instruction-file signing, env hygiene, detachable-session verbs,
packaging breadth, docs with per-agent recipes, and an SDK that never shells
out to the CLI.

## Pitfalls observed, not to repeat

- Restore must use the exclusions recorded with the snapshot, never rebuilt
  defaults.
- Restore must be journaled so a crash mid-restore can be completed or rolled
  back.
- A content store must never record a hash it did not store.
- Security-relevant audit events must not be buffered in memory until exit.
- A placeholder must be scoped per destination, never one token for all
  routes.
- Private ranges and loopback must be denied by default, not only link-local.
- Do not let bindings drift: one ABI, generated stubs, and a drift gate.
