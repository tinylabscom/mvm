# mvm — Product Requirements

Status: draft for owner review, 2026-11-02, against v0.26.0.
Replaces `specs/01-project.md`.

Every capability below carries a status. **Shipped** means a test or CI gate
witnesses it. **Preview** means it runs but is bounded or unwitnessed in part.
**Planned** means designed, not built. Anything with no witness is listed under
[Not promised](#not-promised), not sold.

This document states the product and its requirements. It is not a progress
tracker. The claims ledger in ADR-001 owns what is enforced; GitHub issues own
status, scope and dependencies (for example #3553 Windows, #4414 rootless
Firecracker launch, #4839 cleanup). Where this file and the ledger or an issue
disagree, they win and this file is stale.

## What mvm is

**A microVM sandbox where you can verify what ran.**

mvm runs code you did not write, in its own kernel, on a laptop or a single
host. Every launch is described by a signed plan, admitted before boot, and
recorded in a tamper-evident audit log. The guest has no network device, no
secrets and no shell in production. It starts in under 300 ms cold, admission
included, and under 50 ms warm.

The CLI is `mvmctl`. Python, TypeScript and Rust libraries drive the same
operations. Fleet orchestration, tenants and production launch live in
[mvmd](https://github.com/tinylabscom/mvmd), not here.

## What is important always

In priority order. When two conflict, the higher one wins.

1. **Security is the top line.** A feature that weakens a numbered claim does
   not ship. Speed and DX are bought inside the security model, never by
   loosening it. Two invariants never bend: **no secret ever enters a
   microVM** (the guest holds placeholders; the host substitutes), and **no
   workload runs without a signed, audited plan.** PII is detected and
   redacted at the boundary. **Nothing requires root:** mvm never needs `sudo`
   on the host, and the user inside every microVM is non-root.
2. **Fast.** Cold launch under 300 ms (admission included) and warm startup
   under 50 ms are hard requirements, not goals. Security work (verification,
   decryption, auditing) must fit inside them. If it does not, we fix its cost;
   we do not move the ceiling. A boot-time gate enforces them on every PR.
3. **Lightweight.** Small on disk and small in use: the `.mvmpkg` size, guest
   memory and per-VM host memory are budgeted. A minimal purpose-built guest
   kernel, no NIC, no SSH, no daemon, few dependencies. Every added crate or
   guest binary needs a reason.
4. **Reproducible.** Same inputs, same image, on every host. Builds run in a VM
   we launch; host tools never touch the result. We rebuild and replace, never
   patch a running machine.
5. **Composable.** Policy is built from small layers with fixed precedence, and
   composition can only narrow what a lower layer granted.
6. **Observable.** Tracing everywhere: every launch phase, admission decision,
   host-service call and backend step emits a span, in the host and the
   guest, so any latency or refusal can be explained from its trace. A gate
   enforces coverage; "everywhere" is checked, not asserted.
7. **Many backends, one abstraction.** HVF, libkrun, Firecracker, QEMU and the
   claim-free tiers sit behind one backend trait. A backend may advertise less
   (a snapshot tier, a CPU quota); it may not silently do less than it
   advertises, and unsupported requests fail closed.
8. **Effortless to use, rigorous to build.** One command does the obvious
   thing, `--help` documents every verb, `doctor` says what is missing. The
   code follows the repo's Rust rules: small single-purpose functions, builders
   for wide types, traits for backend variation, newtypes over stringly flags,
   reuse before writing, zero clippy warnings, a test for every new function.
9. **Fast to develop.** The inner loop is short: an incremental build, a
   scoped test run and a local launch all take seconds to low minutes, and a
   PR reaches merge quickly. Contributors need no host Nix, no Docker and no
   root. Slow loops are bugs. The bar is a number, not a feeling (see Open
   decisions).
10. **Honest.** Every claim ships with its limit. If a property is policy and
    not absence, we say so.

## Who it is for

- **AI agents running generated code.** Every execution is untrusted. Network,
  secrets and filesystem are under policy.
- **Code interpreters and agent products** that need a real, stateful
  environment without handing users your infrastructure.
- **Regulated environments** that must prove isolation, show nothing persists
  between runs, and hand over a signed audit trail.
- **CI and build isolation** for untrusted builds and third-party steps.

## The pillars

### Verifiable (Shipped)

Every workload runs from a typed `ExecutionPlan`, signed by the host key,
checked for validity window and replay, and only then launched. Admission,
launch and failure are written to a hash-chained audit log. Dependency volumes
carry an SBOM and CVE scan; OCI images record full provenance. Claims 8, 9, 11,
14, 19, 20.

```bash
mvmctl trust audit verify
```

Limit: tail truncation of whole sessions is undetectable without an off-host
witnessed root. The host is trusted with the signing key.

### Walled (Shipped)

A workload microVM has no network device. Everything leaves over vsock to a
per-VM host process that opens each outbound connection itself. That one seam
enforces default-deny egress and swaps secret placeholders for real
credentials, so the guest never holds them. Claims 10, 13; Preview 16.

```bash
mvmctl machine run --image alpine --allow-host api.example.com:443 -- ./fetch
```

Limit: a secret's destination is bound at the host; the guest can still send
the placeholder anywhere it is allowed to connect. Stdin, when granted, is a
policy gate with a fingerprint scan, not an identity check (Preview 17).

### Scrubbed (Preview detection; replacement and taint are Planned requirements 15 and 16)

Because the host owns the wire, it can inspect traffic in both directions.

- **PII.** `PiiRedactor` detects only today. The requirement is detect **and
  replace**: a matched value (SSN, card number, email, phone) is substituted
  with a stable token before it leaves, and the event is audited by rule name,
  never by value. ADR-001 already carries this design as "Reversible
  replacement on owned cleartext paths" (proposed, not accepted): replace with
  opaque tokens, restore only exact token echoes, policy inside the signed
  plan, plaintext-free proof metadata. Limit: patterns find structured identifiers.
  Names follow the owner's rule: a name is PII only as a full name, a first
  and last name together. "Kim" alone is not PII; "Kim Williams" is. Finding
  a full name needs a name dictionary or model plus adjacency, or declared
  values. State which when it is built, publish its known misses and false
  positives, and claim no more than that.
- **Prompt injection.** Detection is pattern-based and advisory; it will have
  false positives. The guarantee that matters is deterministic: content of
  untrusted provenance cannot authorize a privileged action, because reaching
  a host service or releasing a secret needs a signed binding in the plan.
  Taint tracking is the work that makes that provenance real. It is on only
  when there is something to escalate to: egress, a host-service binding, a
  secret binding or a tool grant is admitted. A fully offline sealed workload
  carries no taint cost. The trigger is capability, not a pack label, because
  "this pack contains an agent" is not something the host can verify.

### Sealed (Shipped)

A production workload has a dm-verity root filesystem, no console, no shell and
no DevOnly verbs. A flipped block stops the boot. Services run as unprivileged
uids under `mvm-setpriv --no-new-privs` with a seccomp tier chosen at
admission. When a session ends the guest and its memory are destroyed. Claims
1–4, 15.

Limit: local `mvmctl` launches are development mode. The only production launch
authority is an authenticated launch from `mvmd` (ADR-037). A cold boot on a
guest agent older than the seccomp token applies no filter (claim 1 row).

### Volumes (Shipped as policy; not yet a numbered claim)

A user can attach their own volumes, read-only or read-write. They can never
sit on top of anything the system owns.

- **Read-only is the default.** Read-write is explicit, per volume.
- **Allow-list, not deny-list.** A user volume may land only at or under
  `/data` or `/work`. Every other path is refused, including `/bin`,
  `/usr/bin`, `/etc`, `/proc` and any path the policy has never heard of. The
  root filesystem and every runtime-managed mount are therefore off-limits by
  construction, not by a list someone must keep complete.
- **Containment is checked both ways.** A mountpoint is refused if it sits
  inside a protected path *or* above one, because a mount over a parent would
  hide everything beneath it. Refusals name the protected path.
- **The guarantee.** A volume cannot shadow or replace the verified root
  filesystem, the config and secret drives, or a system directory.

Witnessed by unit tests on `MountPathPolicy` (`mvm-core`
`crypto/policy/mount.rs`), including the ancestor and segment-aware cases. The
allow-list is deliberate and strict; widening it needs an ADR. No ADR-001
claim row names this policy yet. Adding one (under claim 1, "no host-fs access
beyond explicit shares") is part of making it a ledger entry.

Corrections to earlier drafts: the allowed roots are `/data` and `/work` only.
`/mnt` was removed because a share there hid the config and secret drives, and
`~/.cache` is not an allowed root today.

### Rootless (anti-escalation Shipped; never-root and rootless host Planned)

- **In the guest.** What ships is the narrower guarantee: no guest binary can
  elevate to uid 0 (claim 2). Services run as their own unprivileged uids
  through `mvm-setpriv --no-new-privs`, and the passwd, group and nsswitch
  files are read-only bind mounts. The stronger requirement, that the runtime
  never runs as root and there is no usable root account, is ADR-026, still
  `Proposed`. It is a requirement here, not a claim; do not promote it until
  its build-time no-setuid check and runtime euid witness exist.
- **On the host.** The requirement is that `mvmctl` never needs `sudo`. Today
  that is **not true on Linux/Firecracker**: the driver starts Firecracker
  under `sudo` as root, stops it with `sudo kill`, and reaches its API socket
  with `sudo curl` (`mvm-backends` `fc.rs`, `fc/host.rs`, `fc/control.rs`).
  `install.sh` also falls back to `sudo`. macOS HVF and libkrun do not need it.
- **The approved direction** is ADR-001 PS-21 (issue #4414, option A): direct
  current-user launches with operator-provisioned access (for example `kvm`
  group membership) and predelegated resources. Missing rights refuse before
  the process is created; there is no `sudo`, `doas`, `pkexec` or shell
  fallback; limits apply at birth, not by a later move into a cgroup. This is
  a design direction, not shipped enforcement. The one-time OS step is outside
  mvm, and `doctor` must name it.

A lint that fails on any new `sudo` spawn keeps the result.

### Composable (Shipped)

What a workload may do is written once as groups, composed by profiles, and
resolved into the signed plan. Precedence is fixed and the merge rules are the
security contract:

- Groups apply first; then each profile's `when` blocks and `overrides`,
  parents before children. With repeated `--policy`, the last one wins.
- A deny beats any allow from any layer. `network.block = true` cannot be
  undone by a later layer.
- Resource values are ceilings; the smallest wins and a flag cannot exceed it.
- Secret destinations, tool detail and shares only narrow.
- Signed packs cannot mount host directories. Escape hatches are user-only.
- A pack's grants are bounded by pack, application, invocation, user policy and
  host constraints (ADR-055).

Precedence is one rule set (settled by the owner, 2026-11-02):

1. **Layers.** Host constraints, organization policy, user policy (groups and
   profiles; with repeated `--policy`, the last wins), the signed pack and
   application, and the invocation's flags.
2. **Ceilings, denies and blocks are monotone.** Set by any layer, they are
   never undone by another. Resource values are ceilings; the smallest wins.
3. **Grants come only from the host owner's layers** (host, organization,
   user, flags): allowed hosts, secret bindings, shares, environment names,
   tools. A pack or application may request a grant; a request grants nothing
   until a user layer grants it.
4. **Effective permission is the grant intersected with every layer's
   ceiling**, the pack's and application's included. A signed ceiling binds the
   user and cannot be widened locally.
5. **Choices that are not security limits** (a timeout default, a name): among
   peer layers the last wins, parents before children.
6. **Escape hatches exist only in user-authored layers.**
7. **Every rule has a test, and `mvmctl policy show` says which layer decided.**

To verify before this is claimed: that a pack's allowed network hosts are
requests, as its secret bindings and host shares already are.

```bash
mvmctl run --policy ./org-base.toml --policy ./team.toml --policy ./mine.json -- make test
mvmctl policy show agent-apis
```

Source of truth: `public/src/content/docs/guides/policy-and-profiles.md`.

### Fast (hard requirement; the gate is Planned)

| Path | Requirement | Enforced today |
| --- | --- | --- |
| Cold launch, invocation to guest ready, **admission included** | **< 300 ms**, every sample | Warm launches are refused over 300 ms; cold is only measured on the dispatch window |
| Warm startup (claimed standby) | **< 50 ms** | Table budget p50 30 ms, p99 50 ms |

An unnamed run leaves a standby VM behind so the next matching run claims it.
Live-memory fork is advertised on Firecracker; save/restore state on HVF.
libkrun has no snapshot tier.

Gaps between the requirement and the tree:

- The boot-latency lane runs on manual dispatch only. It must gate every PR.
- The existing cold budget (p50 200 ms) covers dispatch only. `admit` has no
  budget. An earlier, single-host measurement put admission alone near 280 ms;
  it has not been re-run, so assume cold-with-admit does not yet meet 300 ms
  until measured.
- The only published cold result is 20 samples on one Linux/Firecracker host.
  HVF needs its own.
- **HVF warm claim misses the 50 ms bar by about 3x.** It measured ~145 ms on
  2026-10-30; ~104 ms of that is forking the child at claim, because HVF has
  no preloaded child. Firecracker already preloads one and measured ~32 ms
  p50 after the sealed-digest fix, on a shared rotational box, so that is a
  before/after and not gate evidence. Closing the HVF gap is a requirement of
  this PRD, not a nice-to-have.

### Portable — packs (Preview)

A **pack** is an immutable, signed workload distribution: a prepared
environment, its policy and its declared applications, under a publisher
namespace with explicit trust (ADR-055). `mvm/` is reserved for packs verified
under the MVM release identity and a fresh signed revocation document; absence,
expiry or rollback fails closed. A signature proves who published and that the
bytes are intact; it says nothing about safety. Pack-authored secret bindings
are requests, never authority.

A `.mvmpkg` is the sealed, host-signed output of `mvmctl build`, re-verified at
fetch and at admission (claim 9). Packs live in
[mvm-packs](https://github.com/tinylabscom/mvm-packs) and are the image
registry going forward (ADR-054).

```bash
mvmctl build .            # writes a host-signed ./<name>.mvmpkg
mvmctl pack pull <ref>    # also: info verify lock compile search ls rm update
```

Smaller is better: `.mvmpkg` size on disk is a budgeted metric (see
[Lightweight](#what-is-important-always)).

### Observable (Preview — coverage is uneven and ungated)

The host assembles a tracing subscriber with fmt, span-timing and OTLP layers
(`mvm-cli` observability module), and launches report per-phase timings. The
requirement is full coverage: every phase of a launch, every admission and
policy decision, every broker call, and the guest agent's own steps.

Today the files that mention tracing are about 7% of `mvm-core`, 10% of
`mvm-agentd`, 14% of `mvm-cli`, 26% of `mvm-hostd` and 44% of `mvm-backends`.
That is a crude proxy, not a coverage measure, and no gate checks it. The
work: define what "covered" means (a span per launch stage and per trust
decision), add a lint that fails when a stage lacks one, and keep payload
bytes and secret values out of spans.

```bash
mvmctl doctor
mvmctl trust audit verify
```

Tracing is operational telemetry. The chain-signed audit log remains the
evidence record; the two must not be confused.

## Authoring

Nix is the engine; users never need to learn it. Every surface lowers to one
workload IR and produces the same image. The SDKs exist to make packs easy to
build: the decorator declares a workload, the live SDK drives a sandbox, and
both are first-class. Builds run in a headless builder VM, so the host needs no
Nix installed.

| Surface | Status |
| --- | --- |
| Decorated function (`@mvm.app`), read statically, never run on the host | Shipped |
| OCI image (`image pull`, `machine run --image`) with provenance audit | Shipped |
| `mvm.toml` manifest, Nix flake via `mkGuest` | Shipped |
| Runtime `Sandbox` API (exec, copy, ports, timeouts) | Shipped (Python, TypeScript) |
| Dependencies from the language manifest, sealed read-only in the builder | Shipped |
| Lifecycle hooks `before_build`, `after_build`, `before_start`, `after_start`, `before_stop` | Shipped |

```bash
echo '[[], {"name": "ari"}]' | mvmctl machine run --entrypoint --flake ./out
```

SDK types are generated from one schema, so a new language is a new generator.
Beyond Python and TypeScript, the route to more languages is the host library's
C ABI (requirement 14). A Kotlin tree for pack authoring exists in
`crates/mvm-sdk/sdks/`; it is not yet a promise.

## Platforms

| Host | Workload backend | Status |
| --- | --- | --- |
| macOS 26+ Apple Silicon | In-house HVF VMM (default) | Shipped, Tier 2 |
| macOS 13–25 Apple Silicon | libkrun | Preview, Tier 2 (live hardware witness open) |
| Linux with `/dev/kvm`, x86-64 and aarch64 | Firecracker | Shipped, Tier 1 (aarch64 builder untested) |
| Linux without KVM | QEMU/TCG, dev and test only | Tier 2, not an isolation target |
| Browser | WebLinux, direct WASI | Claim-free: no numbered claim applies |
| Windows x86-64 with WHP | libkrun on the Windows Hypervisor Platform (issue #3553) | Planned; blocked on a qualified Windows host for a boot witness |
| WSL2 | QEMU, explicit dev/test only | Experimental |

`apple-container` is opt-in only. The Docker tier is retired: hosts without a
hypervisor fail closed.

## How it compares

By category, not by product.

| | mvm | Containers | Hand-run VMM | VM-per-container runtimes |
| --- | --- | --- | --- | --- |
| Boundary | VM + own kernel | Shared kernel | VM + own kernel | VM + own kernel |
| Signed, audited admission | Yes | No | No | No |
| Guest has a NIC | No | Yes | Usually | Yes |
| Secrets inside the guest | Placeholders only | Yes | Yes | Yes |
| Embeddable libraries | Yes | No | No | No |
| Signed, verifiable release artifacts (claim 20) | Yes | Varies | Varies | Varies |

A startup-time row belongs here only once mvm's own number is gated and the
others are sourced from a benchmark we ran.

## Boundaries

| Repo | Owns |
| --- | --- |
| mvm | CLI, host runtime, guest runtime, SDKs, `mkGuest`, claims ledger |
| mvmd | Tenants, pools, fleet, **production launch authority** |
| mvm-images | Linux layer only: kernels, base rootfs, builder image, Stage 0 seeds |
| mvm-packs | Signed packs, the image registry, the `mvm/` namespace |

The guest runtime ships with each `mvmctl` release as one signed asset (claim
20). `mvmctl` assembles overlay, initramfs and SDK sidecar from it at boot.

## Security claims

The ledger is the claims table in ADR-001 (claims 1 to 21);
`xtask check-claim-catalog` fails if a named witness disappears. Claims 16–18
are Preview; the rest are Shipped. Claims hold in full only on the Tier 1
backend (Firecracker on Linux/KVM). HVF, libkrun and QEMU are Tier 2: for
example verified boot is block+ext4 only there. The per-backend matrix in
ADR-001 is the authority, and every pillar above is read through it.

Out of scope, always: a malicious host and multi-tenant guests. Hardware
attestation is in scope only as an opt-in TPM2 measurement source (ADR-001
amendment, 2026-08-24); the host stays trusted. The hypervisor can read live
guest memory; only hardware confidential computing closes that.

## Planned requirements from a field comparison

Rows 1 to 14 come from a study of a comparable local microVM project's README
and docs; rows 15 and 16 are owner requirements from the Scrubbed pillar. Each
is a requirement here, status Planned unless noted. None may weaken a numbered
claim.

| # | Requirement | Acceptance |
| --- | --- | --- |
| 1 | **One-command first run.** After install, `mvmctl machine run --image alpine -- uname -a` works with no prior `doctor`, `bootstrap` or `image pull`. Setup happens inside the run, and says what it is doing. | A clean-host test runs the single command and passes. Counts toward the 300 ms bar only once artifacts are cached; first-run download time is reported separately. |
| 2 | **Agent-readable docs.** An `llms.txt` index plus one folder per task, each with a `README.md` of facts and a `SKILL.md` an agent can follow, with tested scripts. Every procedure states the version, date and host it was verified on, and a "done means" condition. Known regressions are listed with issue links. | CI runs each procedure's scripts on the release candidate and fails on drift. |
| 3 | **A pack that runs by itself.** A signed `.mvmpkg` can be run as an executable with `run`, `start`, `exec` and `stop`, nothing to install and no downloads at run time. Verification (claim 9) happens on every run and counts toward the budget. | A copied pack boots on a clean host, verified, inside the cold and warm bars. Size on disk is reported per release. |
| 4 | **Live policy change on a running machine.** Narrowing (revoking a host, shrinking a ceiling) applies to the next connection and is audited. Widening requires a new signed plan delta under the same precedence and monotone rules, and is audited. | Tests: revoke takes effect on the next flow; a widening without a signed delta is refused. |
| 5 | **One-flag secret binding.** A single flag or one manifest table binds a secret to its exact hosts, optionally its methods. Header substitution is the default; body substitution is explicit and form-encoded only. A placeholder sent to any other host, query string or body is refused. The value never enters the machine record, a checkpoint, a span or the audit log. | Extends claims 13 and 16; witnesses for method limits and for checkpoint and trace cleanliness. |
| 6 | **State as an artifact.** Pause and resume, checkpoint and restore, and branching from a running machine, with history and rewind. Checkpoints are encrypted, signed and content-addressed. A checkpoint taken on an Apple Silicon host resuming on arm64 Linux is the portability target. Branches get a fresh identity (machine id, hostname, RNG reseed). | Fork exists on Firecracker and HVF today. Cross-host resume, rewind and history are Planned. Restore stays inside the warm bar. |
| 7 | **One checked-in file.** Image, resources, ports, mounts, network policy and secret bindings in one file (`mvm.toml` plus a policy profile), with strict parsing: an unknown key is an error. | Schema is generated from types and a test fails on drift (as policy profiles do today). |
| 8 | **A Known Limitations page**, kept beside the docs and generated or checked against this PRD's Not promised list. | A doc-sync test fails when the two disagree. |
| 9 | **Teardown you can trust.** One documented command lists what state exists and where, and leaves nothing running. | A test starts machines, interrupts the CLI, and asserts no VMM process survives. |
| 10 | **Pack ownership fidelity.** Building and running a pack preserves every file's uid and gid exactly, not "owned by whoever ran the tool". | A test packs a tree with non-root owners and asserts them inside the guest. |
| 11 | **Windows through libkrun on WHP.** Promote the existing libkrun backend to a released Windows x86-64 tier rather than write a native WHP driver (a from-scratch hypercall and virtio layer is out of scope). Where WHP is absent or libkrun cannot start, refuse with a named reason; never fall back to another tier silently. Keep admission-visible tier labels. Preserve private-state permissions with Windows ACLs equal to the 0700 posture elsewhere. | A boot witness on a real Windows host is archived. `doctor` reports the tier and capabilities, and the platform matrix matches it. Until the witness exists the tier is Preview and claim-free. The guest stays NIC-less and vsock-only; if the WHP path cannot hold that, it ships behind a stated limit, not silently. No GPU on this path. |
| 12 | **Easy installation on every platform.** One command installs a signed release with no prerequisite: `curl \| sh` on macOS and Linux (user-writable prefix, no `sudo`), a Homebrew tap, distro packages, and `winget` plus a signed zip on Windows. Every channel verifies the signature (claim 20) before running anything. `mvmctl doctor` names anything still missing. | A clean-VM install test per platform ends with requirement 1 passing. |
| 13 | **Elastic memory on every backend.** A guest returns memory it frees, and a machine's footprint tracks its use, not its size. Over-provisioning costs close to nothing. | Today: HVF uses free page reporting; Firecracker uses a target balloon driven by host pressure; libkrun and QEMU report no mechanism. Each backend must either implement one or advertise `none` in `doctor`. A test fills and frees guest memory and asserts the host footprint falls. Publish the footprint numbers beside the launch budgets. |
| 14 | **Language bindings through the host library's C ABI.** `libmvm_hostlib` already exposes a versioned C ABI (`mvm_hostlib_abi_version`, `mvm_hostlib_abi_is_compatible`, `mvm_hostlib_call`, `mvm_hostlib_free`, an approval callback) that takes and returns JSON, so any language with a C foreign-function interface can bind it without a subprocess. Candidates in priority order: Go, Java and Kotlin, C#, Swift. Each binding is a thin loader plus types generated from the existing schema. | A reference binding in one new language passes the client-interface conformance suite (ADR-043). Bindings call the version handshake before their first call, free every returned buffer, and never shell out (`check-no-cli-shellout`). How the signed library reaches users per platform is part of the work. |
| 15 | **PII replacement.** Detect and replace, not detect only. A matched value (SSN, card number, email, phone, full name) is substituted with a stable opaque token on the host-owned wire before it leaves, and restored only on an exact token echo. The event is audited by rule name, never by value. Policy lives in the signed plan and can only narrow. A name is PII only as a full name (first and last together). State how names are found (dictionary, model plus adjacency, or declared values) and publish the known misses and false positives. Builds on ADR-001's proposed "Reversible replacement on owned cleartext paths". | Tests: each rule replaces on egress and restores only an exact echo; no raw value reaches the wire, a span, a checkpoint or the audit log; a policy cannot widen a lower layer's rule. The claim is limited to what the published miss and false-positive list supports. Needs an ADR-001 ledger row before it is called Shipped. |
| 16 | **Taint tracking.** Content of untrusted provenance cannot authorize a privileged action. Reaching a host service or releasing a secret already needs a signed binding in the plan; taint makes the provenance real. It is on only when something is admitted to escalate to (egress, a host-service binding, a secret binding or a tool grant), so a fully offline sealed workload pays nothing. The trigger is capability, not a pack label. Prompt-injection detection stays advisory and pattern-based, with false positives. | Tests: a tainted input cannot cause an unbound host-service call or secret release; an offline workload runs with taint off and no added cost on the launch budgets. Trigger confirmation is open decision 3. Needs an ADR-001 ledger row before it is called Shipped. |

Also noted for decision, not yet required: a local,
privacy-preserving lifecycle journal (counts and shapes only, no names, paths or
commands, off by default). It must never become telemetry that leaves the host.

## Trusted computing base

State it as plainly as a limit. In a local launch the invoking host user, the
host OS, the hypervisor backend and mvm itself are trusted. Host directories
mounted into a guest are exposed with the requested access. Every capability
granted (a mount, a host, a port, a secret binding, stdin) becomes authority the
workload holds. Guest root, where a dev image has it, is untrusted. mvm
provides the boundary and the evidence; the policy decides what crosses it.

## Not promised

Cut from the old PRD until a witness exists. Each may return as Planned with an
ADR. PII replacement and taint tracking are not here: they are Planned
requirements 15 and 16. Until built, only detection ships, and the standing
guarantee is the narrower one: a privileged action needs a signed binding in
the plan.

- **S3, R2 or MinIO-backed volumes.** Deferred by the owner; not to be
  scoped yet. The volume spec type parses `s3://`; no end-to-end witness
  exists.
- **An interactive shell inside the builder VM.** The builder is headless and
  exists only to run Nix builds. The shell is a dev image booted with
  `machine run -it`.
- **WASM as a core goal.** It is a claim-free portability tier.
- **TUN/TAP over vsock.** Superseded by one flow-aware path (ADR-042).
- **A Docker or container fallback.** Retired.
- **Fleet scheduling, tenants, deploy.** mvmd.
- **Encryption of "every piece of data on the host".** Checkpoints are
  encrypted at rest; a full at-rest inventory has not been verified.

## How we measure direction

Each release, check the PRD against the tree:

- Every Shipped row has a named witness in ADR-001 or a gate.
- Cold < 300 ms (admission included) and warm < 50 ms hold on a PR-gating
  lane, on both Linux and HVF.
- A tracing-coverage lint passes, and no span carries a secret or payload.
- No `sudo` spawn exists in `mvmctl`, and every guest service runs non-root.
- Every backend's advertised capabilities match what `doctor` reports and what
  its tests exercise.
- `cargo fmt`, clippy with warnings denied, nextest and doctests are green.
- No new guest NIC, guest-side secret, shell or listening socket
  (`check-single-network-path`, `check-prod-agent-no-exec.sh`).
- Policy merge rules have a test per row of the table above.
- README examples run; they gate releases.
- Nothing is added to Not promised without moving to Shipped or Cut.

## Open decisions for the owner

Settled by the owner on 2026-11-02: cold under 300 ms including admission,
warm under 50 ms, the boot-time gate on every PR, the precedence rule set,
lightweight measured by `.mvmpkg` size on disk and by memory (guest and
per-VM host), headless builder, SDKs first-class, a name is PII only as a full
name, S3 volumes deferred. Still open:

1. **Budgets for Lightweight and for development speed.** The metrics are
   chosen. Measure today's `.mvmpkg` size, guest memory and per-VM host memory,
   plus incremental build time, scoped test time and PR time-to-merge, then set
   the numbers.
2. **Warm startup definition.** Confirm "under 50 ms" is the warm claim, as
   the table assumes; cold cannot reach 50 ms without a different design.
3. **Taint trigger.** Confirm the recommendation: on when egress, a host
   service, a secret or a tool grant is admitted; off for offline workloads.
4. **First language binding.** Pick the reference binding for requirement 14
   (recommended: Go).
5. **Cache and home mounts.** Tools want a persistent cache (`~/.cache`,
   package caches). Today only `/data` and `/work` are allowed. Either keep it
   that way and document a `/data/cache` convention, or add one more allowed
   root by ADR. I'd keep the allow-list as is.
6. **Make mount policy a ledger claim.** Add an ADR-001 row with its witness
   so `check-claim-catalog` guards it.
