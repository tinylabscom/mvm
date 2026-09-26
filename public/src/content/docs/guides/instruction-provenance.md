---
title: Provenance for instruction files
description: Sign agent instruction files (CLAUDE.md, AGENTS.md, SKILL.md, .claude/**) with Sigstore or a local key, set a trust policy, and have every boot verify the instruction files it copies into the guest.
---

An agent treats `CLAUDE.md`, `AGENTS.md`, a `SKILL.md`, or a rules file as
instructions. A poisoned one is a prompt injection with no code in it at all.
`mvm` verifies release artifacts with Sigstore; this is the same idea applied to
what an agent reads as instructions: a trust policy says who may sign them,
signatures sit beside the files, and every boot verifies the instruction files
it is about to copy into the guest before admitting it.

**Status: Preview.** The gate and its audit entries are wired into admission
and tested, but this is not one of the numbered security claims in the
[claim ledger](/security/claim-ledger/). Read the [limits](#limits) before
relying on it.

## Quick start

```sh
# Write a user policy that trusts this host's signing key and refuses
# (enforcement = "deny") any boot whose instruction files do not verify.
mvmctl trust instructions init

# Review the files, then sign them with the host key.
mvmctl trust instructions verify ./my-agent        # lists what fails, exits nonzero
mvmctl trust instructions sign ./my-agent          # writes <file>.mvmsig.json beside each
mvmctl trust instructions verify ./my-agent        # passes

# Every boot now checks what it copies into the guest.
mvmctl run --mount ./my-agent:/work -- claude -p "…"
```

Edit a signed file and the next boot refuses it, naming the file and the reason
(`bad signature: … file changed after signing`).

## Which files

A file is an instruction file when its path, relative to the directory being
scanned, matches one of the policy's `includes` globs. With none configured the
built-in list applies:

```text
**/CLAUDE.md   **/CLAUDE.local.md   **/AGENTS.md   **/AGENT.md
**/GEMINI.md   **/SKILL.md          **/.claude/**/*.md
**/.cursor/rules/**                 **/.cursorrules
```

Matching is case-insensitive, because a case-insensitive host filesystem serves
`claude.md` to an agent that asked for `CLAUDE.md`. `*` does not cross `/`;
`**` does. Signature files (`*.sigstore.json`, `*.mvmsig.json`) are never
instruction files themselves. `.git/` is skipped and symlinked directories are
not followed; a symlinked file is verified by its target only while the target
stays inside the scanned directory.

## Signatures

Each file carries its own signature beside it, rather than one bundle per
directory:

| Sidecar | Written by | Checked against |
| --- | --- | --- |
| `<file>.sigstore.json` | `cosign sign-blob --new-bundle-format --bundle <file>.sigstore.json <file>` in CI | a `keyless` publisher: the certificate's OIDC issuer, repository, workflow and ref |
| `<file>.mvmsig.json` | `mvmctl trust instructions sign` with a local Ed25519 key | a `keyed` publisher |

Per-file sidecars travel with the file when it is copied or mounted on its own,
an edit invalidates only that file's signature, and the verifier checks exactly
the bytes an agent reads with no manifest in between whose coverage could drift.

The keyless bundle is a standard Sigstore bundle, verified offline by the same
in-process verifier `mvmctl` uses for [its own release
artifacts](/guides/verify-release/) against the embedded Sigstore trust root and
the bundle's own transparency-log inclusion proof. That verifier ships in
release builds and in builds with `--features user`; a build without it reports
a keyless signature as `verifier_unavailable`, which fails under `deny`.

A keyed signature is a small JSON envelope — `key_id`, the file's SHA-256, and an
Ed25519 signature over a domain-separated digest — not a Sigstore bundle, because
a Sigstore bundle's verification needs a transparency-log entry a local key
cannot produce offline.

## The policy

The user policy lives at `$MVM_HOME/config/instruction-trust.toml`
(`~/.mvm/config/instruction-trust.toml` by default) and is authoritative. A
project may carry its own at `<project>/.mvm/instruction-trust.toml`. Both have
the same shape; the [JSON Schema](https://github.com/tinylabscom/mvm/blob/main/schema/instruction-trust-policy-v0.json)
is generated from the Rust types the file is parsed into, and unknown keys are
refused at every level so a misspelt restriction is an error rather than absent.

```toml
# deny (the default when a policy exists), warn, or audit.
enforcement = "deny"

# Omit to use the built-in list; an empty list selects nothing.
includes = ["**/CLAUDE.md", "**/AGENTS.md", "**/.claude/**/*.md"]

# A CI workflow signing keylessly. repository and workflow match exactly;
# ref is a glob.
[[publishers]]
kind = "keyless"
name = "agents-ci"
issuer = "https://token.actions.githubusercontent.com"
repository = "acme/agents"
workflow = ".github/workflows/sign-instructions.yml"
ref = "refs/heads/main"

# A local key: either enrolled with `mvmctl trust add` and named by key_id,
# or given inline as 64 hex characters. Exactly one of the two.
[[publishers]]
kind = "keyed"
name = "reviewer-laptop"
public_key = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"

# Refused whoever signed them.
[[blocklist]]
sha256 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
reason = "poisoned CLAUDE.md from incident 7"
```

`mvmctl trust instructions policy [--project DIR]` prints the effective policy
after merging.

### Merge rules

| Policies present | enforcement | includes | publishers | blocklist |
| --- | --- | --- | --- | --- |
| none | `audit` | built-in | none | none |
| user | user's (default `deny`) | user's or built-in | user's | user's |
| user + project | the stricter of the two | union | user's, narrowed to those the project also lists | union |
| project only | project's, capped at `warn` | project's or built-in | project's | project's |

A project can only add restrictions: raise enforcement, add include patterns,
block digests, or narrow the user's publishers to entries it repeats verbatim.
A project publisher the user does not trust is ignored and reported, never
added, and a project asking for a weaker mode than the user's is ignored and
reported. A project policy with no user policy above it is **advisory**: a
repository cannot declare which publishers vouch for its own files and then have
that declaration decide a boot, so its findings warn and never refuse. A broken
user policy refuses the boot; a broken project policy refuses it only when a
user policy exists to give it force.

## Before every boot

Admission scans every host path the boot copies into the guest:

- each `--mount` source directory,
- each `--asset` file or tree,
- the workload's own source directory, when `--flake` or `--manifest` names a
  local path — the project policy is read from there too.

Each instruction file gets a verdict — verified, unsigned, or refused for a
named reason — and a chain-signed audit entry bound to the plan the boot was
admitted under, whatever the enforcement mode:

| Event | Meaning |
| --- | --- |
| `trust.instruction_verified` | Signed by a trusted publisher. Labels include `publisher` and `signer`. |
| `trust.instruction_unsigned` | No signature beside the file. |
| `trust.instruction_blocked` | Refused: `reason` is `digest_blocked`, `publisher_mismatch`, `bad_signature`, `verifier_unavailable`, or `unreadable`, with a `detail`. |

Every entry carries `path`, `root`, `root_kind` (`mount`, `asset`, `workload`),
`sha256`, `enforcement`, `policy` (`builtin`, `user`, `user+project`,
`project-advisory`), and `action` — `admitted`, `refused`, `warned`, or
`recorded` — so a `blocked` entry says whether the boot was actually stopped.
Labels never carry file content. Then:

- **deny** refuses the boot, naming each failing file and why, and records
  `plan.admission_refused` with stage `instruction_provenance`. The boot is
  never recorded as admitted.
- **warn** prints each failure and boots.
- **audit** records and says nothing.

With no policy anywhere the built-in includes apply in `audit` mode, so the
chain shows which unsigned instruction files went into a guest without refusing
anything. Under an operator-written policy, a verdict that cannot be written to
the chain fails the boot.

## Signing in CI

`.github/workflows/sign-instructions.yml` signs this repository's instruction
files keylessly on a push to `main` that touches one (or on manual dispatch),
verifies every fresh bundle through `mvmctl trust instructions verify` under a
policy trusting exactly that workflow and ref, and uploads the bundles as an
artifact. It holds no write access: a maintainer reviews the artifact and lands
the bundles through a pull request.

To sign another repository's files, **copy** the workflow into that repository
rather than calling it as a reusable workflow. A keyless certificate names the
workflow file that ran; for a called workflow that is the called file, whoever
called it, so a policy trusting a shared reusable workflow would trust every
repository able to call it. Pin the copy's own identity in the publisher entry,
and pin the ref: `workflow_dispatch` can run the workflow on any branch, which
signs under that branch's ref.

`mvmctl trust instructions sign --dry-run DIR` prints the files the policy
selects, one per line — the list the workflow signs.

## Limits

These are the known gaps. None is silently papered over.

- **Volumes attached as block devices are not scanned — including a persistent
  machine's host-directory volume.** A disk-image volume, and a volume
  registered with `mvmctl machine volume mount`, reach admission as a block
  device rather than a host tree, so instruction files inside them are never
  verified. That matters most for `mvmctl machine volume mount <vm> --host DIR`:
  the directory is re-snapshotted at the machine's next start after a host
  edit, so an instruction file rewritten on the host reaches the guest at the
  next start without passing this gate. With `--rw`, a restart also reuses the
  machine's private copy while `DIR` is unchanged, so an in-guest rewrite
  survives restarts. Open.
- **A `--mount` never changes under a running guest.** `--mount` is
  materialized into an ext4 image — a snapshot, handed to each launch as a
  private copy-on-write clone — not a live share, for transient runs and
  `machine run -d` alike, and it is scanned at every admission. What the guest
  reads is fixed at boot.
- **`:rw` mounts are writable inside the guest.** `--mount` is read-only unless
  `:rw` is given; with `:rw` an in-guest process can rewrite its own copy for
  the rest of that boot. A transient run discards the copy on exit.
- **The scan reads the host source, not the materialized image.** The mount
  image is built moments before admission scans the directory it came from. The
  share's content digest recorded in the plan is re-checked when the share is
  attached, so a post-admission edit is refused, but the image is not re-scanned.
- **Only host trees are scanned.** Files baked into an OCI image, or into a
  flake fetched from a remote reference, are not; a local `--flake`/`--manifest`
  directory is.
- **Keyless verification needs the Sigstore verifier in the build** (release
  builds, `--features user`).
- **GitHub Actions is the only keyless identity understood**: a publisher's
  certificate identity must be `https://github.com/<repo>/<workflow>@<ref>`.

## Related

- [Verifying release artifacts](/guides/verify-release/) — the same verifier,
  applied to `mvmctl` itself.
- [Audit and receipts](/guides/audit-and-receipts/) — reading the chain-signed
  log these entries land in.
- [CLI reference](/reference/cli-commands/#instruction-file-provenance).
