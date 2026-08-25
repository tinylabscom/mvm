---
title: Air-gapped Bootstrap
description: How to run mvmctl in environments that can't reach github.com without disabling supply-chain verification.
---

# Air-gapped Bootstrap

In regulated, government, or otherwise air-gapped environments where
the host can't reach the network at all, the sanctioned path is a
**signed portable bundle** (`.mvmpkg`): build or seal one on a
connected host, then verify and launch it on the air-gapped host from
local files only — no network access needed for that step.

:::note[What changed]
The former `mvmctl dev import-image` command — a local-file import
path specifically for the dev/workload microVM image, verified against
a cosign-signed manifest — was removed along with the standalone
`mvmctl dev` command. Its would-be successor (the `dev-image` pack
class) has no publish/fetch path wired yet: `mvmctl pack download
--kind dev-image` refuses explicitly rather than pretending to work.
Signed bundles are the current sanctioned air-gapped path for shipping
a prebuilt workload; this guide describes that flow.
:::

## What you need

A signed `.mvmpkg` bundle from a trusted publisher, plus that
publisher's raw 32-byte Ed25519 public key (no PEM, no headers). The
bundle carries its own manifest (per-artifact SHA-256, target arch,
publisher `key_id`) and the artifact bytes in one archive — nothing
else needs to cross the air gap for a single workload.

## Workflow

### 1. Enroll the publisher's key (once, on the air-gapped host)

```bash
mvmctl trust add ./publisher.pub
mvmctl trust list
```

This writes `~/.mvm/trusted-publishers/<key_id>.pub`. No network
access required — the key file itself has to reach the host by some
other channel (sneakernet, artifact mirror, USB).

### 2. Transfer the bundle

Sneakernet, internal artifact mirror, signed USB, scp through a jump
host — whatever your environment allows.

### 3. Verify before installing

```bash
mvmctl bundle fetch ./my-app.mvmpkg
```

`bundle fetch` accepts a local path (or an `https://` URL) and, for a
local path, does no network I/O at all: it checks the manifest
signature against the enrolled publisher's `key_id` in the local trust
store, then re-verifies every artifact's SHA-256, and reports the
parsed manifest. It rejects an unknown `key_id`, a tampered manifest,
or a tampered artifact before anything is installed.

### 4. Install and run

```bash
mvmctl bundle install ./my-app.mvmpkg
mvmctl manifest ls                        # find the installed slot (keyed by bundle sha256)
mvmctl machine run --manifest <bundle-sha256>
```

`bundle install` re-runs the same verification as `fetch`, then
atomically extracts the archive into `~/.mvm/bundles/<bundle_sha256>/`.

The bundle trust model above — a local `key_id`-pinned Ed25519 trust
store — is self-contained and carries no revocation list of its own.

## Provisioning the builder VM

A `--flake` source still needs the builder VM's Nix toolchain, which
ships as its own release artifact (the "builder pack") under a
separate cosign/OIDC-based keyless trust model. That model does
consult a [revocation list](verify-release#recall-revocation-list) —
mvmctl caches it under `~/.mvm/cache/revocations/`, valid for 24 hours
before refresh and tolerated up to 7 days stale when the network is
unavailable; a 404 on the upstream URL is treated as "no recalls
today," not an error.

On a connected host, fetch and verify the builder pack:

```bash
mvmctl pack download builder    # fetch + verify, don't activate
mvmctl pack update builder      # fetch + verify + activate
```

Carrying the resulting cache into a fully air-gapped host isn't a wired
CLI flow today. If your source is `--flake`, that means the builder
pack currently has to be fetched from a host that can reach the
network. Sources that don't need the builder VM at all — an OCI
`--image`, or a sealed `.mvmpkg` bundle as above — remain fully
air-gap-friendly once transferred.

## Failure modes

`mvmctl bundle fetch` / `mvmctl bundle install` fail closed. The most
common errors and what they mean:

| Error wording | Cause | Fix |
|--------------|-------|-----|
| `trust store has no entry for key_id <id>` | The bundle's publisher key isn't enrolled on this host | `mvmctl trust add <pubkey>` for the correct publisher, or double-check you transferred the right key file |
| `signature does not verify under trusted key <id>` | The manifest was tampered with after signing, or paired with the wrong signature | Re-export the bundle from the publisher; never hand-edit a `.mvmpkg` archive |
| `artifact <name> sha256 mismatch` | Artifact bytes were tampered with or corrupted in transit | Re-transfer the bundle; check the transit medium |
| `manifest references artifact <name> but it is missing from the archive` | Truncated or corrupted archive | Re-transfer the full `.mvmpkg` file |
| `archive entry path is unsafe: ...` | Malicious or malformed archive contents | Get a fresh bundle from a trusted publisher |