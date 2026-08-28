---
title: "Capturing a Project Environment"
description: Inspect a Linux project, resolve its environment, and render a reviewable MVM definition.
---

# Capturing a Project Environment

`mvmctl capture` inspects a project directory and the host environment required
to build and run it, then produces a reviewable MVM definition. It is
**project-scoped capture**, not lossless machine cloning.

## What it does

- Scans the project directory for manifests, lockfiles, and known
  configuration files.
- Records platform facts such as CPU architecture and Linux distribution.
- On Linux, resolves observed executables to native package ownership where
  possible (Debian/Ubuntu via `dpkg`, with RPM/Pacman/APK stubs).
- Looks up executables with no native package match in the local
  `nix-index` database and resolves matches into the canonical workload.
- Performs safe, read-only ELF metadata inspection on observed executables:
  architecture, interpreter (`PT_INTERP`), declared shared libraries
  (`DT_NEEDED`), and GNU build-id (`PT_NOTE`).
- Records explicit user-supplied commands for later tracing and verification.
- On Linux, traces explicit commands with a bounded `strace` adapter and
  records observed file opens, network connects, and executed programs.
- Emits a versioned, evidence-oriented **capture report**.
- Resolves the report into the existing canonical MVM IR.
- Renders `flake.nix`, `launch.json`, and `workload.json` through the same
  Nix renderer used by the SDK.
- Optionally builds the rendered flake inside the Linux builder VM and emits
  a verification-status report.

## What it does not do

- Run discovered executables, scripts, or installation hooks automatically.
- Copy databases, caches, logs, or other mutable application state into Nix
  derivations.
- Guess `nixpkgs` attributes from native package names without evidence.
- Capture secret values.
- Reproduce the entire source machine.
- Boot a microVM and replay the verification command inside the guest yet
  (the rendered flake is built in the builder VM; guest command replay is the
  next hardening slice).

## CLI workflow

```bash
# Capture the project environment.
mvmctl capture project ./my-app \
  --run "cargo test" \
  --output capture.json

# Resolve the report into canonical MVM IR.
mvmctl capture resolve capture.json \
  --output environment.json

# Render Nix artifacts and record a verification command.
mvmctl capture verify environment.json \
  --manifest-dir ./my-app \
  --run "cargo test" \
  --out-dir ./mvm-verify

# (Optional) Build the rendered flake in the Linux builder VM.
mvmctl capture verify environment.json \
  --manifest-dir ./my-app \
  --run "cargo test" \
  --out-dir ./mvm-verify \
  --exec-in-builder-vm

# (Optional) Boot a microVM in the builder VM and replay the command inside the guest.
mvmctl capture verify environment.json \
  --manifest-dir ./my-app \
  --run "cargo test" \
  --out-dir ./mvm-verify \
  --boot-and-replay
```

The `--run` arguments are explicit user-supplied commands. They are recorded
for tracing and verification; they are not executed during capture.

## Verification status

`mvmctl capture verify` writes `verification.json` to `--out-dir`. Each `--run`
command produces a `VerificationRecord` with one of the following statuses:

- `recorded` — command captured but not executed (default).
- `built` — rendered flake built successfully inside the builder VM
  (`--exec-in-builder-vm`).
- `replayed` — command successfully replayed inside a clean microVM
  (`--boot-and-replay`).
- `failed` — build or replay failed, with `exit_code`, `stdout`, and `stderr`
  preserved for review.

## Security and privacy

- The collector is read-only by default and does not require root.
- Secret-shaped files such as `.env` are classified as sensitive. Their
  content hashes and paths are redacted from the capture report.
- Secret values are represented by name and requirement only in the canonical
  IR, using `SecretRef`. They are never copied into generated Nix, the Nix
  store, or test snapshots.
- Filesystem traversal is bounded by configurable limits on file count,
  depth, individual file size, total bytes inspected, and elapsed time.
- Symlinks are skipped to prevent traversal escapes.
- Discovered executables are inspected as bytes; they are never executed
  automatically and `ldd` is never invoked.

## Deterministic versus heuristic resolution

Resolution is ordered:

1. Existing MVM or Nix declarations.
2. Project manifests and lockfiles.
3. Exact native package ownership of observed files.
4. Local `nix-index` matches for observed executables.
5. Safe ELF dependency metadata.
6. Explicit user overrides.
7. Unresolved result.

If no defensible mapping exists, the item stays explicitly unresolved with a
`needs_review` flag.

## Supported platforms

- Linux: full manifest, executable, package, `nix-index`, and dynamic-tracing
  collection.
- macOS / Windows: manifest scan, platform facts, and Nix rendering; native
  package, executable metadata, and dynamic tracing require a Linux host or
  the builder VM.

## Known limitations

- Native package ownership is implemented for Debian/Ubuntu (`dpkg`); RPM,
  Pacman, and APK providers are stubs that report no match.
- Native package names are not translated into `nixpkgs` attributes unless a
  `nix-index` lookup succeeds.
- Boot-and-replay verification can boot a microVM inside the builder VM and
  replay the command as the guest entrypoint, but it requires a builder VM
  with working nested microVM support and has not been validated on every
  backend.
