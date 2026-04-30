# Plan 25 — microVM hardening: from "soft" to "load-bearing"

> Status: in progress
> Owner: Ari
> Started: 2026-04-30

## Why

Today the project's stated security claim — "no SSH in microVMs ever, vsock
only" — is true but partial. The compile-time `dev-shell` feature gate is
real, but every other layer underneath it is "default-off": no seccomp, no
per-service uid, no verified boot, the host-side proxy socket is world-
traversable, the dev image download is HTTPS-only, the guest agent runs as
uid 0 with no fuzzing of its deserializer. The project must be able to
state, with technical receipts, what an untrusted guest can and cannot do.
This plan turns each soft layer into a hard one.

ADR-002 (`specs/adrs/002-microvm-security-posture.md`) captures the
architectural decisions; this plan is the execution sequence.

## Threat model

We protect against three adversaries, in order of priority:

1. **A malicious guest workload**. Code running inside a microVM must not
   be able to (a) read the host filesystem outside the explicit shares,
   (b) talk to the host network, (c) escape the hypervisor, (d) read
   secrets from a sibling service in the same VM, (e) tamper with the
   guest agent or the rootfs's baked closure.
2. **A same-host hostile process**. Another local user, or another
   process running as `auser`, must not be able to talk to the dev VM's
   guest agent, read its console log, write to its rootfs cache, or
   tamper with launchd plists/GC roots.
3. **A compromised supply chain**. A malicious nixpkgs commit, a
   compromised GitHub account hosting the prebuilt dev image, or a
   typo-squatted Cargo dep, must not silently land code in a microVM
   without a verifiable signature failure.

Out of scope for this plan: a fully malicious *host* (mvmctl trusts the
host completely; the host runs the hypervisor, holds private keys, etc.).

## Workstreams

Each item is independently shippable. Numbering is execution order.

### W1 — Cheap defaults that are wrong today (1 day, no architecture changes)

- **W1.1** Default seccomp tier in `crates/mvm-cli/src/commands/vm/up.rs:84`
  changes from `unrestricted` → `standard`. Document each tier's allowed
  syscalls in `crates/mvm-security/src/seccomp.rs`. Add a regression test
  that verifies a microVM started with the default tier cannot call
  `mount(2)` from inside a guest service.

- **W1.2** Vsock proxy Unix socket on the host is created with mode `0700`.
  Patch in `crates/mvm-apple-container/src/macos.rs::start_vsock_proxy_listener`:
  `std::fs::set_permissions(&socket_path, Permissions::from_mode(0o700))`
  immediately after `UnixListener::bind`. Add a unit test asserting the
  bound socket's mode.

- **W1.3** Vsock proxy enforces a port allowlist. Today any 4-byte LE
  port can be tunnelled. Restrict to `{52}` (guest agent) and the
  `PORT_FORWARD_BASE..PORT_FORWARD_BASE+65535` range that
  `start_port_proxy` legitimately uses. Reject everything else with a
  one-line tracing warning. Patch in `crates/mvm-apple-container/src/macos.rs::proxy_accept_loop`.

- **W1.4** Console log + daemon log gain `0600` perms on creation.
  Patch in `crates/mvm-apple-container/src/macos.rs::start_vm` (where
  `console.log` is created via `File::create`) and in
  `crates/mvm-cli/src/commands/env/apple_container.rs` (the truncate
  loop).

- **W1.5** `~/.mvm` and `~/.cache/mvm` are created with mode `0700`
  unconditionally. Today they inherit umask. Add to
  `crates/mvm-core/src/config.rs::ensure_data_dir`/`ensure_cache_dir`.

### W2 — Defense in depth inside the VM (✅ shipped — 2026-04-30)

Detail plan: `specs/plans/26-w2-defense-in-depth.md`. All four sub-items
landed with the dev VM rebuilt, booted, and verified end-to-end.

- **W2.1** Per-service uid, replacing the shared `serviceGroup`.
  `nix/minimal-init/default.nix::mkServiceBlock` already takes a `user`
  parameter; today every service that doesn't specify one falls through
  to `serviceGroup` (uid 900). Generate a unique uid per service
  (1000+sha8(service-name) % 8000), enrol in a service-specific group
  for its secrets, and tighten `/run/mvm-secrets/<service>/*` to mode
  `0400` owned by that uid. The shared `serviceGroup` becomes the
  fallback for legacy callers; new services are isolated.

- **W2.2** `/etc/passwd`, `/etc/group`, `/etc/nsswitch.conf` are made
  immutable after init. We can't `chattr +i` on tmpfs, so instead init
  builds the files in `/run/mvm-etc/`, then `mount --bind -o ro`
  re-mounts them over `/etc/passwd` etc. A compromised guest service
  can't add a uid 0 entry without first defeating the bind-mount.

- **W2.3** Service launches via `runuser --no-pam --user $svcUser
  --pgroup $svcGroup -- env -i $envvars setpriv --reuid $uid --regid
  $gid --clear-groups --bounding-set=-all --no-new-privs $cmd` instead
  of busybox `su`. Drops capabilities, clears env, sets `no_new_privs`.
  busybox doesn't ship `setpriv`/`runuser`; add `pkgs.util-linux` to
  the production guest closure (already in dev image, costs ~1.5MB in
  prod).

- **W2.4** Per-service seccomp filters. `mkServiceBlock` accepts a
  `seccompTier` attribute (default: `standard`); init applies it via
  `setpriv --seccomp-filter=…` or a small rust shim that calls
  `prctl(PR_SET_SECCOMP, …)`. The tier list lives in
  `mvm-security/src/seccomp.rs` (already exists, just wired through).

### W3 — Verified boot (🟡 host-side shipped — 2026-04-30; boot regression pending)

Detail plan: `specs/plans/27-w3-verified-boot.md`. Kernel config,
mkGuest's verity sidecar, both backends' wiring, the dev-VM
exemption, and the security.yml gate are live. The live-boot +
tamper regressions need a Linux/KVM CI lane that doesn't exist
yet — they remain the only outstanding W3 work.

- **W3.1** mkGuest emits a dm-verity sidecar alongside `rootfs.ext4`:
  a `rootfs.verity` Merkle tree and a `rootfs.roothash` text file.
  `make-ext4-fs.nix` doesn't do this directly; we add a small
  `pkgs.runCommand` that runs `veritysetup format` against the ext4
  output. The result is two store paths: the rootfs (read-only) and
  the verity sidecar (also read-only).

- **W3.2** `start_vm` (Apple Container backend) attaches the rootfs
  *and* the verity device, passes the root hash via kernel cmdline as
  `mvm.roothash=<hex>`. Init constructs a dm-verity device on
  `/dev/mapper/rootfs-verified` using the sidecar + cmdline hash,
  and remounts `/` from it. A tampered ext4 fails verity setup; init
  panics; VM doesn't reach userspace.

- **W3.3** The Firecracker backend gets the same treatment via a
  second VirtioBlk device for the verity hash tree. Already
  multi-disk-capable per W2.

- **W3.4** dm-verity is enforced unconditionally for production
  microVMs. The dev VM is exempt (the overlay upper layer makes /nix
  writable, which dm-verity can't accommodate; the tradeoff is
  documented in ADR-002).

### W4 — Guest agent attack surface (✅ shipped — 2026-04-30)

Detail plan: `specs/plans/28-w4-guest-agent-attack-surface.md`. All
five sub-items landed; the workspace builds + tests + clippies clean
and the CI gate against accidental `dev-shell` reintroduction is
wired up.

- **W4.1** Replace `serde_json::from_slice` over the vsock frame with
  a strict-typed deserializer that rejects unknown fields, caps depth,
  caps total frame size to 1MB (already capped at `MAX_FRAME_SIZE`,
  but we audit the constant). Add `#[serde(deny_unknown_fields)]` to
  `GuestRequest`.

- **W4.2** Add a fuzzer for the vsock frame parser. `cargo-fuzz`
  target in `crates/mvm-guest/fuzz/`. Run for 1h on each PR via CI;
  failure blocks merge. Corpus committed to the repo.

- **W4.3** Compile-time gate audit. Add a CI job that builds
  `mvm-guest-agent` with the production feature set, runs `nm` on the
  output binary, and `grep -q exec_handler` — if the symbol is
  present, fail the build. Same for `do_exec`. This catches accidental
  reintroduction of the `dev-shell` feature in production builds.

- **W4.4** `StartPortForward` binds the guest-side TCP listener to
  `127.0.0.1` only, never `0.0.0.0`. Audit
  `crates/mvm-guest/src/bin/mvm-guest-agent.rs` and grep tests for any
  bind-to-anyhost patterns. Add a regression test using `socket2` to
  assert the bind address.

- **W4.5** The guest agent runs as a non-root uid inside the VM
  (`mvm-agent` user, uid 901). It doesn't need root for any of its
  current operations except `/dev/console` write and listening on
  vsock; both can be granted via group membership and `CAP_NET_BIND_SERVICE`-
  free vsock (vsock ports aren't privileged). Init starts the agent
  via `setpriv` like any other service.

### W5 — Supply chain (✅ shipped — 2026-04-30)

Detail plan: `specs/plans/29-w5-supply-chain.md`. All four sub-items
shipped. Hash-verified downloads, `cargo-deny` + `cargo-audit` in CI,
reproducibility double-build, SBOM at release time.

- **W5.1** Pre-built dev image download verifies a SHA-256 hash bundled
  with the mvmctl binary. The release pipeline computes the hash at
  build time and embeds it as a `const` in `mvm-cli`; the download
  function refuses any artifact whose hash doesn't match. Patch in
  `crates/mvm-cli/src/commands/env/apple_container.rs::download_dev_image`.

- **W5.2** `cargo-deny` and `cargo-audit` run in CI. `deny.toml`
  allowlists licenses, blocks duplicate-major-version deps, and pins
  the advisory DB version. New advisories on a transitive dep block
  the next merge. Pre-commit hook runs them locally too.

- **W5.3** The mvmctl binary is reproducibility-checked. CI builds it
  twice on different runners, hashes both outputs, fails on mismatch.
  Catches build-time non-determinism that could mask supply-chain
  injection.

- **W5.4** SBOM emission. `cargo-sbom` produces a CycloneDX file at
  release time; attached to GitHub releases alongside the binary.

### W6 — Documentation and CI gates (✅ shipped — 2026-04-30)

Detail plan: `specs/plans/30-w6-docs-and-ci-gates.md`. ADR-002 +
CLAUDE.md security model + the consolidated `security.yml` workflow
+ live probes in `mvmctl security status` are all live. W3 (verified
boot) is the remaining workstream and its associated lanes will land
alongside it.

- **W6.1** ADR-002 documents the threat model + every decision in
  this plan + the explicit non-goals.

- **W6.2** `CLAUDE.md` gains a "Security model" section linking to
  the ADR. Replaces the current single sentence about vsock-only.

- **W6.3** New CI workflow `security.yml`: runs cargo-deny, cargo-audit,
  the `Exec` symbol grep, the seccomp regression test, the proxy-socket
  perm test, and the verity round-trip test. Blocks merge on failure.

- **W6.4** `mvmctl security status` (the existing command) gets new
  checks: verifies the running daemon's vsock proxy socket is mode
  0700, asserts the dev image's roothash matches, prints the active
  seccomp tier, lists installed CI badges.

## Phasing for incremental ship

W1 ships first as a single PR; everything in W1 is one-line-ish patches
that strictly tighten without risk of regression.

W2-W6 are independent and can land in any order; W3 (verity) is the
biggest and likely benefits from being a sprint of its own.

## Non-goals

- A *malicious host* threat model. mvmctl trusts the host with the
  hypervisor, with the host's nixpkgs config, with the GC roots.
  Defending against a malicious host requires running mvmctl itself
  in a secure enclave; that's a separate project.
- Multi-tenant guests. Today one guest = one workload. If a guest is
  ever shared across users, W2.1's per-service uid isn't enough; you
  also need user namespaces or per-tenant VMs.
- Hardware-backed key attestation. Out of scope for v1; revisit if
  the project ever ships outside the laptop dev model.

## Success criteria

By the end of this plan, the project must be able to make these
claims with technical receipts:

1. *No host-fs access from a guest beyond the explicit shares.* —
   evidence: regression test that verifies `ls /` inside a sandboxed
   guest service shows only the rootfs.
2. *No guest binary can elevate to uid 0.* — evidence: `setpriv
   --no-new-privs` in the launch path, regression test that runs
   `setuid /bin/su` inside a guest service and asserts EPERM.
3. *A tampered rootfs ext4 fails to boot.* — evidence: regression
   test that flips a byte in the rootfs and asserts boot panic.
4. *The guest agent does not contain `do_exec` in production builds.*
   — evidence: CI grep gate.
5. *Vsock framing is fuzzed.* — evidence: cargo-fuzz target with 1h
   CI run, no crashes, corpus committed.
6. *Pre-built dev image is hash-verified.* — evidence: download
   refuses a tampered artifact in a regression test.
7. *Cargo deps are audited on every PR.* — evidence: green
   cargo-audit + cargo-deny in CI.
