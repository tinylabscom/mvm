---
kind: design
issue: https://github.com/tinylabscom/mvm/issues/4443
status: accepted
---

# Opt-in Firecracker lifecycle service prototype

Historical design: the unpublished prototype was retired under #4839. The
crate, executable and commands below no longer exist. This preserves the
original design and its limitations, not current lifecycle or deployment
guidance; see [the retirement decision](../contracts/build-dependency-decisions.md#firecracker-lifecycle-prototype-retirement).

Backing: preview
Validation: targeted

The maintainer approved an opt-in prototype: validate security first, then
measure startup before considering a default change. Approval covers code and
local validation, not installation, sudoers changes, remote access, source
transfer, release publication, or permanent host configuration.

The issue owns progress. This plan specifies the prototype's boundaries.

## Scope and authority

Build a dedicated `mvm-fc-lifecycle` crate and executable, separate from the
user-owned host agent. The executable serves only when explicitly opted in
with `serve --experimental`, and production serving requires Linux and root.
Existing launches and cleanup paths remain unchanged by default.

The first prototype registers already-created Firecracker processes through
a root-only operation. It does not spawn VMs, execute commands, build images,
change cgroups, install itself, or elevate a client. Root registration is an
explicit trusted-operator/launcher action, not an unprivileged assertion that
a PID belongs to the caller. Automatic trusted-spawn integration is a later
gate, not a property this prototype may claim.

Stop and query requests name only an opaque registration ID. They do not
provide a PID, executable, arbitrary signal, scope, or cleanup pathname.
Credentials come from the Unix socket's kernel peer credentials, never from
request JSON. Root may administer registrations; other peers must match the
registered owner UID. A capability from another UID grants no authority.

Registration captures original PID/start time, trusted installed executable,
state-directory identity and owner, API-socket identity and command-line
binding. The root registry is authoritative; user-owned claim files are only
evidence/lookup keys. Unknown or changed evidence refuses signaling.

Retain the original pidfd through normal registration, validation and signal
delivery, together with handles pinning filesystem identity evidence. After
restart those handles are gone: persisted inode numbers alone do not prove
that user-controlled objects were not replaced and recycled. The prototype
therefore preserves recovered records as stale and refuses signaling until
explicit trusted-operator re-registration; transparent restart acceptance is
not part of this slice.

Path validation and signal delivery are not one atomic filesystem operation.
Detected binding changes refuse the operation; signal delivery uses the
retained original pidfd rather than resolving a replacement process by PID.
Do not claim rejection of every mutation occurring after the final check.
No numeric-PID fallback or user-writable executable may gain root
authority. Existing signed-plan admission, audit, resource grants, verified
boot artifacts, no guest NIC/TAP/TUN, and secret handling stay unchanged.

## Trusted deployment boundary

Use fixed prototype locations:

- Service executable: `/usr/libexec/mvm/mvm-fc-lifecycle`
- Socket: `/run/mvm/fc-lifecycle.sock`
- Registry: `/var/lib/mvm/fc-lifecycle`
- Trusted Firecracker executable: `/usr/bin/firecracker`

Serving validates root ownership, non-writable ancestor directories, safe
object types and descriptor/inode bindings. Reject environment and PATH
overrides for privileged executable or registry discovery. Do not install
these locations from a test or ordinary client command.

Transport is bounded local Unix IPC with strict typed requests, unknown-field
rejection, bounded framing and connection deadlines. Credential-aware intake,
per-UID concurrency bounds and reserved administrative capacity must prevent
one slow local peer from occupying all service handlers. Do not log capability
IDs, raw request bodies, or workload secrets. Client-side server identity and
socket-path checks prevent a substituted unprivileged service.

Native tests may use injected process/credential/storage adapters. Those
adapters must not create a production trust bypass. Privileged Linux tests are
explicitly gated and must not run on the native macOS host.

## Step-by-step tasks

1. **Protocol and authorization core.** Define versioned register, stop and
   query operations; opaque random IDs; peer-derived authorization; a registry
   and a mockable identity-stable process interface.
   VALIDATE: `cargo test -p mvm-fc-lifecycle --lib`.
2. **Identity and root storage.** Implement retained pidfds, exact identity
   revalidation, safe root-owned persistent records and restart refusal.
   Include negative tests for PID reuse, missing evidence, changed executable,
   socket/directory replacement, corrupted records and unsupported pidfds.
   VALIDATE: `cargo test -p mvm-fc-lifecycle --lib`.
3. **Opt-in transport and executable.** Implement fixed-path Linux/root
   serving and a bounded client, with disabled-by-default command behavior.
   Test malformed frames, unknown fields, UID/capability theft, client/server
   impersonation, absent service and non-root registration refusal.
   VALIDATE: `cargo test -p mvm-fc-lifecycle`.
4. **Review and deployment guidance.** Document the explicit trust boundary,
   manual registration limitation and operator prerequisites. No packaging or
   installer activation is part of this prototype.
   VALIDATE: `cargo clippy -p mvm-fc-lifecycle --all-targets -- -D warnings`.
5. **Assembly and security review.** Obtain fresh review before publication or
   default integration.
   VALIDATE: `cargo fmt --all -- --check` and `git diff --check`.

## Acceptance gates not supplied by native tests

The prototype is not production cleanup support until a trusted spawn boundary
creates registrations atomically, real privileged Linux/systemd and restart
tests pass, and packaging/install ownership has been reviewed.

Only after security validation may performance be compared on the same
release candidate, signed runtime and host. Keep the original invocation
clock, mandatory authentication, two warmups plus twenty measured attempts,
and strict per-sample startup <300 ms. First service startup, restart and
accumulated registry state need separate measurements. No source-cache
substitution, hidden durability cost, or relaxed threshold is permitted.
