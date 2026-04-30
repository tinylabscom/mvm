# Plan 28 — W4: guest-agent attack surface

> Status: ✅ shipped — 2026-04-30
> Owner: Ari
> Parent: `specs/plans/25-microvm-hardening.md` §W4
> ADR: `specs/adrs/002-microvm-security-posture.md`
> Estimated effort: 3-5 days
>
> ### Shipped artifacts
>
> - **W4.1** `#[serde(deny_unknown_fields)]` on `GuestRequest`,
>   `GuestResponse`, `HostBoundRequest`, `HostBoundResponse`, `FsChange`
>   (`crates/mvm-guest/src/vsock.rs`), and on `AuthenticatedFrame`,
>   `SessionHello`, `SessionHelloAck`
>   (`crates/mvm-core/src/policy/security.rs`). Six regression tests
>   in `vsock::tests` cover the unknown-field rejection paths
>   (`test_*_rejects_unknown_field*`).
> - **W4.2** Cargo-fuzz harness at `crates/mvm-guest/fuzz/` with two
>   targets — `fuzz_guest_request` and `fuzz_authenticated_frame`.
>   Excluded from the workspace via `Cargo.toml::workspace.exclude`
>   (libfuzzer-sys only links under `cargo fuzz run`). Justfile recipes
>   `fuzz-guest-request` / `fuzz-authenticated-frame` drive the targets.
> - **W4.3** `scripts/check-prod-agent-no-exec.sh` builds the agent
>   without `dev-shell` and asserts the demangled symbol
>   `mvm_guest_agent::do_exec` is absent. Runs as the
>   `prod-agent-no-exec` job in `.github/workflows/ci.yml` and as
>   `just security-gate-prod-agent` locally.
> - **W4.4** Port-forward TCP target pinned to a `PORT_FORWARD_TCP_HOST`
>   constant (`127.0.0.1`) in `crates/mvm-guest/src/bin/mvm-guest-agent.rs`,
>   with a regression test (`test_port_forward_target_is_loopback`)
>   asserting the constant parses as a loopback address.
> - **W4.5** Guest agent now launches as uid 901 (`mvm-agent`) via
>   `setpriv --reuid=901 --regid=901 --clear-groups --groups=901,900
>   --bounding-set=-all --no-new-privs --inh-caps=-all`. The agent's
>   `/etc/mvm/{integrations,probes}.d/` directories are chgrp'd to the
>   shared service group so the dropped-privilege agent can still read
>   drop-in configs.

## Why

The `mvm-guest-agent` binary listens on vsock port 52 and is the
*only* host→guest control surface in production microVMs. It runs
as PID 1 = uid 0 today, parses every host message via
`serde_json::from_slice` with no schema strictness, and is gated
from arbitrary command execution only by a single Cargo feature
flag (`dev-shell`). One bug in the deser path or one accidental
feature-flag flip would give the host (or whoever the host trusts
with vsock) full root in every running guest.

W4 makes that surface defensible at the language and CI level.

## Threat shape addressed

- A malformed vsock frame (whether crafted by a malicious host or
  a misbehaving piece of infrastructure mvmctl trusts) cannot
  panic, OOM, or remote-code-execute the agent.
- A future refactor that accidentally enables `dev-shell` for
  production builds is caught in CI before merge.
- A `StartPortForward` request can't trick the agent into
  exposing a guest service on the guest's external network.
- A bug in the agent (uid 0 today) cannot escalate beyond what
  the agent's own user can do — the agent runs as a non-root
  user.

## Scope

In: `crates/mvm-guest/`. New binary (`mvm-seccomp-apply`, shared
with W2.4 — implement once, used by both). New fuzz target. Two
CI workflow steps. Init changes to start the agent under setpriv.

Out: protocol redesign. The current `GuestRequest`/`GuestResponse`
shapes stay. The audit is *defensive* — we harden what's there,
we don't redo the wire format.

## Sub-items

### W4.1 — `#[serde(deny_unknown_fields)]` + size/depth caps

**What**

`crates/mvm-guest/src/vsock.rs::GuestRequest` is currently:

```rust
#[derive(Deserialize, ...)]
pub enum GuestRequest {
    Ping,
    Exec { command: String, ... },
    ...
}
```

Add `#[serde(deny_unknown_fields)]` to the enum and to every
`struct` variant. Today an attacker can stuff arbitrary fields
into a request and serde silently ignores them; with strict mode,
unknown fields produce a deser error and the agent rejects the
frame.

`MAX_FRAME_SIZE` is checked at the framing layer (good); audit
its value. Today: pinpoint exact constant + decide if 1 MB is
right for the largest legitimate request (snapshot CheckpointInt
manifests can be biggish; let's profile). Default to a more
restrictive value — 256 KB — and bump for specific request types
that need it.

**Files**

- `crates/mvm-guest/src/vsock.rs`:
  - Add `#[serde(deny_unknown_fields)]` to every Deserialize'd
    type (`GuestRequest`, `GuestResponse`, all variant structs).
  - Audit `MAX_FRAME_SIZE` against the largest known request.

**Tests**

- A unit test sends a JSON frame with an unknown field, asserts
  the agent responds with an error (not silent acceptance).
- A unit test sends an oversize frame, asserts the agent reads
  the length, refuses to read the body, sends an error, closes
  the connection.

### W4.2 — `cargo-fuzz` target for the vsock frame parser

**What**

New crate at `crates/mvm-guest/fuzz/` driven by `cargo-fuzz`.
Fuzz target: `parse_request_frame` — takes raw bytes, attempts
to parse them as the length-prefixed framing format, then runs
serde_json on the body. Catches:

- Length-prefix integer overflows.
- Truncated bodies.
- Nested-JSON depth bombs (`{"a":{"a":...}}` deeply).
- Unicode escape edge cases.
- Numeric overflows in size/timeout fields.

Run for 1 hour on each PR via a CI job. Failure (panic, ASan
finding, deser-error-with-side-effect) blocks merge. Corpus
committed to `crates/mvm-guest/fuzz/corpus/parse_request_frame/`
so subsequent runs start warm.

**Files**

- `crates/mvm-guest/fuzz/Cargo.toml`: new fuzz crate (won't be
  in the workspace's default members; `--workspace` opts in).
- `crates/mvm-guest/fuzz/fuzz_targets/parse_request_frame.rs`:
  ~30 lines.
- `.github/workflows/security.yml` (added in W6.3): fuzz step.

**Tests**

The fuzzer *is* the test. Initial corpus seeded with 5-10 known-
good frames + a handful of malformed ones we want to confirm
the parser rejects without panicking.

### W4.3 — CI gate: production binary doesn't contain `do_exec`

**What**

The compile-time `#[cfg(feature = "dev-shell")]` gate around
`do_exec` and the `Exec` request handler is the project's
load-bearing security claim. Today nothing prevents a future
contributor from enabling the feature for a production build,
either by accident (e.g., `default-features = ["dev-shell"]` in a
new Cargo.toml) or by a typo in a CI matrix.

CI gate:

1. Build `mvm-guest-agent` with the production feature set
   (`--no-default-features --features production`, or whatever
   the canonical prod build is — verify and document).
2. Run `nm` on the binary.
3. `grep -q ' do_exec\| exec_handler' nm-output && exit 1`.

The gate becomes part of `security.yml` (W6.3).

**Files**

- `.github/workflows/security.yml`: new step.
- `crates/mvm-guest/Cargo.toml`: ensure the feature names are
  stable + documented.

**Tests**

- CI is the test. Locally, `xtask security-check` runs the same
  grep so contributors can verify before pushing.

### W4.4 — `StartPortForward` bind-address audit

**What**

`crates/mvm-guest/src/bin/mvm-guest-agent.rs::StartPortForward`
binds a TCP listener inside the guest and pipes traffic from a
vsock channel to it. Audit:

- Confirm bind address is `127.0.0.1` only, never `0.0.0.0` or a
  guest-routable interface.
- If we want guest-LAN-accessible ports (for guest-to-guest
  communication via the host's tap network), that's a separate
  feature with its own threat model — for now, deny it.

Add an explicit unit test using `socket2` to introspect the
listener's local address after `StartPortForward` is invoked, and
assert it's `127.0.0.1`.

**Files**

- `crates/mvm-guest/src/bin/mvm-guest-agent.rs::handle_request`:
  audit the `StartPortForward` arm. If it currently uses
  `0.0.0.0`, change to `127.0.0.1`. If unclear, add an explicit
  bind address.
- `crates/mvm-guest/tests/`: new integration test.

**Tests**

- Unit test: send a `StartPortForward` request, then on the
  guest side bind a peer that asserts the agent's listener is
  on `127.0.0.1:<port>`.

### W4.5 — Agent runs as uid 901, not uid 0

**What**

Init currently spawns `mvm-guest-agent` directly under PID 1
(uid 0). The agent doesn't need root for any of its current
operations: vsock listen is unprivileged (vsock ports aren't
gated by the privileged-port rule), `/dev/console` writes can be
done as a member of the `tty` group, and probe exec runs in a
subprocess where setpriv would have already dropped privs.

Plan:

1. Add `mvm-agent` user (uid 901, gid 901) to the rootfs's
   passwd/group baseline. Already in the design doc; W2.1's
   per-service uid path makes this trivially additive.
2. `chown mvm-agent:tty /dev/console` happens early in init
   (before the agent block in section 9).
3. Section 9's agent launch wraps with `setpriv --reuid=901
   --regid=901 --bounding-set=-all --no-new-privs --
   /run/current-system/sw/bin/mvm-guest-agent`.

The agent gains no privilege from being root. A bug in its
deser path now yields uid 901, not uid 0. Combined with the
read-only `/etc/passwd` from W2.2, the agent can't even
escalate by editing the user database.

**Files**

- `nix/minimal-init/lib/04-etc-and-users.sh.in`: add the
  `mvm-agent` user.
- `nix/minimal-init/lib/07-services-and-agent.sh.in`: wrap
  the agent launch with setpriv.

**Tests**

- Boot regression: `getent passwd mvm-agent` returns uid 901.
- `pgrep -u mvm-agent mvm-guest-agent` matches.
- The agent still answers Ping over vsock with the new uid.

## Order of operations

W4.1 and W4.4 are surgical edits with regression tests; do them
first. W4.3 is a 5-line CI step. W4.5 depends on W2.1's user-
provisioning machinery being in place. W4.2 is the largest piece
and probably its own PR.

Suggested PR sequence:

1. PR-A: W4.1 + W4.3 + W4.4 (deser hardening + CI gate + bind
   audit). Small, clear-cut.
2. PR-B: W4.5 (agent under setpriv) — depends on W2.1 having
   landed.
3. PR-C: W4.2 (cargo-fuzz target + corpus). Independent of the
   others; can land any time.

## CI gates added by this plan

- `cargo-fuzz` 1h run per PR (W4.2).
- `nm | grep do_exec` symbol check on production build (W4.3).
- Bind-address regression test (W4.4).
- Agent uid 901 boot regression test (W4.5).

## Rollback shape

- W4.1 (`deny_unknown_fields`): if a future protocol revision
  adds optional fields and a forwards-compat issue arises,
  remove the attribute on the affected variant only; document
  the loosened invariant in the variant's doc comment.
- W4.2: fuzz can be marked `[no-merge]` advisory if it's too
  noisy at first; treat the corpus as the truth and let real
  failures gate.
- W4.3: a single gate; trivially reversible if it produces
  false positives (e.g., `do_exec` substring matches a
  third-party crate's symbol — unlikely, but adjust the regex).
- W4.4: a single bind address; trivially reversible.
- W4.5: a `MVM_AGENT_AS_ROOT=1` env override on the launch
  command, defaulting off. Useful only for debugging.

## Reversal cost

W4.1 / W4.3 / W4.4 / W4.5: low. Each is a localized change.

W4.2: medium. Fuzzing infrastructure has gravity (corpus growth,
CI time budget) but reversing means deleting the workflow step
and the crate. No load-bearing API.

## Acceptance criteria

W4 is done when:

1. ✅ The four units listed under "tests" all pass.
2. ✅ The fuzzer has run for 24h on a developer's machine
   without producing a crash on the seed corpus.
3. ✅ A test PR that *adds* `do_exec` to the production build
   is rejected by the CI gate.
4. ✅ `pgrep -u mvm-agent mvm-guest-agent` returns a hit on a
   booted production microVM.
5. ✅ Plan 25 §W4 checkboxes flipped.
