You are a senior systems integrator and Rust infrastructure engineer.

You are working in the existing repository:
https://github.com/tinylabscom/mvm

Assume the following have ALREADY been implemented:

1) Nix-flake-based guest and builder microVM builds
2) Multi-tenant Firecracker lifecycle with ephemeral build microVMs
3) Security hardening:
   - jailer
   - cgroup v2
   - seccomp
   - secrets handling
   - audit logging
4) Snapshot-based sleep / warm / wake
5) Reconcile-based node agent for fleet control
6) Agent-workload worker lifecycle hooks and sleep heuristics

Your task is to perform a FINAL INTEGRATION AND COHERENCE PASS.

This is NOT a feature task.
DO NOT add new concepts, commands, or subsystems.
Only refactor, align, simplify, and correct.

Do not explain. Make concrete code changes.

----------------------------------------------------------------
PRIMARY GOALS
----------------------------------------------------------------

1) System coherence
- The codebase must read as ONE designed system
- Naming, state machines, and control flow must be consistent
- No duplicated logic across lifecycle / agent / sleep paths

2) Correctness
- State transitions must be valid and enforced
- Reconcile logic must not fight manual CLI commands
- Sleep / warm / wake must not race lifecycle actions

3) Operator ergonomics
- CLI behavior must be predictable and unsurprising
- Error messages must be actionable
- Logs must tell a clear story of what happened and why

----------------------------------------------------------------
INTEGRATION TASKS (DO ALL)
----------------------------------------------------------------

A) Normalize tenant state model

- Review TenantState, BuildRevision, SnapshotMetadata, and sleep-related fields
- Ensure:
  - Exactly one source of truth for:
      - running / warm / sleeping / stopped
      - pinned / critical flags
  - Clear allowed transitions:
      stopped → running
      running → warm
      warm → sleeping
      sleeping → wake → running
      running → stopped
  - Invalid transitions fail loudly

- Centralize state transition logic in ONE module
  (e.g., src/tenant/state.rs)
- All CLI commands and agent reconcile must call into this module

----------------------------------------------------------------

B) Unify lifecycle entry points

- Identify duplicated lifecycle paths:
  - CLI commands
  - reconcile agent
  - sleep heuristics
- Refactor so that:
  - There is ONE internal API for:
      start
      stop
      sleep
      warm
      wake
      destroy
  - CLI and agent both call these APIs
  - No direct Firecracker manipulation outside these APIs

----------------------------------------------------------------

C) Resolve reconcile vs manual control conflicts

- Define clear precedence rules:
  - Manual CLI commands override reconcile temporarily
  - Reconcile respects:
      - pinned tenants
      - critical tenants
      - manual “hold” windows
- Implement:
  - a short-lived “manual override” flag in TenantState
  - automatic expiration of override

----------------------------------------------------------------

D) Align snapshot semantics

- Ensure snapshot creation/restoration logic is:
  - not duplicated
  - invoked only through lifecycle APIs
- Ensure:
  - snapshot metadata is always recorded
  - snapshot reuse logic is centralized
  - base vs delta snapshots are consistently named and referenced

----------------------------------------------------------------

E) Networking and resource cleanup guarantees

- Verify:
  - tap devices are always removed on destroy
  - cgroups are always cleaned on stop/sleep/destroy
  - jailer directories are cleaned appropriately
- Add defensive cleanup in failure paths

----------------------------------------------------------------

F) CLI consistency pass

- Review all CLI commands:
  mvm tenant *
  mvm agent *
  mvm net *
  mvm node *

- Ensure:
  - consistent naming and verbs
  - consistent output format
  - consistent exit codes
- Add:
  - `--json` output option where appropriate
  - concise human-readable defaults

----------------------------------------------------------------

G) Logging and audit alignment

- Ensure lifecycle events emit:
  - structured logs
  - audit entries
- Ensure:
  - logs explain *why* an action occurred
    (manual vs reconcile vs sleep policy)
  - audit log remains append-only and minimal

----------------------------------------------------------------

H) Dev mode protection

- Ensure dev mode:
  - does not use tenant lifecycle code
  - cannot accidentally sleep or snapshot
  - is clearly isolated in code and CLI
- Add guardrails if necessary

----------------------------------------------------------------

I) Dead code and complexity reduction

- Remove:
  - unused helpers
  - partially duplicated modules
  - obsolete code paths from earlier prompts
- Simplify overly complex logic if equivalent behavior can be preserved

----------------------------------------------------------------
FINAL VALIDATION
----------------------------------------------------------------

- Code must compile
- Commands must exist and run
- State transitions must be deterministic
- No TODOs or commented-out code
- README must reflect the final, unified mental model

----------------------------------------------------------------
IMPLEMENT NOW
----------------------------------------------------------------

- Make minimal, surgical changes
- Prefer deletion and consolidation over expansion
- Leave the system cleaner than you found it
