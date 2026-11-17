# mvm-policy

`mvm-policy` is the shared authored workload-policy resolution library for
MVM clients and host admission. It parses the policy files a user authors,
resolves layered sources into one effective policy, and selects the launch
policy for a project. It never grants a running workload any effect by
itself: composition can only narrow what the surrounding authority allows.

## What it provides

- Parsing for authored policy bodies: profiles, groups, and allow-host rules.
- Source resolution across the policy layers, with capture of every layer
  origin so a committed generation can be explained and reproduced.
- Merge and composition of layered rules into a single resolved policy,
  with per-layer summaries for diagnostics.
- Launch-policy selection that binds a resolved project policy to the
  committed local project generation used for admission.
- A `schema` feature that derives JSON Schema for the authored file shapes.

## Who uses it

`mvm-client` consumes these rules to activate a committed project generation
and to show the user which sources produced the effective policy. Host-side
admission uses the same resolution rules without depending on client launch
orchestration, so the CLI, the host library, and the SDKs all see one
policy semantics.

## Boundaries

This library does not commit a generation, sign a plan, or talk to a
hypervisor. Committing a generation and enforcing it at launch are owned by
the caller with the matching authority.
