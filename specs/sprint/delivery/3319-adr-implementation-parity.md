# ADR implementation claims match the shipped architecture

Issue #3319; items A2.6 and A2.7 of
`specs/plans/2026-09-15-the-big-cleanup.md`.

Status: validation complete; ready for merge-queue delivery.

ADR-038 now distinguishes the one part that shipped — IPv6 support in the
workload kernel — from the proposed L3 admission, allocation, guest setup and
forwarding design. Its header records that ADR-042 superseded that transport
premise and that the current tree refuses the retired raw-packet mode.

ADR-025 keeps the security decision but corrects its rationale. Production
workloads do not stay on virtio-net or cross a network bridge; they use the
single flow-aware vsock seam where the host endpoint admits, meters and audits
connections. The implemented page sharing is the inherent copy-on-write
relationship within a fork family. Active same-page merging and a policy gate
for it do not exist, so the same-family rule is explicitly a constraint on any
future merging mechanism.

ADR-026 remains Proposed. It now separates the shipped `--no-new-privs`
boundary from the target-state image guarantee and explicitly defers the
build-time no-setuid-root scan with the runtime-euid witness. ADR-023 already
described substitution through the live `NetworkFlow` path and required no
change.

## Evidence checked

- the execution-plan network modes are only `None` and `HostVsockProxy`;
- `raw_ip_stack` is accepted only as a legacy input that fails with a migration
  error, while the single-network-path gate rejects retired L3 symbols;
- guest netinit records IPv6 deny ranges as skipped rather than configuring an
  IPv6 interface;
- the workload kernel enables `CONFIG_IPV6` while keeping the IPsec/XFRM family
  disabled;
- no active same-page-merging implementation or merge-policy gate exists;
- no build-time rootfs no-setuid scan exists in `xtask` or the security
  workflow.

## Validation

- `cargo fmt --all --check`
- `cargo run -q -p xtask -- check-all` — all 74 policy gates passed,
  including ADR coverage, witness citations, document links and claims, sprint
  append-only discipline, and declared-backing checks.

The pull request's required CI lanes provide the full workspace compile, test,
Clippy and platform coverage before merge-queue admission.
