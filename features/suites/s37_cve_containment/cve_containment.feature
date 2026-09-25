Feature: s37_cve_containment

  Witnessed CVE-2026-80521 containment at the DestructiveLabOnly risk ceiling.

  CVE-2026-80521 is an AF_UNIX SCM_RIGHTS garbage-collection use-after-free with
  a complete public container-escape proof-of-concept. It is exactly the threat
  class MVM's architecture is built to contain: each workload boots its own
  kernel, has no guest NIC, speaks only authenticated vsock, is default-deny on
  egress, and runs from a dm-verity-sealed rootfs. This suite turns that
  argument into a demonstration — it deliberately detonates the real, public
  exploit inside a sealed guest and asserts, from host evidence only, that the
  guest-kernel compromise crosses no boundary.

  This scenario is the strictest gate in the suite. It carries @live and
  @firecracker (a real KVM boot) plus @destructive_lab_only, whose opt-in
  (MVM_BDD_DESTRUCTIVE_LAB=1) is deliberately separate from MVM_BDD_LIVE so that
  no ordinary live lane — including the merge-queue @ci_live selection — can
  ever reach it. It never runs in CI. Run it only on a throwaway lab host, after
  staging the pinned exploit and the vulnerable kernel per this suite's README.

  The exploit source and the vulnerable kernel are pinned by digest in
  pins.toml and fetched at scenario time into the lab, never vendored into the
  repository. The guest's own compromise report is a candidate observation; the
  assertions derive from host evidence, per the assurance contract. Architectural
  claims this witnesses: MVM-SEC-01 (no host-fs access), MVM-SEC-10 (default-deny
  egress), MVM-SEC-15 (no interactive access to a sealed guest).

  @live @firecracker @destructive_lab_only
  Scenario: A public container-escape exploit inside a sealed guest crosses no boundary
    Given the host surface is recorded
    And a bystander sibling guest is booted and its rootfs digest recorded
    And the CVE-2026-80521 exploit is staged from its pinned source
    When a sealed victim guest runs the exploit through admission
    Then the guest-side compromise report is recorded as a candidate observation
    And no outbound connection was admitted from the victim guest
    And the audit chain verifies intact
    And the host surface is unchanged
    And the bystander sibling guest's rootfs digest is unchanged
    And both guests are torn down and leave no residue
