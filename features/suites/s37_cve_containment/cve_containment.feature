Feature: s37_cve_containment

  Witnessed CVE-2026-80521 containment at the DestructiveLabOnly risk ceiling.
  It never runs in CI, and its full rationale, pins, and run instructions live
  in this suite's README.

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
