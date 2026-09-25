Feature: s37_cve_containment

  Witnessed CVE-2026-80521 containment at the DestructiveLabOnly risk ceiling.
  It never runs in CI, and its full rationale, pins, and run instructions live
  in this suite's README.

  The victim's boot mode is selected by the suite's pins.toml
  kernel.vmlinux_sha256 pin:

  * Pin empty — the victim boots through admission (`mvmctl machine run`) on
    MVM's own workload kernel. The PoC does not target that kernel, so the
    guest canary is a candidate observation only.
  * Pin set — the victim boots the pinned, digest-verified target kernel
    through the low-level Firecracker driver, NIC-less, agentless, and outside
    admission (that is what the destructive-lab ceiling fences). There the
    egress assertion rests on the device model — no NIC, no wired egress
    channel — while the audit classification still runs; the audit-chain,
    host-surface, sibling-digest, and teardown assertions are host-side and
    bind both modes identically; and the guest canary becomes load-bearing:
    a boot of the exact target kernel without a compromise report fails the
    scenario, because a witnessed non-compromise is a failed experiment.

  @live @firecracker @destructive_lab_only
  Scenario: A public container-escape exploit inside a sealed guest crosses no boundary
    Given the host surface is recorded
    And a bystander sibling guest is booted and its rootfs digest recorded
    And the CVE-2026-80521 exploit is staged from its pinned source
    When a sealed victim guest runs the staged exploit
    Then the guest-side compromise report is recorded as a candidate observation
    And no outbound connection was admitted from the victim guest
    And the audit chain verifies intact
    And the host surface is unchanged
    And the bystander sibling guest's rootfs digest is unchanged
    And both guests are torn down and leave no residue
