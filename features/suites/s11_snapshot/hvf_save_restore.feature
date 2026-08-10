Feature: HVF save/restore for checkpoint and fork

  The in-house HVF VMM can freeze a running machine into a checkpoint and bring
  one back — as a same-identity restore or as a fresh forked child. A checkpoint
  is a lineage record that later admissions trust, so the properties that matter
  are not "does it boot" but "what does it refuse, and what does the restored
  machine come up holding".

  Scenario: a restored HVF machine holds no path off the box
    Given a captured HVF launch config carrying an egress relay, a broker and a console socket
    When the captured config is rewritten for a restored child
    Then the restored config carries no egress relay, broker or console socket
    And the restored config carries no live-handoff control socket
    And the restored config loads the saved machine state instead of booting a kernel

  Scenario: a restored HVF machine never shares its parent's identity or files
    Given a captured HVF launch config whose per-VM paths all point at the parent
    When the captured config is rewritten for a restored child
    Then every per-VM path in the restored config points at the child's own state directory
    And the restored config reads its rootfs from the child's own clone

  Scenario: an HVF checkpoint edited after it was audited cannot be restored
    Given an audited HVF vm_full checkpoint
    When the sealed record is edited after it was audited
    Then restoring the checkpoint is refused before the VMM is started

  Scenario: an HVF checkpoint that was never audited cannot be restored
    Given an HVF vm_full checkpoint that no signed audit entry covers
    Then restoring the checkpoint is refused before the VMM is started

  Scenario: a checkpoint from a removed backend is refused rather than guessed
    Given a vm_full checkpoint carrying a launch config but no machine-state blob
    Then its origin is reported as a removed backend
    And restoring the checkpoint is refused before the VMM is started

  Scenario: an HVF checkpoint is classified by the machine state it carries
    Given an audited HVF vm_full checkpoint
    Then its origin is reported as the in-house HVF VMM
