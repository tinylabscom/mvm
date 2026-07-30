Feature: Warm-restore integrity refusal

  A sealed warm snapshot is HMAC-bound to its epoch. Any bit flip in the
  captured vmstate or guest memory before restore must fail closed before a
  single guest instruction resumes.

  Scenario: a flipped byte in a sealed snapshot refuses restore
    Given a sealed warm snapshot for VM "integrity-vm"
    When a byte at offset 7 of the snapshot memory file is flipped
    And warm restore is attempted from that snapshot
    Then warm restore of that snapshot is refused with an integrity error
