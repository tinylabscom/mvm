Feature: Warm-restore epoch rollback refusal

  The per-instance epoch counter is monotonic. A snapshot whose epoch is
  below the recorded high-water mark is a replay and must be refused.

  Scenario: an older-epoch snapshot refuses restore after a newer seal
    Given a sealed warm snapshot for VM "epoch-vm" captured at epoch 1
    And the same VM is sealed again at a newer epoch
    When warm restore is attempted from the older-epoch snapshot
    Then warm restore is refused with an epoch rollback error
