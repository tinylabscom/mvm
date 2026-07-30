Feature: Warm-restore NIC refusal

  A restored snapshot must not carry a network interface; the only guest
  egress path is the audited vsock seam.

  Scenario: a snapshot device model with a network interface refuses restore
    When a restored device model containing a network interface is checked
    Then the no-NIC guard refuses it
