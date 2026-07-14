Feature: Secrets and PII never enter the guest

  Raw secret values and unredacted PII never cross into a microVM. The host
  substitutes bound secrets and redacts PII at the egress boundary, and
  every substitution is written to the chain-signed audit log.

  @wip
  Scenario: A guest requesting a bound secret never observes its raw bytes
    Given a scenario awaiting its step implementation

  @wip
  Scenario: Outbound PII is redacted before it leaves the host
    Given a scenario awaiting its step implementation
