Feature: Secrets and PII never enter the guest

  Raw secret values and unredacted PII never cross into a microVM. The host
  substitutes bound secrets and redacts PII at the egress boundary, and
  every substitution is written to the chain-signed audit log.

  Scenario: A guest requesting a bound secret never observes its raw bytes
    Given a bound secret "api-key" with value "sk-ant-0123456789abcdef0123456789abcdef" in tenant "local"
    When the secret metadata is queried
    Then the metadata does not contain the raw secret value
    And the metadata names the secret and its bound destination

  Scenario: Outbound PII is redacted before it leaves the host
    Given an outbound body containing PII
    When the body is redacted by the egress PII redactor
    Then the redacted body does not contain the original PII
    And the redacted body contains the redaction mask
    And the PII redactor reports the categories it masked
