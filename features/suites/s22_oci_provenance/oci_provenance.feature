Feature: s22_oci_provenance

  Conformance scenario for MVM-SEC-14.

  A `--prod` OCI run records where its image came from, which only means
  something if the reference cannot move underneath it. So `--prod` refuses a
  mutable tag **before any network fetch**: the refusal is a property of the
  reference itself, not of what some registry happened to answer.

  Both scenarios run against an empty, isolated mvm home with nothing cached,
  which is what makes "before any network fetch" observable — the refusal
  arrives without a registry being consulted at all.

  The claim's full witness (a `plan.oci_provenance` entry in the chain-signed
  audit log) needs a real boot and stays with the live lane; what is checked here
  is the admission property that has to hold before any of that can be trusted.

  @MVM-SEC-14 @build
  Scenario: A prod image pull refuses a mutable tag before reaching a registry
    When I run mvmctl with "image pull --prod alpine:latest" and an isolated mvm home
    Then the command exits with code 1
    And the error output contains "requires a digest-pinned reference"

  @MVM-SEC-14 @build
  Scenario: Image repository capitalization is normalized before admission
    When I run mvmctl with "image pull --prod GHCR.IO/Acme/Widget:ReleaseCandidate" and an isolated mvm home
    Then the command exits with code 1
    And the error output contains "requires a digest-pinned reference"
    But the error output does not contain "invalid image reference"

  # The discriminating half. Without it, the scenario above would pass just as
  # well against a blanket `--prod` refusal that never looked at the reference:
  # a digest-pinned reference must get *past* the pin check and be refused for
  # the next reason instead.
  @MVM-SEC-14 @build
  Scenario: A digest-pinned reference passes the pin check and meets the next gate
    When I run mvmctl with "image pull --prod alpine@sha256:1111111111111111111111111111111111111111111111111111111111111111" and an isolated mvm home
    Then the command exits with code 1
    And the error output contains "requires an OCI registry policy"
    But the error output does not contain "requires a digest-pinned reference"
