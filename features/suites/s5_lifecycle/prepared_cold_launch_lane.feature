Feature: Prepared cold-launch measurement lanes

  A prepared cold-launch number only means something if the launch behind it
  acquired nothing, built nothing, materialized no mount image, and claimed no
  warm standby. The benchmark refuses a sample that did any of those, and
  refuses any sample at all from an unoptimised binary, so a published
  percentile cannot quietly include work the contract excludes.

  Scenario: A launch that only booted is a prepared cold sample
    Given a release launch sample whose launch performed no hidden work
    When the sample is offered to the prepared-cold lane
    Then the prepared-cold lane accepts the sample

  Scenario Outline: A launch that did hidden work is not a prepared cold sample
    Given a release launch sample whose launch performed <work>
    When the sample is offered to the prepared-cold lane
    Then the prepared-cold lane refuses the sample naming <work>

    Examples:
      | work              |
      | image_pull        |
      | image_build       |
      | mount_materialize |
      | warm_claim        |

  Scenario: A warm claim is refused even when only the launch mode reveals it
    Given a release launch sample whose launch performed no hidden work
    And the launch was satisfied by a warm standby without setting the work flag
    When the sample is offered to the prepared-cold lane
    Then the prepared-cold lane refuses the sample as not a cold launch

  Scenario: An unoptimised binary can never produce a launch measurement
    Given a debug launch sample whose launch performed no hidden work
    When the sample is offered to the prepared-cold lane
    Then the prepared-cold lane refuses the sample as not release-built
