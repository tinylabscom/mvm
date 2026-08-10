Feature: Prepared cold-launch measurement lanes

  A prepared cold-launch number only means something if the launch behind it
  acquired nothing, built nothing, materialized no mount image, claimed no
  warm standby, and re-read no artifact whose digest it already had. The
  benchmark refuses a sample that did any of those, and refuses any sample at
  all from an unoptimised binary, so a published percentile cannot quietly
  include work the contract excludes.

  The last two are the ones a small test image hides. Re-hashing a cached
  rootfs costs milliseconds on a 10 MB image and hundreds on a 1 GB one, and a
  process-table walk costs whatever the host is busy with. Neither is a pull, a
  build, a materialization, or a claim, so neither had a name here before.

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
      | artifact_hash     |
      | process_table_scan|

  Scenario: A warm claim is refused even when only the launch mode reveals it
    Given a release launch sample whose launch performed no hidden work
    And the launch was satisfied by a warm standby without setting the work flag
    When the sample is offered to the prepared-cold lane
    Then the prepared-cold lane refuses the sample as not a cold launch

  Scenario: An unoptimised binary can never produce a launch measurement
    Given a debug launch sample whose launch performed no hidden work
    When the sample is offered to the prepared-cold lane
    Then the prepared-cold lane refuses the sample as not release-built
