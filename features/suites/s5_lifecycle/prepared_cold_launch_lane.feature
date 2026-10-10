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

  A launch from a signed `.mvmpkg` verifies the archive against the publisher
  trust store first. That is real work and the prepared lanes refuse it; the
  `prepared_cold_artifact` lane is where it is measured, held to the same
  dispatch budgets and per-boot ceiling, with the verification time published
  beside the boot rather than folded into it.

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
      | bundle_verify     |

  Scenario: A launch from a verified signed archive is an artifact-lane sample
    Given a release launch sample whose launch performed bundle_verify
    When the sample is offered to the prepared-cold-artifact lane
    Then the prepared-cold-artifact lane accepts the sample

  Scenario: The artifact lane refuses a launch that verified no archive
    Given a release launch sample whose launch performed no hidden work
    When the sample is offered to the prepared-cold-artifact lane
    Then the prepared-cold-artifact lane refuses the sample naming bundle_verify

  Scenario: The artifact lane still refuses an image pull
    Given a release launch sample whose launch performed image_pull
    When the sample is offered to the prepared-cold-artifact lane
    Then the prepared-cold-artifact lane refuses the sample naming image_pull

  Scenario: A warm claim is refused even when only the launch mode reveals it
    Given a release launch sample whose launch performed no hidden work
    And the launch was satisfied by a warm standby without setting the work flag
    When the sample is offered to the prepared-cold lane
    Then the prepared-cold lane refuses the sample as not a cold launch

  Scenario: An unoptimised binary can never produce a launch measurement
    Given a debug launch sample whose launch performed no hidden work
    When the sample is offered to the prepared-cold lane
    Then the prepared-cold lane refuses the sample as not release-built

  Scenario: A prepared boot just below 200 ms meets the hard requirement
    Given a prepared-cold launch with a dispatch window of 199.9 ms
    When the dispatch timing is checked against the hard boot requirement
    Then the hard boot requirement passes

  Scenario: A prepared boot at 200 ms fails the hard requirement
    Given a prepared-cold launch with a dispatch window of 200.0 ms
    When the dispatch timing is checked against the hard boot requirement
    Then the hard boot requirement fails and says every boot must be under 200 ms
