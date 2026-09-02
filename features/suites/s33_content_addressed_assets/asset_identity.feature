Feature: Content-addressed asset identity

  Every dataset, model, prompt, agent, policy, and compute environment a
  workload names carries a content-derived identity in the signed plan.
  `mvmctl trust audit asset id` recomputes the same digest offline — the
  identical `hash_source` walk admission uses — so a caller can compare a
  path on disk against the `asset_N_digest` labels in the chain-signed log.

  Scenario: A file's asset identity is its sha256
    Given an isolated mvm home
    And a file asset "weights.bin" containing "fixed model bytes"
    When I compute the asset identity of "weights.bin"
    Then the command exits with code 0
    And the output is the sha256 of file asset "weights.bin"

  Scenario: A directory asset hashes as its canonical tree manifest
    Given an isolated mvm home
    And a directory asset "dataset" with file "train/a.csv" containing "1,2"
    And a directory asset "dataset" with file "train/b.csv" containing "3,4"
    When I compute the asset identity of "dataset"
    Then the command exits with code 0
    And the output is the canonical tree hash of directory asset "dataset"

  Scenario: A missing asset path is refused and named
    Given an isolated mvm home
    When I compute the asset identity of "nope.bin"
    Then the command exits with code 1
    And the error output contains "content identity"
