Feature: A launch plan directs execution without selecting the image

  This hermetic witness parses the documented command with the real CLI
  parser, loads a real launch plan, and executes the production guest wrapper
  in a private host directory. It does not boot a microVM or resolve an image.

  Scenario: an explicit manifest and launch plan preserve execution direction
    Given a scratch working directory
    And a command launch plan in the scratch directory
    When I execute the guest wrapper for "run --manifest minimal --launch-plan ./launch.json --env PORT=9090"
    Then the command exits with code 0
    And the output contains "PORT=9090"
    And the output contains "APP_ONLY=application"
    And the output contains "ENTRY_ONLY=entrypoint"
    And the guest wrapper used the launch plan working directory
