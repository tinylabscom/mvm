Feature: mvmctl run auto-detects the runtime image

  The one-shot `mvmctl run <command>` surface auto-detects the workload
  runtime from the trailing command (`python3`, `npm`, `cargo`, ...) and falls
  back to project files in the working directory. Explicit sources (`--image`,
  `--manifest`, `--launch-plan`) always win, and `--no-detect` disables the
  behavior entirely.

  These scenarios are hermetic: they use `--dry-run` so no VM boots and no
  network is touched. The assertions observe only whether the preflight
  resolved an OCI image or the bundled default microVM.

  Scenario: run detects Python from the command name
    When I run mvmctl with "run --dry-run python3 -c print()" and an isolated mvm home
    Then the command exits with code 0
    And the output contains "image: OCI reference"

  Scenario: run detects Node from the command name
    When I run mvmctl with "run --dry-run npm test" and an isolated mvm home
    Then the command exits with code 0
    And the output contains "image: OCI reference"

  Scenario: run detects Rust from the command name
    When I run mvmctl with "run --dry-run cargo test" and an isolated mvm home
    Then the command exits with code 0
    And the output contains "image: OCI reference"

  Scenario: run detects Go from the command name
    When I run mvmctl with "run --dry-run go version" and an isolated mvm home
    Then the command exits with code 0
    And the output contains "image: OCI reference"

  Scenario: run --no-detect skips auto-detection and uses the default image
    When I run mvmctl with "run --dry-run --no-detect python3 -c print()" and an isolated mvm home
    Then the command exits with code 0
    And the output contains "image: bundled default microVM"

  Scenario: run with an explicit --image skips auto-detection
    When I run mvmctl with "run --dry-run --image alpine python3 -c print()" and an isolated mvm home
    Then the command exits with code 0
    And the output contains "image: OCI reference"
