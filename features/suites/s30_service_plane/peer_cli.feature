Feature: The --peer flag authors a route the runtime honours

  These drive the built `mvmctl`, so they cover the gap that unit tests could
  not: whether a user invocation actually reaches the code under test. A
  malformed route was once accepted here while every unit test was green,
  because `--dry-run` returned before the flag was ever parsed.

  Scenario: the documented peer invocation is accepted
    Given an isolated mvm home
    When I run mvmctl in the isolated mvm home with "run --peer db.mvm.peer:5432=127.0.0.1:34567 --dry-run -- /bin/true"
    Then the command exits with code 0

  Scenario Outline: a malformed peer route is refused at the CLI
    Given an isolated mvm home
    When I run mvmctl in the isolated mvm home with "run --peer <route> --dry-run -- /bin/true"
    Then the command exits with code 1
    And the error output contains "invalid --peer"

    Examples:
      | route                             |
      | api.example.com:443=127.0.0.1:80  |
      | db.mvm.peer:5432                  |
      | db.mvm.peer:5432=127.0.0.1        |
      | db.mvm.peer:0=127.0.0.1:34567     |
      | db.mvm.peer:5432=db.internal:80   |

  Scenario: machine run accepts the same route
    Given an isolated mvm home
    When I run mvmctl in the isolated mvm home with "machine run --name bdd-peer --image alpine --peer db.mvm.peer:5432=127.0.0.1:34567 --dry-run -- /bin/true"
    Then the command exits with code 0
