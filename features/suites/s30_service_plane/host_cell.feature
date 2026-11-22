Feature: A unit keeps a state cell on the host, and a replaced epoch is fenced

  A topology declares one writer and its readers for each cell; the host holds
  the value. The guest reaches the cell over the broker channel only when the
  signed plan binds the service, and the writer's role, the reader's and
  whether an epoch may act all come from the host, never from the call.

  The witness boots real Firecracker microVMs. The fixture speaks the broker
  framing itself, since no guest library exports the cell service, and the
  test admits the topology and advances the ledger through the host's own
  functions, since no command does either.

  @live @firecracker @cell_live
  Scenario: a writer's value reaches a reader and the writer is fenced once replaced
    Given the state-cell fixture is materialized as a read-only disk image
    And the image "python:3.12-alpine" is prepared in the live home
    And the live home admits a topology where "controller" writes cell "setpoint" and "reader" reads it
    When the writer "controller" runs the cell fixture and its epoch is replaced mid-run
    Then the command exits with code 0
    And the output contains "CELL-WRITER-FENCED"
    When the reader "reader" runs the cell fixture
    Then the command exits with code 0
    And the output contains "CELL-READER-OK"
