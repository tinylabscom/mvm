Feature: Bounded workload output capture
  A stopped output consumer must not make a workload wait for telemetry space.
  Under saturation the capture keeps a bounded tail and reports missing bytes.
  This hermetic pipe fixture is not an every-VM telemetry certification.

  @stream_capture
  Scenario: Workload finishes writing while its capture consumer is paused
    When a workload floods its bounded capture while the consumer is paused
    Then the capture is bounded and every output byte is delivered or reported lost
