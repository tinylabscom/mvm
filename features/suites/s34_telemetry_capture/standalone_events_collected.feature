Feature: Events outside any span are collected as standalone records

  Every guest event must reach host collection, including events emitted
  outside any span, exported through their proper signal rather than being
  attached to a fabricated span or dropped.

  # BLOCKED — no collection path exists for an outside-span event. This is not
  # an unwritten test; it is an unimplemented feature, and the scenario keeps
  # the gap visible:
  #
  #   * The typed telemetry contract already has the record family for this:
  #     `RecordBody::Event` carries an *optional* trace context precisely so a
  #     standalone event is representable on the wire.
  #   * The OTLP layer (`mvm-observability`) drops an event with no enclosing
  #     span before any accounting exists — pinned by the gap regression
  #     `an_event_outside_any_span_is_dropped_with_no_record_and_no_loss_evidence`,
  #     which asserts today's deficient behavior and must flip into the
  #     positive contract in the same change that lands standalone-event
  #     capture.
  #
  # Un-tag this and write the steps in the same change that lands guest
  # capture for standalone events.
  @wip
  Scenario: An event emitted outside any span reaches the host collector
    Given a scenario awaiting its step implementation
