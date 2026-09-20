Feature: Guest agent and helper diagnostics reach the host collector

  Diagnostics the guest agent and its helpers emit must reach authenticated
  host collection across cold start, restore and exit — not a local console
  nobody captures, and not a facade with no subscriber behind it.

  # BLOCKED — no guest capture path exists. This is not an unwritten test; it
  # is an unimplemented feature, and the scenario keeps the gap visible:
  #
  #   * The sealed guest agent emits real diagnostics through the `tracing`
  #     facade and installs no subscriber, so every one of them is discarded —
  #     pinned by the gap regression
  #     `boot_diagnostics_are_emitted_but_the_sealed_agent_discards_them`,
  #     which asserts today's deficient behavior and must flip into the
  #     positive contract in the same change that lands guest capture.
  #   * The addon helpers that do install subscribers write to the guest
  #     console only; the telemetry source inventory
  #     (`specs/telemetry/sources.toml`) classifies every one of these as an
  #     explicit runtime gap with its required witness.
  #
  # Un-tag this and write the steps in the same change that lands the guest
  # capture subscriber and its authenticated delivery to the host collector.
  @wip
  Scenario: Sealed-agent boot diagnostics arrive at the authenticated collector
    Given a scenario awaiting its step implementation
