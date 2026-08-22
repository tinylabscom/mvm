Feature: One public FlowMux networking surface

  New workloads use loopback adapters and typed FlowMux flows. The rejected
  packet-tunnel compatibility surface remains understandable to old callers,
  but cannot enter the admitted domain or reappear in generated SDKs.

  Scenario: generated workload surfaces omit the retired raw stack field
    Then the generated schema and SDK models omit the retired raw stack field

  Scenario: stale workload IR fails with migration guidance
    Then stale workload IR naming the retired raw stack is refused with adapter guidance

  Scenario: stale signed plans fail before admission
    Then a stale signed plan naming the retired L3 mode is refused at deserialization

  Scenario: all supported adapters use typed FlowMux classes
    Then FlowMux exposes TCP, UDP, DNS, mediated ping, HTTP proxy, and typed HTTP classes

  Scenario: typed connectors stay distinct from opaque byte streams
    Then a typed HTTP connector is classified separately from opaque TCP

  Scenario: applications bypassing adapters fail closed
    Then a networked workload requires a backend with no routable guest NIC
