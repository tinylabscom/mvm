# mvm-observability

`mvm-observability` assembles tracing subscribers for mvm's host-side binaries.
It is the process-level integration between `tracing` events and the metrics
registry defined in `mvm-core`.

## Who uses it

`mvm-cli` initializes logging and span timing through this crate. Other
host-side binaries can use it when they own a process and therefore may install
a global subscriber. Guest and embedded helper binaries emit through the
lightweight `tracing` facade but do not depend on this crate.

## How it works

`logging::init` builds one subscriber from a filter and `LogFormat`, then
installs it as the process-global default. Human output is optimized for
interactive terminals; structured output is suitable for automation. The
default filter can be overridden explicitly without requiring each binary to
rebuild subscriber wiring.

`SpanTimingLayer` observes span lifecycle events, records elapsed durations,
and updates the shared registry in `mvm-core`. Metrics DTOs and Prometheus
rendering remain in the foundation crate because they also cross the agent
protocol; only the dependency-heavy subscriber layer lives here.

## Public surface

| Item | Responsibility |
|---|---|
| `init` | Install logging with standard defaults |
| `init_with_filter` | Install logging with a caller-supplied filter |
| `LogFormat` | Select human or structured output |
| `DEFAULT_FILTER` | Workspace default directive |
| `SpanTimingLayer` | Feed tracing span durations into shared metrics |

Subscriber installation is process-global and should happen once near a binary
entry point. Libraries should emit spans and let their caller choose the
subscriber.

## Developing

Run `cargo test -p mvm-observability`. Tests should use scoped subscribers where
possible and must cover filter parsing, both output formats, nested spans, and
concurrent timing updates without relying on global test order.
