# FlowMux transformations are bounded and endpoint-owned

Typed HTTP no longer assembles a whole request or response at the FlowMux
boundary. Request heads and bodies are validated and forwarded incrementally;
responses return as bounded chunks. Fixed-length and chunked framing are
checked strictly, head and body limits fail closed, idle timeouts are bounded,
and reset or session teardown cancels in-flight work and returns reservations.

Secret substitution, redaction, and reversible replacement retain only a
bounded overlap window so matches split across frames are transformed without
retaining an unbounded body. Secret-bearing buffers are zeroized when they are
finished or cancelled. Replay is available only where signing or reversible
replacement requires it. Opaque TCP and UDP are refused only when a declared
destination requires a typed transformation, and refusal audits contain a
derived destination and reason rather than payload bytes.

Typed host tools now use a per-VM, mode-0600 endpoint connector socket. The web
fetch and Brave, Tavily, and Google search brokers authorize requests and pass
placeholders, but they no longer resolve DNS, dial destinations, or construct
an independent workload HTTP client. The endpoint performs final destination
admission, substitution, hardened HTTP execution, response redaction, and
auditing with the same service used by guest `OpenHttp` flows.

Witnesses cover fixed and chunked request and response streaming, split-token
transforms, long clean streams with bounded overlap, redirects without
automatic following, oversized heads and bodies, idle timeout, cancellation,
session teardown, connector permissions and framing, credential placeholders,
endpoint subprocess execution, and payload-free failure audits. Required
validation passed: workspace all-target Clippy with warnings denied, workspace
check, Linux and BDD-feature gated compilation, workspace executable tests,
workspace doctests, and the complete BDD suite (56 features, 210 scenarios:
209 passed and one intentionally skipped; 860 steps: 859 passed and one
intentionally skipped).
