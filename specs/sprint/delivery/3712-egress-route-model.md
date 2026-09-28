# #3712 — egress routes: endpoint rules over method and path

The second part of PS-02 (`specs/plans/2026-09-25-agent-sandbox-product-surface.md`).
It follows the private-range default deny, which landed separately.

## What landed

- **Types.** `mvm_contract::policy::routes` defines routes and endpoint rules:
  - `EgressRoute { id, host, port, rules, otherwise, intercept }`;
  - `EndpointRule { id?, method?, path, outcome }`;
  - `RouteOutcome` of allow, deny or ask.

  Every type is `deny_unknown_fields`. `RouteSet::new` validates:
  - ids are well formed and unique;
  - hosts are lower-case, and wildcards cover at least two labels;
  - each destination has at most one route;
  - methods and globs are well formed;
  - a set holds at most 256 routes and each route at most 256 rules.
- **Path matching.** Paths are canonicalised before matching. A dot segment,
  an empty segment, a backslash, a raw control or non-ASCII byte, or an
  encoded `/`, `\` or `.` is refused as `ambiguous_path`. Encoded unreserved
  characters are decoded first, so `/%61dmin` cannot evade a rule on
  `/admin`. Globs match by dynamic programming, so many `**` segments stay
  linear.
- **Fuzzing.** `fuzz_egress_routes` covers decode, validation and decision.
  It asserts four things:
  - nothing panics;
  - an ambiguous path is always refused;
  - a decision is deterministic;
  - a parsed `--allow-endpoint` spec always builds a valid route.

  It ran for 60 s locally (3.1M executions) with no failure, and is wired into
  `security.yml`. `fuzz_substitution_positions` additionally exercises the
  four injection positions, malformed placeholders, position mismatches, and
  the no-secret-on-error invariant; it is registered in the same workflow.
- **Signed plan.** Routes ride on `NetworkPolicy` as `routes` in both
  variants, serialised only when present, so plans without routes are
  byte-identical. `EgressGate::from_network_policy` validates them and fails
  closed to deny-all on an invalid set.
- **Enforcement point.** `EgressGate::decide_route` decides, and the
  substitution service enforces the decision on every request it reads
  (typed and terminated flows) after the claim-10 host decision.
  - A refused request never reaches the forward leg.
  - `ask` is put to `EgressApprover`. Its default, `NoApprovalBackend`,
    refuses with `approval_unavailable`, and PS-07 plugs in behind that trait.
- **Audit.** Every decision (allow, deny, ask) is recorded as
  `host.route.decided` with route, rule, outcome, destination, a fixed-set
  method label, verdict and reason. The path is not recorded.
- **Interception.** A destination with no bound secret is terminated for its
  rules only when its route says `intercept = true`. The spawner mints the
  per-VM certificate over those hosts as well. An opaque flow to a
  destination whose rules cannot be enforced is refused as
  `endpoint_rules_unenforceable`.
- **CLI.** `--allow-endpoint "[METHOD ]URL"` works on `run` and `machine run`,
  including `--entrypoint`. Each flag admits its host and adds an allow rule;
  flags for one host form one route that denies everything else, and the flag
  is the interception grant.
- **Manifest.** `[[network.routes]]` is read from the run's local manifest. A
  flag naming a destination the manifest already routes is refused, because
  composition only narrows.
- **Persistent machines.** `machine run --name`/`-d` and
  `machine create --manifest` store validated endpoint routes in
  `MachineSpec`. Drift checks compare them, restart reconstructs the network
  policy from them, and `machine inspect` renders them.
- **Injection modes.** `secret set --inject` accepts `header`, `query_param`,
  `url_path`, and `basic_auth`, records the selected mode in binding metadata,
  and validates that it is compatible with the provider's authentication
  type. Admission carries that mode into the signed plan and refuses tampered
  or incompatible metadata. The host endpoint substitutes the placeholder
  only in the selected request position, refuses missing, misplaced, or
  repeated placeholders, and registers encoded wire forms with the reflected
  credential scrubber.

## Live verification (macOS 26, HVF)

The run was `run --image curlimages/curl:latest --allow-endpoint "GET https://postman-echo.com/get"`.
The guest got the trust-bundle variables (`SSL_CERT_FILE` and the rest)
because the certificate covered the intercepted host.

| Request | Guest result | Recorded as |
| --- | --- | --- |
| `GET /get` | 200 | `rule-1 allow forwarded` |
| `POST /post` | 502, `egress route refused POST postman-echo.com:443 (route_denied)` | `otherwise deny refused route_denied` |
| `GET /headers` | 502 | refused |
| `GET /get/%2e%2e/headers` | 502 | refused |

## Validation

- focused contract, binding, runtime persistence, client launch, CLI,
  admission, proxy, and hostd suites;
- workspace check and zero-warning workspace Clippy;
- Linux- and feature-gated cross-checks plus `check-single-network-path`;
- the host workspace suite split around two pre-existing builder-environment
  tests that wait indefinitely when local libkrun prerequisites are absent.
