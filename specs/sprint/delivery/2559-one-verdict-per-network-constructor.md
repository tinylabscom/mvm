# One verdict per network constructor

Delivered 2026-08-16. Closes #2559.

## What was wrong

`mvm_sdk::ctor::host_port("api.example.com", 0)` built a perfectly good IR node.
`mv.host_port("api.example.com", 0)` raised `ValueError`. Same constructor, same
arguments, two answers — and the value feeds `NetworkEgress.allowlist`, which is
the claim-10 allowlist. Port 0 reads as "any port" to the operating system, so
an entry carrying it authorizes nothing while looking exactly like an
authorization.

`dns_resolver` had the wider version of the same hole: Python refused an empty
host, and nothing on the Rust side looked at the resolver at all — not the host,
not the port.

Nothing in the tree could see any of it. The parity machinery compares
**names**: the s27 surface scenario diffs `Object.keys(mvm)` against
`dir(mvm)` and reconciles the difference with `surface_divergence.json`. Both
languages export a `host_port` taking `(host, port)`, so that comparison reports
agreement and always would have.

`xtask check-two-surfaces` could not have caught it either, and it is worth
saying so plainly because the name invites the assumption: that gate parses the
root `Cargo.toml`'s `[features]` table and enforces that the *product* ships
exactly two surfaces, `host` and `user`. It has nothing to do with language
bindings.

## What the divergence actually was

Not "Python is stricter". Python's checks and Rust's `u16` are both attempts to
state the same constraint, and `u16` states it wrong: `1..=65535` is not
`0..=65535`. Rust discharges most of this class of constraint in the type
system, which is why the constructors can stay `-> HostPort` instead of
`-> Result<HostPort, _>`, and the constructor signature is the wrong place to
patch — that was settled when the generated-surface spike weighed it.

What was missing is a place where the constraint is stated **once**, below both
languages. The workload document has one: `mvm_contract::ir::validate` is the
seam every surface's output passes through on its way to a boot.

## What changed

`validate` now checks every place the host will originate a connection to on the
guest's behalf, through one helper, `validate_dialable_destination`:

- egress allowlist entries — previously wildcard-checked on the host only;
- the pinned DNS resolver — previously not checked at all.

Both get the same two rules: the host must not be empty, blank, or a wildcard
(`E_NETWORK_WILDCARD`, the existing code and existing predicate), and the port
must be in `1..=65535` (`E_NETWORK_INVALID_PORT`, new). One helper rather than
two call-sites' worth of copied `if`s, because a rule enforced at one of two
adjacent seams is how this drifted in the first place.

An empty *egress* host, it turns out, was already refused — `is_wildcard_host`
matches `""` — so the issue's claim that Rust accepts one holds for
`dns_resolver` and not for `host_port`. The corpus records both, which is the
point of writing the verdicts down.

## What stops it diverging again

`features/suites/s27_sdk/fixtures/network_constraints.json` states each
constructor's verdict once, and two independent checks read it:

- `crates/mvm-sdk/tests/validate.rs` builds every case through the public Rust
  constructors and asserts `validate` reaches the corpus verdict;
- the s27 scenario runs `python_constraints.py`, which builds every case through
  the public Python DSL, and validates whatever it emits.

Refusing at the constructor and emitting a document validation then rejects
count as the same verdict, deliberately: the corpus states what may reach a
workload, and which seam catches it is a language-idiom detail. A surface that
starts accepting what another refuses now fails a gate instead of reaching a
user, in either direction — loosening Rust fails the Rust half, loosening Python
fails the BDD half, and changing the contract means changing the file both read.

This is the first slice of the golden-document behavioural gate the
generated-surface plan's WS-1 decision asks for. When WS-3 generates these
constructors into TypeScript, the third surface checks against the same file.

## Not done here

The constructors are still hand-written per language, and the constraint is
still spelled twice — once as Python `if`s, once as Rust validation. The corpus
makes the two provably agree; it does not make them one piece of code. That is
WS-3's job and needs the declarative constructor manifest to exist first.

`PortForward.host` / `.guest` take the same `u16` and are unchecked for zero.
Left alone: no language surface refuses them today, so there is no divergence,
and widening the fix would be a behaviour change nobody asked for.
