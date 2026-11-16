# ADR-061 conditional graph snapshot

Backing: preview
Validation: none

This is design evidence for issue #5510, not an implementation or a new CI
gate. The owner accepted ADR-061 on 2026-11-15, including the crypto-boundary
exception ([decision record](https://github.com/tinylabscom/mvm/issues/5510#issuecomment-6903558088)).
The item cuts and preserved transitions live
in [the ADR](../../../../specs/adrs/061-crate-layout-by-where-code-runs.md#concrete-item-cuts).

The first implementation-planning attachment is
[P1: lower bounded host framing](framing-prerequisite-plan.md).
It is an issue-linked planning snapshot, not implementation or landing approval.

The JSON snapshots keep `adr_status: Proposed` and
`acceptance_gate_cleared: false` as historical measurement-time values.
They do not track the current ADR decision; replay cannot confer acceptance
or turn design evidence into compiler/runtime validation.

## Replay

From the repository root, using only Python's standard library:

```sh
python3 xtask/data/evidence/adr-061/replay.py --self-test
```

This checks the retained graph's masks, counts and acyclicity, plus negative
fixtures for cycles and corrupt metadata. It does **not** re-extract source,
compare the current checkout with the pinned revision, compile the proposed
interfaces, or supply implementation authorization.

## Measurement

The snapshot names the source revision, tools and scope. The source pass
parsed 1,261 Rust files reached through library, binary and development target
module declarations in nine packages. It followed nested/path modules and
source-visible imports, aliases, wildcard imports, qualified paths and
bound identifiers. Production projection excluded test attributes/branches
and development target edges; build dependencies stayed separate in Cargo
metadata before composition.

The 32 concrete cases use the eight targets in the snapshot and default,
no-default, all, and release feature selections. Release means
`host,user,release-artifact-bootstrap,release-channel,embed-host-bins`.
Eight additional feature-union cases retain both possible Cargo/CPU-feature
and debug-assertion branches rather than treating `--all-features` as every
combination. The target cfg values remain target-specific.

The source projection applies the ADR's proposed item destinations and the
five explicit future call-site rewrites retained in `graph.json`. It does not
delete an upward call merely because it breaks the desired layering.
The combined graph adds local normal/build manifest edges after the named
contractions, retirement and conditional VMM dependency removals. Untouched
packages retain their manifest relationships. Role names stand for the
proposed extracted packages; other node names are existing package names.
Node counts include endpoints of retained edges, not disconnected workspace
members and not a count of packages compiled for that target.

For each edge, bit `i` denotes case `i` in the `cases` array. The first mask
is the combined graph; the second is the source-only projection. Masks retain
each case rather than just a single default-feature adjacency list.

The source inventory fingerprint is SHA-256 over a sorted-key JSON map of
relative source paths to SHA-256 file-content hashes. It identifies the
measurement input, not authority to reuse a result on a changed source tree.
The snapshot was remeasured at `dd2af0833eeaf1e2abd738e694dc1b463140ff25`
after the local-run staging change in #5564; its new adapter remains in
supervisor composition, not lower admission. All 40 source edge sets retained
the reviewed topology.

## Package-selected closure baseline

The separate [closure baseline](closure-baseline.json) records 28 successful
offline, locked `cargo tree` resolutions, rerun at
`052276763f889960b0fd16cb7d58583e6cce4ec5` after the crypto-leaf addition. These select
one package at a time instead of using whole-workspace metadata. Normal and
build edges are included; dev edges are excluded. The command template and
every target/feature selection are retained in the JSON.

Twenty default cases cover core, agentd, builder-guest, host-services and
setpriv on both Linux architectures and both GNU/musl targets:

| Selected package | aarch64, either libc | x86_64, either libc |
| --- | ---: | ---: |
| `mvm-core` | 77 | 78 |
| `mvm-agentd` | 84 | 85 |
| `mvm-builder-guest` | 88 | 89 |
| `mvm-host-services` | 85 | 86 |
| `mvm-setpriv` | 2 | 2 |

Counts include the selected package. All 20 had no hits in the recorded
async/host-state/HTTP/TLS/C-build name set. Where core was present its only
resolved feature was `default` (an empty feature), not `host-state`,
`hostd-transport` or `schema`. Setpriv reached only itself and libc.

Eight contrast cases cover macOS core, opt-in core transport, agent schema
and addons, contract on bare-metal/default/no-default and browser Wasm, and
host-services on browser Wasm. Transport opts into Tokio; schema opts into
schemars without Tokio; addons opts into its async stack while core remains
default-only. These are resolution observations, not builds or proof that
agentd/host-services source compiles on Wasm. They do not simulate the future
manifests and are not checked by `replay.py`.

## Head reconciliation

The [head delta](head-reconciliation.json) records the bounded review from the
original graph revision to `052276763f889960b0fd16cb7d58583e6cce4ec5`.
Every workspace manifest's declared local normal/build edges was compared:
only `mvm-core → mvm-crypto` was added, with no removals. The runner's moved
start/standby/claim and broker-registration definitions remain runtime-owned.
The source inventory was not regenerated; its fingerprint still belongs to
the base revision. Applying the one new leaf edge to the retained 40 cases
gives an acyclic union of 29 incident nodes and 123 edges.

Replay that additive topology check separately from the base snapshot:

```sh
python3 - <<'PY'
import json
import runpy
from pathlib import Path

p = Path("xtask/data/evidence/adr-061")
g = json.loads((p / "graph.json").read_text())
d = json.loads((p / "head-reconciliation.json").read_text())
assert g["source_revision"] == d["base_source_revision"]
assert d["adr_status"] == "Proposed" and not d["acceptance_gate_cleared"]
topological_order = runpy.run_path(str(p / "replay.py"))["topological_order"]
edges = g["edges"] + d["added_projected_edges"]
assert len({(a, b) for a, b, _, _ in edges}) == len(edges)
for i in range(len(g["cases"])):
    for mask_column in (2, 3):
        topological_order([(e[0], e[1]) for e in edges if int(e[mask_column], 16) & (1 << i)])
nodes = topological_order([(a, b) for a, b, _, _ in edges])
expected = d["expected_composed_graph"]
assert (len(g["cases"]), len(nodes), len(edges)) == (
    expected["cases"], expected["union_incident_nodes"], expected["union_edges"])
print("Head delta: 40 cases; 29-node/123-edge conditional union acyclic")
PY
```

This is not source re-extraction or compiler validation. Retaining the new
independently optimized crypto crate is the explicitly accepted exception to
the ADR's original three-reason crate rule.
Its package-profile optimization and caller-owned key custody stay intact.

## Consumer coverage

Manifest inspection found 15 detached Cargo manifests beyond the 29 workspace
packages: nine fuzz workspaces, three web packages, one eBPF program and two
standalone fixtures. Paths below are current source paths, relative to the
repository root. Future paths and feature decisions are in the ADR.

| Current consumer | Relocation obligation / existing validation entrypoint |
| --- | --- |
| `crates/mvm-agentd/fuzz/Cargo.toml` | Preserve its eight targets and explicit agentd/core/contract/build path edges; protocol targets consume the new core owner. Retain the target commands and corpus paths in `.github/workflows/security.yml`. |
| `crates/mvm-contract/fuzz/Cargo.toml`, `crates/mvm-core/fuzz/Cargo.toml` | Carry with parent, including exclusions/patch depths; retain FlowMux/substitution and snapshot/application fuzz targets in the security workflow. |
| `crates/mvm-fs/fuzz-oci/Cargo.toml`, `crates/mvm-fs/fuzz-ext4/Cargo.toml`, `crates/mvm-http/fuzz/Cargo.toml`, `crates/mvm-sdk/fuzz/Cargo.toml` | Carry with parent; preserve security workflow working directories, target names and `--fuzz-dir` selectors. |
| `crates/deps/libkrun-sys/fuzz/Cargo.toml` | Existing location stays fixed; preserve its independent config/attach targets without enabling FFI linkage. |
| `crates/mvm-runtime/fuzz-backend/Cargo.toml` | Geometry harness follows VMM, imports `mvm_vmm::vmm::vsock::FuzzTransportDriver` directly instead of runtime's facade, and preserves `fuzz_virtqueue_geometry` plus its `--fuzz-dir fuzz-backend` lane. |
| `web/audit-verify/Cargo.toml`, `web/mvm-demo/Cargo.toml`, `web/mvm-demo-guest/Cargo.toml` | First two rewrite the contract path; guest has no local MVM dependency. Preserve separate wasm-pack/WASIp1 builds, demo size budgets and `web/mvm-demo/build.sh`; workspace builds omit them. |
| `crates/mvm-hostd/ebpf/Cargo.toml` | A separate `[workspace]`, not a member or root exclusion. Move with egress and its manifest-relative loader lookup. Preserve binary/object name, `just check::ebpf` and the Linux `test-ebpf-telemetry` CI lane. |
| `examples/wasm-hello/Cargo.toml`, `tests/fixtures/capture/rust-hello/Cargo.toml` | No local MVM path dependency or relocation; retain their parent test/build uses. |
| `crates/mvm-conformance/Cargo.toml` | Workspace test-only package with cross-owner dev dependencies; Cucumber is now an optional normal dependency selected by `bdd`. Preserve required-feature BDD and `just check::gated`; `just bdd::run` builds schema emitters and checks generated SDK artifacts before running scenarios. |
| Required-feature binaries/examples | Preserve explicit selectors in manifests and CI, notably schema, addons, libkrun supervisor, APFS helper and BDD. `--all-targets` alone skips these. Keep `cargo run -p mvm-agentd --features schema --bin emit_protocol_schema` valid. |
| Build/cache and distribution consumers | Update relative source/patch paths, fingerprint inputs, workflow path filters and SDK PyPI/NPM packaging alongside each move. Retain binary/CDylib names. Remove only runmvm-client's publish root and registry-smoke consumers, not contract publication. |
| External Studio | Retain `crates/mvm-client`; no external checkout inspected. Its eventual relocation needs a coordinated source-consumer change, not an assumption that package-name stability fixes path dependencies. |

The root exclusion `crates/mvm-build/fuzz` has no matching directory at this
source pin; it is not a sixteenth detached consumer. The browser audit README
and HTML also retain the old `mvm-verify` name; their actual dependency is
contract. These are path/documentation migration corrections, not new crates
or unimplemented harnesses to invent. No fuzz, browser, eBPF, BDD, schema
generation or packaging commands were executed in this review.

## Limits and review corrections

This is conditional syntax-based evidence, not compiler name/trait/macro
resolution. It does not certify API visibility, private-field invariants,
generated code, dev/test dependency cycles, detached fuzz/browser workspaces,
future guest closures or runtime platform support. The consumer inventory and
current package-selected resolutions above narrow those gaps but do not turn
the retained production graph into a compiler-validated extraction.

Two incomplete models were rejected during review:

- A wildcard import in post-admission `final_gates` retained an upward
  admission → supervisor edge. Its complete start transaction belongs above
  admission.
- Treating all UI calls as reporting hid helper-build consent. Consent and
  source-build preparation must remain explicit; VMM consumes prepared helper
  paths, not a build implementation disguised as a callback-free UI call.

The ADR's [interface review](../../../../specs/adrs/061-crate-layout-by-where-code-runs.md#interface-review)
now records concrete recommendations for native-completion append, opaque
caller capabilities and confinement diagnostics. This source-based review
does not compile the designed interfaces or supply runtime evidence. In
particular, native-completion provenance relies on the typed adapter and a
production call-site restriction, not the raw record method's signature.
These refinements do not change the retained graph's edges or source pin;
the graph was not re-extracted for this documentation-only review.

The feature/consumer review also refined two item boundaries: socket-free
helpers inside guest `api` stay portable beside DTOs, and raw HVF keeps its
public export/refusal surface under the VMM `hvf` feature rather than a blanket
macOS/aarch64 module gate. The ADR maps each group to its predicate and
caller/re-export disposition. These remain within already-assigned core/VMM
owners and existing dependency directions; the snapshot is not new evidence
that the proposed symbols compile under each predicate.
