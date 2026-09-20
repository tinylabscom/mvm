# Core module ownership cleanup

Issue [#3314](https://github.com/tinylabscom/mvm/issues/3314), tracked by
`specs/plans/2026-09-15-the-big-cleanup.md` C3 and C5.

## Result

Fresh production-use measurement found nine genuinely dead `mvm-core` modules:
`action_state`, `at_rest`, `conformance_badge`, `egress_handler`,
`ingress_redaction`, `init_supervisor`, `launch_metadata`, `memory_budget`, and
`metering`. They and the metering-only integration test are removed.

Eight modules had exactly one shipped consumer and now live with that consumer:

- `egress_broker`, `extension_admission`, and `rate_limit` in `mvm-hostd`
- `grants_resolve` in `mvm-client`
- `kernel_artifact` in `mvm-build`
- `page_merge` in `mvm-conformance`
- `run_sidecars` in `mvm-backends`
- the SOCKS5 UDP datagram codec in `mvm-agentd`

The SOCKS5 codec move also exposed and removed its unused pre-FlowMux line marker;
the guest protocol gate continues to reject any reintroduction of that marker.
The serialized `MeteringEpoch` audit kind remains so historical audit logs stay
readable, while ADR-013 now records that its never-consumed resource-metering
model was superseded.

The initial inventory had also gone stale in the other direction.
`trace_context` and `pack_revocation` now have production consumers,
`kernel_advisory` is shared with `xtask`, and `mvmd_iface` is the declared
external contract for the separate `mvmd` repository, so all four remain.

The pack subsystem remains in `mvm-core`. It is no longer an acyclic extraction:
pack code consumes core architecture, plan-key, digest-shape, and image-verification
types while core image-set, trust, cache, and revocation code consumes pack types.
Extracting it alone would create a crate cycle rather than a clean boundary.

`xtask check-core-module-ownership` now pins the result: all nine retired modules
must stay absent from core, and every moved module must stay absent from core and
present in its owning crate.

## Verification

- `cargo fmt --all --check`
- `cargo check --workspace`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `just check-gated` (Linux-gated workspace targets and feature-gated BDD target)
- `cargo run -p xtask -- check-all` — 73 gates clean
- `just bdd` — 66 features; 256 scenarios: 255 passed, 1 expected capability skip
- `cargo test --workspace -- --test-threads=1` — full workspace, integrations,
  804 `xtask` tests, and doctests passed
