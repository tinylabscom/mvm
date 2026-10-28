# Launch-plan compatibility fixture

`workload.json` follows the command-entrypoint subset of mvmforge's
[`schema/workload-ir-v0.json`](https://github.com/tinylabscom/mvmforge/blob/f594eaef21b6b1c1cc226e6fc79ef9717f07fc52/schema/workload-ir-v0.json).
The producer revision is `f594eaef21b6b1c1cc226e6fc79ef9717f07fc52`.
The corresponding artifact shape is defined in that revision's
[`crates/mvmforge/src/launch.rs`](https://github.com/tinylabscom/mvmforge/blob/f594eaef21b6b1c1cc226e6fc79ef9717f07fc52/crates/mvmforge/src/launch.rs).

The fixture exercises `apps[].entrypoints[]`, tagged literal environment
values, the `/app` default working directory, and entrypoint-over-app env
precedence. Both the parser tests and guest-wrapper test consume it.
Environment object validation reuses `mvm_contract::ir::EnvValue`, rather
than maintaining another literal-value schema.

This is not a built-image handoff: `source` and `image` describe build inputs.
Kernel/rootfs artifact discovery is intentionally not inferred from them.
