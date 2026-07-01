//! The builder role layer: maps a builder VM's resolved artifacts onto the
//! backend-agnostic `VmmSpec` a `VmmDriver` boots, and owns the disk-only job/
//! artifact transport. The trusted, disk-only sibling of `workload_runner` — no
//! egress endpoint, no virtio-fs. `spec` is pure (unit-testable without a VM);
//! `runner` owns the disk prep + VM lifecycle.

pub mod inhouse_builder;
pub mod inject;
pub mod runner;
pub mod spec;

pub use inhouse_builder::InHouseBuilderVm;
pub use inject::{InjectRequest, default_inject_work_dir, inject_host_binaries};
pub use runner::{BuilderBuild, BuilderOutcome, BuilderRunner};
pub use spec::{BUILDER_CMDLINE, BuilderSpecInputs, builder_spec};
