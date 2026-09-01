//! The builder role layer: maps a builder VM's resolved artifacts onto the
//! backend-agnostic `VmmSpec` a `VmmDriver` boots, and owns the disk-only job/
//! artifact transport. The trusted, disk-only sibling of `workload_runner` — no
//! egress endpoint, no virtio-fs. `spec` is pure (unit-testable without a VM);
//! `runner` owns the disk prep + VM lifecycle.

pub mod hvf_builder;
pub mod hvf_persistent;
pub mod inject;
pub mod runner;
pub mod spec;

pub use hvf_builder::HvfBuilderVm;
pub use hvf_persistent::{HvfPersistentHostVm, PersistentHvfSession};
pub use inject::{InjectRequest, default_inject_work_dir, inject_host_binaries};
pub use runner::{BuilderBuild, BuilderOutcome, BuilderRunner};
pub use spec::{
    BUILDER_CMDLINE, BuilderSpecInputs, PersistentBuilderSpecInputs, builder_spec,
    persistent_builder_spec,
};
