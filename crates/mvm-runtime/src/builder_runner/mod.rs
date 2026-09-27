//! The builder role layer: maps a builder VM's resolved artifacts onto the
//! backend-agnostic `VmmSpec` a `VmmDriver` boots, and owns the disk-only job/
//! artifact transport. The trusted, disk-only sibling of `workload_runner` — no
//! egress endpoint, no virtio-fs. `spec` is pure (unit-testable without a VM);
//! `runner` owns the disk prep + VM lifecycle.

mod console_progress;
pub mod driver_builder;
mod halt_watch;
pub mod hvf_persistent;
pub mod inject;
pub mod runner;
pub mod spec;
pub mod stage0_vm;

pub use driver_builder::DriverBuilderVm;
pub use hvf_persistent::{HvfPersistentHostVm, PersistentHvfSession};
pub use inject::{InjectRequest, default_inject_work_dir, inject_host_binaries};
pub use runner::{BuilderBuild, BuilderOutcome, BuilderRunner, Stage0Run};
pub use spec::{
    BUILDER_CMDLINE_TAIL, BuilderSpecInputs, PersistentBuilderSpecInputs, Stage0SpecInputs,
    builder_spec, persistent_builder_spec, stage0_spec,
};
pub use stage0_vm::Stage0Vm;
