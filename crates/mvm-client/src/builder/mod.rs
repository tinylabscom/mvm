//! Host-side builder operations shared by command-line and embedded clients.
//!
//! Builder execution stays behind the core build environment and the registered
//! builder factory. No runtime driver or supervisor handle escapes this module.

mod egress;
mod lineage;
mod persistent;
mod recording;
mod secrets;
mod shell_job;
pub mod source;
mod validation;

pub use egress::{EgressSupervisorError, supervise_egress_endpoint};
pub use lineage::{ImageNodeOutcome, OciPullNode, record_flake_build_node, record_oci_pull_node};
pub use persistent::{
    PersistentBuilderArtifacts, PersistentBuilderError, PersistentBuilderResult,
    PersistentBuilderStart, PersistentBuilderStatus, PersistentBuilderSubmit,
    persistent_builder_status, start_persistent_builder, start_session_for_contended_build,
    stop_persistent_builder, submit_persistent_builder,
};
pub use recording::{SecretFinding, scan_recording_for_secrets};
pub use secrets::RecordingSecretScanner;
pub use shell_job::{ShellJobError, run_shell_job, run_shell_job_on};
pub use validation::{
    FlakeValidationError, FlakeValidationReport, FlakeValidationRequest, validate_flake,
    validate_flake_on,
};
