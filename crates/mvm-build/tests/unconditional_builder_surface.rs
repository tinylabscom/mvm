use mvm_build::builder_backend_select::BuilderBackendChoice;
use mvm_build::stage0_host::{Stage0HaltOutcome, stage0_console_halt_outcome};

#[test]
fn builder_surface_is_available_without_optional_features() {
    assert_eq!(BuilderBackendChoice::Qemu.name(), "qemu");
    assert_eq!(
        stage0_console_halt_outcome("stage0-init: done; halting\n"),
        Stage0HaltOutcome::CleanHalt
    );
}
