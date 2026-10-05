//! A process that registers the driver-backed builders can bootstrap and build
//! on HVF and Firecracker; one that has not gets those backends' named refusal.
//!
//! One test in its own binary, so the process starts with nothing registered.
//! Only Stage 0 is probed after registration: constructing it does no I/O,
//! while resolving a builder would look for, and could fetch, a builder image.

use mvm_build::builder_backend_select::{
    BuilderBackendChoice, stage0_is_registered_for, try_resolve_builder_backend_for,
};
use mvm_runtime::builder_runner::register_driver_backed_builders;

const DRIVER_BACKED: [BuilderBackendChoice; 2] =
    [BuilderBackendChoice::Hvf, BuilderBackendChoice::Firecracker];

#[test]
fn registering_makes_hvf_and_firecracker_constructible_in_any_process() {
    for choice in DRIVER_BACKED {
        assert!(
            !stage0_is_registered_for(choice),
            "{} starts unregistered",
            choice.name()
        );
        let refusal = match try_resolve_builder_backend_for(choice) {
            Ok(_) => panic!("{} resolved before registration", choice.name()),
            Err(err) => err.to_string(),
        };
        assert!(refusal.contains("is registered"), "{refusal}");
    }

    register_driver_backed_builders();
    // A second registration is harmless: the first one stands.
    register_driver_backed_builders();

    for choice in DRIVER_BACKED {
        assert!(
            stage0_is_registered_for(choice),
            "{} can bootstrap after registration",
            choice.name()
        );
    }
    for choice in [BuilderBackendChoice::Libkrun, BuilderBackendChoice::Qemu] {
        assert!(
            !stage0_is_registered_for(choice),
            "{} is mvm-build's own, not a registered driver",
            choice.name()
        );
    }
}
