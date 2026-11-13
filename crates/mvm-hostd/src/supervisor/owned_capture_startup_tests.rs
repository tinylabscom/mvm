//! Component binding checks; the checked-boot marker is an explicit fixture.
//! These do not witness actual descriptor verification, guest boot or capture.

use super::*;
use crate::supervisor::hvf_stop::StopControl;
use crate::supervisor::owned_capture::PendingCaptureStartup;
use mvm_core::protocol::hvf_startup::{FrozenConfig, StartupEnvelope};
use mvm_vmm::host::hvf_supervisor::HvfSupervisorConfig;
use std::sync::atomic::{AtomicBool, Ordering};
use uuid::Uuid;

fn checked_shape(
    admitted: &AdmittedPlan,
    registration: &CallerRegistration,
) -> mvm_vmm::host::hvf_supervisor::HvfSupervisorConfig {
    let mut cfg = startup_config(admitted, registration);
    cfg.kernel_fd = Some(100);
    cfg.boot_image_fds = Some(mvm_vmm::host::hvf_supervisor::BootImageFds {
        rootfs: 101,
        verity: 102,
        metadata: 103,
        root_hash: 104,
    });
    cfg
}

fn input(cfg: &mvm_vmm::host::hvf_supervisor::HvfSupervisorConfig, call: Uuid) -> StartupEnvelope {
    let mut wire = FrozenConfig::serialize(cfg)
        .unwrap()
        .for_call(call)
        .unwrap()
        .encode()
        .unwrap();
    let end = wire.len();
    // SAFETY: getppid only observes the current process's actual kernel parent.
    let parent = u32::try_from(unsafe { libc::getppid() }).unwrap();
    wire[end - 4..].copy_from_slice(&parent.to_be_bytes());
    StartupEnvelope::decode(&wire).unwrap()
}

#[test]
fn owned_capture_requires_checked_boot_evidence_beyond_consumed_registration() {
    let (_env, _home) = isolate();
    let vm = "owned-startup-unbound";
    let admitted = admit_fixture(vm, 1);
    let registration = registration_fixture(&admitted, vm, 1);
    let cfg = checked_shape(&admitted, &registration);
    let startup = prepare_startup(&cfg).unwrap().unwrap();
    let pending = PendingCaptureStartup::observe(input(&cfg, Uuid::new_v4())).unwrap();
    let stop = Box::leak(Box::new(AtomicBool::new(false)));
    let control = StopControl::start(vm, stop).unwrap();
    assert!(
        pending
            .bind_to_owner(startup.launch, control.authority())
            .is_err()
    );
}

#[test]
fn owned_capture_cannot_be_relabelled_for_another_protected_owner() {
    let (_env, _home) = isolate();
    let vm = "owned-startup-exact-owner";
    let admitted = admit_fixture(vm, 1);
    let registration = registration_fixture(&admitted, vm, 1);
    let cfg = checked_shape(&admitted, &registration);
    let mut startup = prepare_startup(&cfg).unwrap().unwrap();
    // Component assumption only; no descriptor or guest witness is implied.
    startup.launch.checked_boot_inputs = Some(CheckedCaptureBootInputs);
    let pending = PendingCaptureStartup::observe(input(&cfg, Uuid::new_v4())).unwrap();
    let stop = Box::leak(Box::new(AtomicBool::new(false)));
    let control = StopControl::start(vm, stop).unwrap();
    let authority = pending
        .bind_to_owner(startup.launch, control.authority())
        .unwrap();
    assert!(
        CaptureOwner::start(CaptureParams {
            vm: "different-owner",
            authority: CaptureAuthority::OwnedCold(authority),
            redaction: &admitted.plan().redaction,
        })
        .is_err()
    );
    assert!(!config::vm_stream_socket("different-owner").exists());
}

#[test]
fn owned_capture_refuses_a_different_admitted_caller_even_for_the_same_vm() {
    let (_env, _home) = isolate();
    let vm = "owned-startup-exact-caller";
    let admitted = admit_fixture(vm, 1);
    let original = registration_fixture(&admitted, vm, 1);
    let replacement = registration_fixture(&admitted, vm, 2);
    let cfg = checked_shape(&admitted, &original);
    let mut startup = prepare_startup(&checked_shape(&admitted, &replacement))
        .unwrap()
        .unwrap();
    startup.launch.checked_boot_inputs = Some(CheckedCaptureBootInputs);
    let pending = PendingCaptureStartup::observe(input(&cfg, Uuid::new_v4())).unwrap();
    let stop = Box::leak(Box::new(AtomicBool::new(false)));
    let control = StopControl::start(vm, stop).unwrap();
    assert!(
        pending
            .bind_to_owner(startup.launch, control.authority())
            .is_err()
    );
}

#[test]
fn owned_capture_binds_original_bytes_and_native_gate_and_retires_absorbingly() {
    let (_env, _home) = isolate();
    let vm = "owned-startup-bound";
    let admitted = admit_fixture(vm, 1);
    let registration = registration_fixture(&admitted, vm, 1);
    let cfg = checked_shape(&admitted, &registration);
    let mut startup = prepare_startup(&cfg).unwrap().unwrap();
    // This component fixture assumes the separately tested verified-file bind.
    // Production can mint this marker only after checking the actual boot files.
    startup.launch.checked_boot_inputs = Some(CheckedCaptureBootInputs);
    let call = Uuid::new_v4();
    let envelope = input(&cfg, call);
    let digest = envelope.config().digest();
    let pending = PendingCaptureStartup::observe(envelope).unwrap();
    let stop = Box::leak(Box::new(AtomicBool::new(false)));
    let control = StopControl::start(vm, stop).unwrap();
    let mut authority = pending
        .bind_to_owner(startup.launch, control.authority())
        .unwrap();
    let expected = authority.current_binding().unwrap().clone();
    let (mut owner, producer) = CaptureOwner::start(CaptureParams {
        vm,
        authority: CaptureAuthority::OwnedCold(authority),
        redaction: &admitted.plan().redaction,
    })
    .unwrap();
    assert_eq!(owner.owned_capture_binding().unwrap().unwrap(), &expected);
    let challenge =
        mvm_core::crypto::owned_capture::CaptureChallenge::fresh(expected, unix_now().unwrap())
            .unwrap();
    let encoded = challenge.encode().unwrap();
    assert!(encoded.windows(digest.len()).any(|window| window == digest));
    assert!(encoded.windows(16).any(|window| window == call.as_bytes()));
    stop.store(true, Ordering::Release);
    assert!(owner.owned_capture_binding().is_err());
    stop.store(false, Ordering::Release);
    assert!(
        owner.owned_capture_binding().is_err(),
        "retirement must be absorbing"
    );
    drop(producer);
    assert!(owner.finish());
}

#[test]
fn owned_capture_refuses_unchecked_modes_and_a_claimed_nonparent_pid() {
    let (_env, _home) = isolate();
    let vm = "owned-startup-mode";
    let admitted = admit_fixture(vm, 1);
    let registration = registration_fixture(&admitted, vm, 1);
    let cfg = checked_shape(&admitted, &registration);
    let mutations: [fn(&mut HvfSupervisorConfig); 6] = [
        |cfg| cfg.boot_image_fds = None,
        |cfg| cfg.caller_registration = None,
        |cfg| cfg.trusted_builder_egress = true,
        |cfg| cfg.handoff_socket = Some("/unused".into()),
        |cfg| cfg.restore_ram = Some("/unused".into()),
        |cfg| cfg.vm_name = "private-input-value/invalid".into(),
    ];
    for mutate in mutations {
        let mut changed = cfg.clone();
        mutate(&mut changed);
        let error = PendingCaptureStartup::observe(input(&changed, Uuid::new_v4()))
            .err()
            .unwrap();
        assert!(!format!("{error:?}").contains("private-input-value"));
    }
    // for_call names this process, not its actual parent: observation must refuse.
    let claimed = FrozenConfig::serialize(&cfg)
        .unwrap()
        .for_call(Uuid::new_v4())
        .unwrap();
    assert!(PendingCaptureStartup::observe(claimed).is_err());
}
