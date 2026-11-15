//! Admission enforcement for the optional SDK sidecar attachment.

use anyhow::Result;
use mvm_build::guest_libc::GuestLibc;
use mvm_core::plan::ExecutionPlan;

/// Typed reasons the selected backend cannot carry the native SDK sidecar.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SdkSidecarBackendCompatibilityError {
    #[error(
        "refusing to launch SDK host service(s) [{services}] on the wasm backend: the SDK \
         host-services library is delivered as a native shared object on a read-only disk, but \
         wasm has neither block devices nor a native dynamic loader. Remove these bindings or \
         use a microVM backend; WASI host-service imports are not implemented"
    )]
    WasmHostServicesUnsupported { services: String },
}

/// Refuse a host-service delivery mechanism the selected backend cannot carry.
///
/// This gate runs before attachment-shape validation and backend start so an
/// SDK host-service request cannot leak as an error about the synthetic disk
/// volume used to carry its native library.
pub fn enforce_sdk_sidecar_backend_compatibility(
    backend: mvm_core::vm_backend::BackendKind,
    plan: &ExecutionPlan,
) -> std::result::Result<(), SdkSidecarBackendCompatibilityError> {
    use mvm_core::plan::{sdk_host_services_in, sdk_sidecar_required};

    // When sdk_uses_sidecar is false, the workload speaks the broker protocol
    // directly and doesn't need the SDK sidecar regardless of backend.
    if !plan.sdk_uses_sidecar || backend != mvm_core::vm_backend::BackendKind::Wasm {
        return Ok(());
    }

    // Only wasm backends need the SDK sidecar for host services.
    if !sdk_sidecar_required(plan) {
        return Ok(());
    }

    let services = sdk_host_services_in(&plan.services)
        .iter()
        .map(|service| service.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    Err(SdkSidecarBackendCompatibilityError::WasmHostServicesUnsupported { services })
}

/// Admission enforcement for the optional SDK sidecar attachment.
///
/// The sidecar carries the host-services cdylib the language SDKs `dlopen`. Its
/// attachment is authorized by the plan's host-service bindings, never by an
/// environment variable or a guess about application content. Both directions
/// fail closed: a bound SDK service requires exactly one read-only disk at the
/// SDK mount point, and a plan with no SDK binding may not carry one.
pub fn enforce_sdk_sidecar_attachment(
    volumes: &[mvm_core::vm_backend::VmVolume],
    plan: &ExecutionPlan,
    image_libc: GuestLibc,
) -> Result<()> {
    use mvm_core::plan::{SDK_SIDECAR_GUEST_PATH, sdk_host_services_in, sdk_sidecar_required};

    // When sdk_uses_sidecar is false, the workload speaks the broker protocol
    // directly and may not carry the SDK sidecar.
    if !plan.sdk_uses_sidecar {
        let attached: Vec<_> = volumes
            .iter()
            .filter(|v| v.guest == SDK_SIDECAR_GUEST_PATH)
            .collect();
        if let Some(stray) = attached.first() {
            anyhow::bail!(
                "refusing to attach '{}' at {SDK_SIDECAR_GUEST_PATH}: the signed ExecutionPlan \
                 sets sdk_uses_sidecar=false, so this workload must not carry the SDK sidecar",
                stray.host,
            );
        }
        return Ok(());
    }

    let attached: Vec<_> = volumes
        .iter()
        .filter(|v| v.guest == SDK_SIDECAR_GUEST_PATH)
        .collect();
    let required = sdk_sidecar_required(plan);

    if !required {
        if let Some(stray) = attached.first() {
            anyhow::bail!(
                "refusing to attach '{}' at {SDK_SIDECAR_GUEST_PATH}: the signed ExecutionPlan \
                 binds no SDK host service, so this workload must not carry the SDK sidecar",
                stray.host,
            );
        }
        return Ok(());
    }

    let bound: Vec<&str> = sdk_host_services_in(&plan.services)
        .iter()
        .map(|s| s.as_str())
        .collect();

    let Some(sidecar) = attached.first() else {
        anyhow::bail!(
            "refusing to launch: the signed ExecutionPlan binds SDK host service(s) [{}], which \
             need the SDK sidecar mounted read-only at {SDK_SIDECAR_GUEST_PATH}, and no such \
             attachment is present. The launch path resolves the sidecar from the version-keyed \
             cache under the mvm cache dir; prepare it with \
             `mvmctl bootstrap` and retry.",
            bound.join(", "),
        );
    };
    if attached.len() > 1 {
        anyhow::bail!(
            "refusing to launch: {} attachments target {SDK_SIDECAR_GUEST_PATH}; exactly one \
             read-only SDK sidecar is admissible",
            attached.len(),
        );
    }
    if !sidecar.read_only {
        anyhow::bail!(
            "refusing to attach '{}' at {SDK_SIDECAR_GUEST_PATH} read-write: the SDK sidecar is \
             read-only by contract",
            sidecar.host,
        );
    }
    if sidecar.materialized_image.is_some() {
        anyhow::bail!(
            "refusing to attach '{}' at {SDK_SIDECAR_GUEST_PATH}: the SDK sidecar is a read-only \
             disk image, not a host-directory share",
            sidecar.host,
        );
    }
    // The sidecar's own libc comes from the path it was filed under, so both
    // sides of the comparison are observed rather than assumed. Reading it here
    // rather than threading it in keeps this a check on the launch config as
    // presented — the thing admission is actually authorizing.
    let sidecar_libc =
        mvm_build::guest_libc::sidecar_libc_of_image_path(std::path::Path::new(&sidecar.host));
    enforce_sidecar_libc(image_libc, sidecar_libc, &bound)?;
    Ok(())
}

/// Refuse a launch whose SDK sidecar the guest could not load.
///
/// The launch-shaped entry point onto [`enforce_sdk_sidecar_attachment`], for
/// callers that hold a rootfs path and a launch config rather than an
/// `AdmittedPlan`. `mvmctl run` is one: it admits through `admit_for_run`, which
/// does not run the post-admission gates, so without this the only thing
/// standing between a libc mismatch and the guest is nothing at all — the boot
/// succeeds and the workload dies on `dlopen` resolving `_dl_find_object`.
///
/// Takes the rootfs path rather than the libc so the caller cannot supply a
/// libc that disagrees with the image it is about to boot.
pub fn enforce_sdk_sidecar_for_launch(
    rootfs_path: &str,
    volumes: &[mvm_core::vm_backend::VmVolume],
    plan: &ExecutionPlan,
) -> Result<()> {
    enforce_sdk_sidecar_attachment(
        volumes,
        plan,
        mvm_build::guest_libc::recorded_image_libc(std::path::Path::new(rootfs_path)),
    )
}

/// Refuse a sidecar the guest could not load.
///
/// The cdylib inside it is built for one libc, and a process under the other
/// cannot `dlopen` it at all. Left unchecked, the boot succeeds and the failure
/// lands inside the guest as a relocation error naming `_dl_find_object` — a
/// symbol the operator never heard of, from a library they did not ask for.
/// Refusing here is the same outcome, said where it can name the cause.
///
/// [`GuestLibc::Unknown`] refuses too. It covers an image whose loader was
/// unrecognisable and a sidecar written before the field existed, and neither
/// is evidence that loading would work.
fn enforce_sidecar_libc(
    image_libc: GuestLibc,
    sidecar_libc: GuestLibc,
    bound: &[&str],
) -> Result<()> {
    if mvm_build::guest_libc::sidecar_loads_in(image_libc, sidecar_libc) {
        return Ok(());
    }
    let detail = match (image_libc, sidecar_libc) {
        (GuestLibc::Unknown, _) => {
            "the image records no libc this host recognises. An image materialized before mvm \
             began recording it reads this way — re-pull or rebuild it and the sidecar is \
             rewritten with the libc"
        }
        (_, GuestLibc::Unknown) => {
            "the attached sidecar is not filed under a libc this host recognises, so which \
             variant it holds cannot be established. Prepare the cache with \
             `mvmctl bootstrap`, which files each variant under its own libc"
        }
        _ => {
            "a process under one libc cannot dlopen an object built for the other — the guest \
             would fail resolving symbols such as `_dl_find_object`"
        }
    };
    anyhow::bail!(
        "refusing to launch: the signed ExecutionPlan binds SDK host service(s) [{}], which are \
         delivered by a shared object built for {}, but this image is {}. {detail}. Use an image \
         whose libc matches, or drop the host-service binding.",
        bound.join(", "),
        sidecar_libc.as_str(),
        image_libc.as_str(),
    )
}
