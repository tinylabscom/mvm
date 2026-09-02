//! Which admitted workloads need the optional glibc SDK sidecar attached.
//!
//! The language SDKs reach the host-services broker through one glibc cdylib
//! (`libmvm_host_services.so`) that the workload process `dlopen`s. That cdylib
//! and its loader closure are deliberately **not** part of the base rootfs or
//! the static-musl runtime overlay — carrying them everywhere would drag glibc
//! back into every guest's footprint. They ship as a separate read-only
//! sidecar image that is attached only to the workloads that can actually use
//! it.
//!
//! "Can actually use it" is decided here, from the signed plan's host-service
//! bindings and nothing else. Not from an environment variable a guest could
//! set, not from scanning application source for an `import mvm`: a workload
//! that was never bound to an SDK-served host service gets no sidecar, and a
//! workload that was bound to one gets it read-only. The binding set is the
//! same one the broker's dispatch gate enforces, so the attachment decision and
//! the call-time authorization can never disagree.

use alloc::vec::Vec;

use crate::plan::execution_plan::ExecutionPlan;
use crate::protocol::broker::ServiceId;

/// Absolute guest path the SDK sidecar is mounted at, read-only. The language
/// SDKs default their cdylib lookup to `<this>/lib/libmvm_host_services.so`.
pub const SDK_SIDECAR_GUEST_PATH: &str = "/mvm/sdk";

/// Path of the cdylib inside the sidecar image, relative to its filesystem
/// root. The resolver proves this exists before an attachment is offered, so a
/// truncated or wrong-payload sidecar fails closed instead of surfacing as an
/// in-guest `dlopen` error the workload can't act on.
pub const SDK_SIDECAR_LIB_PATH: &str = "/lib/libmvm_host_services.so";

/// The host services the SDK cdylib serves. A plan bound to any of these needs
/// the sidecar; a plan bound to none of them does not.
///
/// Sorted so the slice can be scanned or bisected without re-sorting, and so a
/// reviewer sees the whole SDK-reachable surface in one place. `broker.v1` is
/// deliberately absent: it is the meta service the transport itself speaks, not
/// a verb the SDK exposes to workload code.
pub const SDK_HOST_SERVICES: [&str; 5] = [
    "host.audit.v1",
    "host.cost.v1",
    "host.kv.v1",
    "host.secrets.v1",
    "host.time.v1",
];

/// Whether `service` is one of the host services reachable through the SDK
/// cdylib.
#[must_use]
pub fn is_sdk_host_service(service: &ServiceId) -> bool {
    SDK_HOST_SERVICES.contains(&service.as_str())
}

/// The SDK-served subset of `services`, in the order the plan listed them.
/// Callers surface this in the non-secret error when a required sidecar is
/// unavailable, so an operator can see exactly which binding demanded it.
#[must_use]
pub fn sdk_host_services_in(services: &[ServiceId]) -> Vec<&ServiceId> {
    services.iter().filter(|s| is_sdk_host_service(s)).collect()
}

/// Whether a workload bound to `services` needs the SDK sidecar attached.
/// The `sdk_uses_sidecar` flag allows workloads that can speak the broker
/// protocol directly (e.g., Python with AF_VSOCK, Go with golang.org/x/sys/unix)
/// to opt out of the glibc sidecar even when bound to SDK services.
#[must_use]
pub fn sdk_sidecar_required_for(services: &[ServiceId], sdk_uses_sidecar: bool) -> bool {
    sdk_uses_sidecar && services.iter().any(is_sdk_host_service)
}

/// Whether `plan` needs the SDK sidecar attached. The single question every
/// attachment site and every admission gate asks, so the answer cannot drift
/// between them.
#[must_use]
pub fn sdk_sidecar_required(plan: &ExecutionPlan) -> bool {
    sdk_sidecar_required_for(&plan.services, plan.sdk_uses_sidecar)
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    fn svc(raw: &str) -> ServiceId {
        ServiceId::parse(raw).expect("fixture service id parses")
    }

    #[test]
    fn no_services_needs_no_sidecar() {
        assert!(!sdk_sidecar_required_for(&[], true));
        assert!(sdk_host_services_in(&[]).is_empty());
    }

    #[test]
    fn every_sdk_host_service_requires_the_sidecar() {
        for id in SDK_HOST_SERVICES {
            let bound = vec![svc(id)];
            assert!(
                sdk_sidecar_required_for(&bound, true),
                "{id} must require the SDK sidecar"
            );
            assert!(is_sdk_host_service(&svc(id)));
        }
    }

    #[test]
    fn unrelated_bindings_do_not_require_the_sidecar() {
        // `broker.v1` is the transport's own meta service, and a
        // non-SDK-served host service must not pull in the glibc closure.
        let bound = vec![svc("broker.v1"), svc("host.frobnicate.v1")];
        assert!(!sdk_sidecar_required_for(&bound, true));
        assert!(sdk_host_services_in(&bound).is_empty());
    }

    #[test]
    fn a_version_bump_of_an_sdk_service_is_not_assumed_compatible() {
        // Only the exact versioned ids the cdylib serves count. A future
        // `host.audit.v2` must be added deliberately, not inherited.
        assert!(!sdk_sidecar_required_for(&[svc("host.audit.v2")], true));
    }

    #[test]
    fn one_sdk_binding_among_unrelated_ones_still_requires_the_sidecar() {
        let bound = vec![svc("broker.v1"), svc("host.time.v1"), svc("host.other.v1")];
        assert!(sdk_sidecar_required_for(&bound, true));
        let matched = sdk_host_services_in(&bound);
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].as_str(), "host.time.v1");
    }

    #[test]
    fn sdk_host_services_in_preserves_plan_order() {
        let bound = vec![svc("host.time.v1"), svc("host.audit.v1")];
        let matched = sdk_host_services_in(&bound);
        assert_eq!(
            matched.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
            ["host.time.v1", "host.audit.v1"],
            "the reported order must mirror the plan, not the constant"
        );
    }

    #[test]
    fn sdk_host_services_constant_is_sorted_and_unique() {
        let mut sorted = SDK_HOST_SERVICES;
        sorted.sort_unstable();
        assert_eq!(sorted, SDK_HOST_SERVICES, "keep the constant sorted");
        for pair in SDK_HOST_SERVICES.windows(2) {
            assert_ne!(pair[0], pair[1], "duplicate entry in SDK_HOST_SERVICES");
        }
    }

    #[test]
    fn every_sdk_host_service_id_is_well_formed() {
        for id in SDK_HOST_SERVICES {
            assert!(
                ServiceId::parse(id).is_ok(),
                "{id} must be a parseable service id"
            );
        }
    }

    #[test]
    fn guest_paths_are_absolute() {
        assert!(SDK_SIDECAR_GUEST_PATH.starts_with('/'));
        assert!(SDK_SIDECAR_LIB_PATH.starts_with('/'));
    }

    /// The store is reachable from workload code only if the sidecar carrying
    /// the cdylib is attached. Binding the service and *not* getting the
    /// library is the shape that made it host-side-only: the handler
    /// registered, the guest had nothing to call it with, and the docs claimed
    /// a workload could use it.
    #[test]
    fn binding_the_key_value_store_attaches_the_sidecar() {
        assert!(sdk_sidecar_required_for(&[svc("host.kv.v1")], true));
        assert!(is_sdk_host_service(&svc("host.kv.v1")));
    }

    /// The list is sorted so a reviewer sees the whole SDK-reachable surface
    /// at a glance and a new entry cannot hide in the middle.
    #[test]
    fn the_sdk_host_service_list_stays_sorted() {
        let mut sorted = SDK_HOST_SERVICES;
        sorted.sort_unstable();
        assert_eq!(SDK_HOST_SERVICES, sorted);
    }
}
