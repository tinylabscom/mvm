//! The Rust-owned registry of SDK error types.
//!
//! Both language SDKs mirror this hierarchy, and until now they mirrored
//! it by hand. The host-services half was the worst case: the status
//! codes live in [`crate::host_services_ffi`], and both SDKs re-declared
//! them as literals under a comment asking a human to keep them matching.
//! They had already drifted in the prose — the Rust doc for
//! `MVM_HSVC_BAD_REQUEST` says "audit cap" where the TypeScript copy says
//! "e.g. the 4 KiB audit cap" — which is harmless here and would not be
//! if it happened to a status number.
//!
//! Each entry declares which language surfaces carry it, for the same
//! reason [`crate::env`] does: a type is generated into a language only
//! when that language can actually express it.

use crate::env::Surface;

/// What a generated type extends.
///
/// Python distinguishes `Exception` from `RuntimeError` from
/// `UserWarning`; JavaScript has only `Error`. Recording the intent
/// rather than a per-language literal lets each emitter map it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorBase {
    /// The language's generic exception root — Python `Exception`,
    /// TypeScript `Error`.
    Root,
    /// Python `RuntimeError`. TypeScript has no distinct runtime-error
    /// class, so this also lands on `Error`.
    Runtime,
    /// Python `UserWarning`, raised through the `warnings` module.
    /// JavaScript has no warning type at all, which is why every entry
    /// using this base is Python-only.
    Warning,
    /// Another entry in this registry, by name.
    Named(&'static str),
}

impl ErrorBase {
    /// The Python base-class expression.
    pub const fn python(self) -> &'static str {
        match self {
            ErrorBase::Root => "Exception",
            ErrorBase::Runtime => "RuntimeError",
            ErrorBase::Warning => "UserWarning",
            ErrorBase::Named(name) => name,
        }
    }

    /// The TypeScript base-class expression. `Warning` has no faithful
    /// mapping; entries using it are not emitted into TypeScript, and
    /// [`SdkErrorType::exports_to`] enforces that rather than trusting
    /// the declaration.
    pub const fn typescript(self) -> &'static str {
        match self {
            ErrorBase::Root | ErrorBase::Runtime | ErrorBase::Warning => "Error",
            ErrorBase::Named(name) => name,
        }
    }
}

/// One error type in the SDK contract.
#[derive(Debug, Clone, Copy)]
pub struct SdkErrorType {
    /// Class name, identical in every language.
    pub name: &'static str,
    /// What it extends.
    pub base: ErrorBase,
    /// One-line description, rendered as a doc comment.
    pub doc: &'static str,
    /// The `MVM_HSVC_*` status this type is raised for, if any.
    pub status: Option<i32>,
    /// Surfaces that carry this type.
    pub surfaces: &'static [Surface],
}

impl SdkErrorType {
    /// Whether this type is emitted for `surface`.
    pub fn exports_to(&self, surface: Surface) -> bool {
        // A warning has no JavaScript form; refuse it here so a
        // mis-declared row fails the unit test rather than emitting a
        // class that silently is not a warning.
        if surface == Surface::TypeScript && matches!(self.base, ErrorBase::Warning) {
            return false;
        }
        let mut i = 0;
        while i < self.surfaces.len() {
            if self.surfaces[i] as u8 == surface as u8 {
                return true;
            }
            i += 1;
        }
        false
    }
}

macro_rules! sdk_errors {
    ($(
        $(#[doc = $doc:literal])+
        $name:ident : $base:expr $(, status = $status:expr)? ; [$($surface:ident),+ $(,)?]
    )+) => {
        /// Every SDK error type, in declaration order. Base classes
        /// precede their subclasses, which the emitters rely on.
        pub const REGISTRY: &[SdkErrorType] = &[
            $(
                SdkErrorType {
                    name: stringify!($name),
                    base: $base,
                    doc: concat!($($doc),+),
                    status: sdk_errors!(@status $($status)?),
                    surfaces: &[$(Surface::$surface),+],
                },
            )+
        ];
    };
    (@status $status:expr) => { Some($status) };
    (@status) => { None };
}

sdk_errors! {
    /// Base of every typed host-services failure.
    HostServiceError: ErrorBase::Root; [Rust, Python, TypeScript]

    /// The host rejected the record shape or size (audit cap).
    BadRequestError: ErrorBase::Named("HostServiceError"),
        status = crate::host_services_ffi::MVM_HSVC_BAD_REQUEST; [Rust, Python, TypeScript]

    /// The per-workload audit emit rate limit is exhausted.
    RateLimitedError: ErrorBase::Named("HostServiceError"),
        status = crate::host_services_ffi::MVM_HSVC_RATE_LIMITED; [Rust, Python, TypeScript]

    /// The host could not answer (handler down, broker not ready).
    UnavailableError: ErrorBase::Named("HostServiceError"),
        status = crate::host_services_ffi::MVM_HSVC_UNAVAILABLE; [Rust, Python, TypeScript]

    /// The workload's `ExecutionPlan.services` did not bind the service.
    NotBoundError: ErrorBase::Named("HostServiceError"),
        status = crate::host_services_ffi::MVM_HSVC_NOT_BOUND; [Rust, Python, TypeScript]

    /// The verb is not implemented in this build.
    VerbNotImplementedError: ErrorBase::Named("HostServiceError"),
        status = crate::host_services_ffi::MVM_HSVC_NOT_IMPLEMENTED; [Rust, Python, TypeScript]

    /// Any other typed broker error code.
    ServiceError: ErrorBase::Named("HostServiceError"),
        status = crate::host_services_ffi::MVM_HSVC_SERVICE; [Rust, Python, TypeScript]

    /// Connect, framing, or (de)serialization failure on the vsock path.
    TransportError: ErrorBase::Named("HostServiceError"),
        status = crate::host_services_ffi::MVM_HSVC_TRANSPORT; [Rust, Python, TypeScript]

    /// The request was malformed: unknown method or a body the verb rejects.
    InvalidInputError: ErrorBase::Named("HostServiceError"),
        status = crate::host_services_ffi::MVM_HSVC_INVALID_INPUT; [Rust, Python, TypeScript]
}

/// The success status. Not an error, so it has no registry row — but it
/// belongs to the same `MVM_HSVC_*` family the SDKs mirrored by hand, and
/// generating the map while leaving this behind would leave the mirror
/// half-alive.
pub const STATUS_OK: i32 = crate::host_services_ffi::MVM_HSVC_OK;

/// The status → error-type mapping, in registry order. `MVM_HSVC_OK` has
/// no entry: it is not a failure.
pub fn status_mapping() -> impl Iterator<Item = (i32, &'static str)> {
    REGISTRY
        .iter()
        .filter_map(|e| e.status.map(|status| (status, e.name)))
}

/// The registry rows `surface` carries, in declaration order.
pub fn exported_to(surface: Surface) -> impl Iterator<Item = &'static SdkErrorType> {
    REGISTRY.iter().filter(move |e| e.exports_to(surface))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn every_status_maps_to_exactly_one_type() {
        let mut seen = BTreeSet::new();
        for (status, name) in status_mapping() {
            assert!(
                seen.insert(status),
                "status {status} mapped twice (at {name})"
            );
        }
        // Every non-OK MVM_HSVC_* code must be reachable, or a broker
        // failure would surface as an untyped fallback.
        let expected: BTreeSet<i32> = (1..=8).collect();
        assert_eq!(seen, expected, "status coverage gap");
    }

    #[test]
    fn ok_is_not_an_error_type() {
        assert!(
            !status_mapping().any(|(status, _)| status == crate::host_services_ffi::MVM_HSVC_OK),
            "MVM_HSVC_OK must not map to an error type"
        );
    }

    #[test]
    fn named_bases_resolve_within_the_registry() {
        let names: BTreeSet<&str> = REGISTRY.iter().map(|e| e.name).collect();
        for e in REGISTRY {
            if let ErrorBase::Named(base) = e.base {
                assert!(
                    names.contains(base),
                    "{}: base {base} not in registry",
                    e.name
                );
            }
        }
    }

    #[test]
    fn a_base_is_declared_before_its_subclasses() {
        // Both emitters render in registry order, so a subclass appearing
        // first would produce source that does not evaluate.
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        for e in REGISTRY {
            if let ErrorBase::Named(base) = e.base {
                assert!(seen.contains(base), "{} precedes its base {base}", e.name);
            }
            seen.insert(e.name);
        }
    }

    #[test]
    fn names_are_unique() {
        let mut names = BTreeSet::new();
        for e in REGISTRY {
            assert!(names.insert(e.name), "duplicate error name {}", e.name);
        }
    }

    #[test]
    fn a_warning_is_never_emitted_into_typescript() {
        // JavaScript has no warning type; claiming one would be the same
        // dishonesty as exporting a constant nothing reads.
        for e in REGISTRY {
            if matches!(e.base, ErrorBase::Warning) {
                assert!(
                    !e.exports_to(Surface::TypeScript),
                    "{} is a warning and cannot exist in TypeScript",
                    e.name
                );
            }
        }
    }

    #[test]
    fn status_docs_match_the_ffi_constants() {
        // The registry is the single source; this pins the numbers to the
        // FFI constants rather than to literals copied beside them.
        let by_name = |n: &str| REGISTRY.iter().find(|e| e.name == n).unwrap();
        assert_eq!(
            by_name("BadRequestError").status,
            Some(crate::host_services_ffi::MVM_HSVC_BAD_REQUEST)
        );
        assert_eq!(
            by_name("InvalidInputError").status,
            Some(crate::host_services_ffi::MVM_HSVC_INVALID_INPUT)
        );
    }
}
