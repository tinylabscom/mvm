//! The Rust-owned registry of SDK error types.
//!
//! Both language SDKs mirror this hierarchy, and until now they mirrored
//! it by hand. The host-services half was the worst case: the status
//! codes live in [`mvm_host_services`], and both SDKs re-declared
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

/// A structured field an error carries alongside its message.
#[derive(Debug, Clone, Copy)]
pub struct ErrorField {
    /// Attribute name, identical in every language.
    pub name: &'static str,
    /// One-line description.
    pub doc: &'static str,
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
    /// The error code (`mvm_core::error_codes`) a host-library error body
    /// carries when this type is raised, if any. Keyed by code rather than
    /// status because the host-library statuses reuse the host-services
    /// numbers.
    pub code: Option<&'static str>,
    /// Surfaces that carry this type.
    pub surfaces: &'static [Surface],
    /// Structured fields the type carries. Empty for a plain subclass.
    pub fields: &'static [ErrorField],
    /// How the human-readable message is composed from those fields,
    /// with `{field}` placeholders. Required when `fields` is non-empty.
    pub message_format: Option<&'static str>,
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
                    code: None,
                    surfaces: &[$(Surface::$surface),+],
                    fields: &[],
                    message_format: None,
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
        status = mvm_host_services::MVM_HSVC_BAD_REQUEST; [Rust, Python, TypeScript]

    /// The per-workload audit emit rate limit is exhausted.
    RateLimitedError: ErrorBase::Named("HostServiceError"),
        status = mvm_host_services::MVM_HSVC_RATE_LIMITED; [Rust, Python, TypeScript]

    /// The host could not answer (handler down, broker not ready).
    UnavailableError: ErrorBase::Named("HostServiceError"),
        status = mvm_host_services::MVM_HSVC_UNAVAILABLE; [Rust, Python, TypeScript]

    /// The workload's `ExecutionPlan.services` did not bind the service.
    NotBoundError: ErrorBase::Named("HostServiceError"),
        status = mvm_host_services::MVM_HSVC_NOT_BOUND; [Rust, Python, TypeScript]

    /// The verb is not implemented in this build.
    VerbNotImplementedError: ErrorBase::Named("HostServiceError"),
        status = mvm_host_services::MVM_HSVC_NOT_IMPLEMENTED; [Rust, Python, TypeScript]

    /// Any other typed broker error code.
    ServiceError: ErrorBase::Named("HostServiceError"),
        status = mvm_host_services::MVM_HSVC_SERVICE; [Rust, Python, TypeScript]

    /// Connect, framing, or (de)serialization failure on the vsock path.
    TransportError: ErrorBase::Named("HostServiceError"),
        status = mvm_host_services::MVM_HSVC_TRANSPORT; [Rust, Python, TypeScript]

    /// The request was malformed: unknown method or a body the verb rejects.
    InvalidInputError: ErrorBase::Named("HostServiceError"),
        status = mvm_host_services::MVM_HSVC_INVALID_INPUT; [Rust, Python, TypeScript]
}

/// The errors Tier C's remote-invocation machinery raises.
///
/// Declared separately from the `sdk_errors!` block because
/// `RemoteError` carries structured fields, which that macro does not
/// express. They are emitted for TypeScript only because Tier C's
/// transport exists there to raise them — generating them earlier would
/// have exported classes nothing could throw.
const TIER_C: &[SdkErrorType] = &[
    SdkErrorType {
        name: "RemoteError",
        base: ErrorBase::Root,
        doc: "User code inside the VM raised; a structured envelope was parsed.",
        status: None,
        code: None,
        surfaces: &[Surface::Rust, Surface::Python, Surface::TypeScript],
        fields: &[
            ErrorField {
                name: "kind",
                doc: "Error class the guest reported.",
            },
            ErrorField {
                name: "error_id",
                doc: "Correlation id for the failing call.",
            },
            ErrorField {
                name: "message",
                doc: "Message the guest reported.",
            },
        ],
        message_format: Some("{kind}: {message} (error_id={error_id})"),
    },
    SdkErrorType {
        name: "MvmTransportError",
        base: ErrorBase::Runtime,
        doc: "Could not reach the substrate, or got an unparseable response.",
        status: None,
        code: None,
        surfaces: &[Surface::Rust, Surface::Python, Surface::TypeScript],
        fields: &[],
        message_format: None,
    },
    SdkErrorType {
        name: "MsgpackUnavailable",
        base: ErrorBase::Runtime,
        doc: "The workload declared msgpack but the SDK has no msgpack support.",
        status: None,
        code: None,
        surfaces: &[Surface::Rust, Surface::Python, Surface::TypeScript],
        fields: &[],
        message_format: None,
    },
    SdkErrorType {
        name: "PayloadTooLarge",
        base: ErrorBase::Named("MvmTransportError"),
        doc: "The encoded request exceeded the payload cap, refused before               anything was sent.",
        status: None,
        code: None,
        surfaces: &[Surface::Rust, Surface::Python, Surface::TypeScript],
        fields: &[],
        message_format: None,
    },
    SdkErrorType {
        name: "NoVmIntrospectionError",
        base: ErrorBase::Named("MvmTransportError"),
        doc: "No-VM dispatch was requested without a local function to               introspect. Python-only in practice: the mode itself has no               TypeScript form.",
        status: None,
        code: None,
        surfaces: &[Surface::Rust, Surface::Python, Surface::TypeScript],
        fields: &[],
        message_format: None,
    },
    SdkErrorType {
        name: "SecretInArgError",
        base: ErrorBase::Runtime,
        doc: "A secret-shaped value was passed as a call argument under strict               mode.",
        status: None,
        code: None,
        surfaces: &[Surface::Rust, Surface::Python, Surface::TypeScript],
        fields: &[],
        message_format: None,
    },
    SdkErrorType {
        name: "SecretInArgWarning",
        base: ErrorBase::Warning,
        doc: "Heuristic flagged a secret-shaped value passed as a call               argument.",
        status: None,
        code: None,
        // Python-only, permanently: JavaScript has no warning type, and
        // `exports_to` refuses to emit a `Warning` into TypeScript.
        surfaces: &[Surface::Rust, Surface::Python],
        fields: &[],
        message_format: None,
    },
    SdkErrorType {
        name: "EmittingContextError",
        base: ErrorBase::Runtime,
        doc: "A transport call fired while `mvm emit` was running the script to               lower its declarations, where no live microVM exists.",
        status: None,
        code: None,
        surfaces: &[Surface::Rust, Surface::Python, Surface::TypeScript],
        fields: &[],
        message_format: None,
    },
];

/// The errors the host library reports, keyed by the code its error body
/// carries. Python only for now: the Python binding is the surface that
/// raises them.
const HOST_LIBRARY: &[SdkErrorType] = &[
    host_library_base(),
    host_library_error(
        "MachineNotFoundError",
        "The machine named does not exist.",
        mvm_core::error_codes::NOT_FOUND,
    ),
    host_library_error(
        "MachineSpecError",
        "The request described a machine that cannot be built.",
        mvm_core::error_codes::INVALID_SPEC,
    ),
    host_library_error(
        "MachineBackendError",
        "The backend failed while carrying the request out.",
        mvm_core::error_codes::BACKEND_ERROR,
    ),
    host_library_error(
        "MachineUnauthorizedError",
        "The caller is not allowed to do this.",
        mvm_core::error_codes::UNAUTHORIZED,
    ),
    host_library_error(
        "MachineConflictError",
        "The request conflicts with the machine's current state.",
        mvm_core::error_codes::CONFLICT,
    ),
    host_library_error(
        "MachineRejectedError",
        "A policy refused the request.",
        mvm_core::error_codes::REJECTED,
    ),
    host_library_error(
        "MachineUnavailableError",
        "The backend cannot answer right now; the request may be retried.",
        mvm_core::error_codes::UNAVAILABLE,
    ),
    host_library_error(
        "HostLibraryInputError",
        "The method is unknown or its request did not parse.",
        mvm_core::error_codes::INVALID_INPUT,
    ),
    host_library_error(
        "HostLibraryAbiError",
        "The library and this binding disagree about the ABI version.",
        mvm_core::error_codes::ABI_NOT_NEGOTIATED,
    ),
    host_library_error(
        "HostLibraryEmbedderError",
        "The library could not set itself up in this process.",
        mvm_core::error_codes::EMBEDDER,
    ),
    host_library_error(
        "HostLibraryInternalError",
        "A fault inside the host library itself.",
        mvm_core::error_codes::INTERNAL,
    ),
];

const fn host_library_base() -> SdkErrorType {
    SdkErrorType {
        name: "HostLibraryError",
        base: ErrorBase::Root,
        doc: "Base of every error the host library reports.",
        status: None,
        code: None,
        surfaces: &[Surface::Rust, Surface::Python, Surface::TypeScript],
        fields: &[],
        message_format: None,
    }
}

const fn host_library_error(
    name: &'static str,
    doc: &'static str,
    code: &'static str,
) -> SdkErrorType {
    SdkErrorType {
        name,
        base: ErrorBase::Named("HostLibraryError"),
        doc,
        status: None,
        code: Some(code),
        surfaces: &[Surface::Rust, Surface::Python, Surface::TypeScript],
        fields: &[],
        message_format: None,
    }
}

/// The success status. Not an error, so it has no registry row — but it
/// belongs to the same `MVM_HSVC_*` family the SDKs mirrored by hand, and
/// generating the map while leaving this behind would leave the mirror
/// half-alive.
pub const STATUS_OK: i32 = mvm_host_services::MVM_HSVC_OK;

/// The status → error-type mapping, in registry order. `MVM_HSVC_OK` has
/// no entry: it is not a failure.
pub fn status_mapping() -> impl Iterator<Item = (i32, &'static str)> {
    REGISTRY
        .iter()
        .filter_map(|e| e.status.map(|status| (status, e.name)))
}

/// The code → error-type mapping, in registry order.
pub fn code_mapping() -> impl Iterator<Item = (&'static str, &'static str)> {
    all().filter_map(|e| e.code.map(|code| (code, e.name)))
}

/// Every error type: the host-services family, Tier C's, then the host
/// library's.
pub fn all() -> impl Iterator<Item = &'static SdkErrorType> {
    REGISTRY
        .iter()
        .chain(TIER_C.iter())
        .chain(HOST_LIBRARY.iter())
}

/// The rows `surface` carries, in declaration order.
pub fn exported_to(surface: Surface) -> impl Iterator<Item = &'static SdkErrorType> {
    all().filter(move |e| e.exports_to(surface))
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

    /// Every code a host-library error body can carry has exactly one type,
    /// so no failure the library reports surfaces as an untyped fallback.
    #[test]
    fn every_host_library_code_maps_to_exactly_one_type() {
        use mvm_core::error_codes as c;
        let codes: Vec<&str> = code_mapping().map(|(code, _)| code).collect();
        let unique: BTreeSet<&str> = codes.iter().copied().collect();
        assert_eq!(codes.len(), unique.len(), "a code is mapped twice");
        let expected: BTreeSet<&str> = [
            c::NOT_FOUND,
            c::INVALID_SPEC,
            c::BACKEND_ERROR,
            c::UNAUTHORIZED,
            c::CONFLICT,
            c::REJECTED,
            c::UNAVAILABLE,
            c::INVALID_INPUT,
            c::ABI_NOT_NEGOTIATED,
            c::EMBEDDER,
            c::INTERNAL,
        ]
        .into_iter()
        .collect();
        assert_eq!(unique, expected);
    }

    /// A type is keyed by a status or by a code, never both: the two maps
    /// answer different transports.
    #[test]
    fn no_type_carries_both_a_status_and_a_code() {
        for e in all() {
            assert!(
                e.status.is_none() || e.code.is_none(),
                "{} has both a status and a code",
                e.name
            );
        }
    }

    #[test]
    fn ok_is_not_an_error_type() {
        assert!(
            !status_mapping().any(|(status, _)| status == mvm_host_services::MVM_HSVC_OK),
            "MVM_HSVC_OK must not map to an error type"
        );
    }

    #[test]
    fn a_structured_error_declares_how_its_message_is_built() {
        for e in all() {
            if e.fields.is_empty() {
                assert!(
                    e.message_format.is_none(),
                    "{}: message_format without fields",
                    e.name
                );
            } else {
                let format = e
                    .message_format
                    .unwrap_or_else(|| panic!("{}: fields without a message_format", e.name));
                for f in e.fields {
                    assert!(
                        format.contains(&format!("{{{}}}", f.name)),
                        "{}: field {} is never interpolated",
                        e.name,
                        f.name
                    );
                }
            }
        }
    }

    #[test]
    fn tier_c_errors_are_registered() {
        let names: BTreeSet<&str> = all().map(|e| e.name).collect();
        for expected in [
            "RemoteError",
            "MvmTransportError",
            "MsgpackUnavailable",
            "PayloadTooLarge",
            "NoVmIntrospectionError",
            "SecretInArgError",
            "SecretInArgWarning",
            "EmittingContextError",
        ] {
            assert!(names.contains(expected), "Tier C is missing {expected}");
        }
    }

    #[test]
    fn named_bases_resolve_within_the_registry() {
        let names: BTreeSet<&str> = all().map(|e| e.name).collect();
        for e in all() {
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
        for e in all() {
            if let ErrorBase::Named(base) = e.base {
                assert!(seen.contains(base), "{} precedes its base {base}", e.name);
            }
            seen.insert(e.name);
        }
    }

    #[test]
    fn names_are_unique() {
        let mut names = BTreeSet::new();
        for e in all() {
            assert!(names.insert(e.name), "duplicate error name {}", e.name);
        }
    }

    #[test]
    fn a_warning_is_never_emitted_into_typescript() {
        // JavaScript has no warning type; claiming one would be the same
        // dishonesty as exporting a constant nothing reads.
        for e in all() {
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
            Some(mvm_host_services::MVM_HSVC_BAD_REQUEST)
        );
        assert_eq!(
            by_name("InvalidInputError").status,
            Some(mvm_host_services::MVM_HSVC_INVALID_INPUT)
        );
    }
}
