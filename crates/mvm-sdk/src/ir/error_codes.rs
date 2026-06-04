use serde::{Serialize, Serializer};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    UnsupportedMajor,
    MinorTooHigh,
    MalformedVersion,
    UnknownField,
    MalformedManifest,
    EmptyApps,
    MultiAppDeferred,
    SourceKindDeferred,
    SecretsNotImplemented,
    PersistDeferred,
    NetworkPortsWithNone,
    CompileOutputExistsNotDir,
    CompileStagingFailed,
    CompileArchiveFailed,
    MvmNotFound,
    SourcePathNotFound,
    SourcePathNotDir,
    SourceCopyFailed,
    SourceGlobInvalid,
    SourceOutOfTreeSymlink,
    MvmVersionTooOld,
    NetworkWildcard,
    InvalidId,
    UnpinnedDeps,
    LockfileNotFound,
    DepsRequiredForFunctionWorkload,
    SecretInSchema,
    FunctionNetworkHostForbidden,
    UnsupportedLanguage,
    NoPrimaryEntrypoint,
    MultiplePrimaryEntrypoints,
    DuplicateEntrypointFunction,
    FunctionNotFound,
    FunctionSchemaMismatch,
    InvalidConcurrencyPoolSize,
    InvalidConcurrencyMaxCallsPerWorker,
    InvalidConcurrencyMaxRssMb,
    UnsupportedConcurrencyInProcessMode,
    UnsupportedConcurrencyForLanguage,
    // Addon error codes (ADR-0018). Mvmforge-side codes are the
    // compile-time-checkable rules (validate.rs + addon::resolve_and_validate
    // + sigstore-keyless verification); mvmd-side codes (ROOTHASH_MISMATCH,
    // EGRESS_VIOLATION, QUOTA_EXCEEDED, TENANT_NAMESPACE_DENIED,
    // SECCOMP_PROFILE_DENIED) are emitted at instance-start time but
    // registered here per ADR-0004 (single source of truth for error codes).
    AddonLockfileMissing,
    AddonLockfileSignatureInvalid,
    AddonShaMismatch,
    AddonSignatureInvalid,
    AddonParamInvalid,
    AddonEnvCollision,
    AddonRegistryUnreachable,
    AddonLocalPathDrift,
    AddonLocalPathInPublish,
    AddonNixParseError,
    AddonEgressViolation,
    AddonQuotaExceeded,
    AddonTyposquatBlocked,
    AddonTenantNamespaceDenied,
    AddonReproducibilityFailed,
    AddonRoothashMismatch,
    AddonTierNotImplemented,
    AddonSeccompProfileDenied,
    AddonNotFound,
}

impl ErrorCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::UnsupportedMajor => "E_UNSUPPORTED_MAJOR",
            Self::MinorTooHigh => "E_MINOR_TOO_HIGH",
            Self::MalformedVersion => "E_MALFORMED_VERSION",
            Self::UnknownField => "E_UNKNOWN_FIELD",
            Self::MalformedManifest => "E_MALFORMED_MANIFEST",
            Self::EmptyApps => "E_EMPTY_APPS",
            Self::MultiAppDeferred => "E_MULTI_APP_DEFERRED",
            Self::SourceKindDeferred => "E_SOURCE_KIND_DEFERRED",
            Self::SecretsNotImplemented => "E_SECRETS_NOT_IMPLEMENTED",
            Self::PersistDeferred => "E_PERSIST_DEFERRED",
            Self::NetworkPortsWithNone => "E_NETWORK_PORTS_WITH_NONE",
            Self::CompileOutputExistsNotDir => "E_COMPILE_OUTPUT_EXISTS_NOT_DIR",
            Self::CompileStagingFailed => "E_COMPILE_STAGING_FAILED",
            Self::CompileArchiveFailed => "E_COMPILE_ARCHIVE_FAILED",
            Self::MvmNotFound => "E_MVM_NOT_FOUND",
            Self::SourcePathNotFound => "E_SOURCE_PATH_NOT_FOUND",
            Self::SourcePathNotDir => "E_SOURCE_PATH_NOT_DIR",
            Self::SourceCopyFailed => "E_SOURCE_COPY_FAILED",
            Self::SourceGlobInvalid => "E_SOURCE_GLOB_INVALID",
            Self::SourceOutOfTreeSymlink => "E_SOURCE_OUT_OF_TREE_SYMLINK",
            Self::MvmVersionTooOld => "E_MVM_VERSION_TOO_OLD",
            Self::NetworkWildcard => "E_NETWORK_WILDCARD",
            Self::InvalidId => "E_INVALID_ID",
            Self::UnpinnedDeps => "E_UNPINNED_DEPS",
            Self::LockfileNotFound => "E_LOCKFILE_NOT_FOUND",
            Self::DepsRequiredForFunctionWorkload => "E_DEPS_REQUIRED_FOR_FUNCTION_WORKLOAD",
            Self::SecretInSchema => "E_SECRET_IN_SCHEMA",
            Self::FunctionNetworkHostForbidden => "E_FUNCTION_NETWORK_HOST_FORBIDDEN",
            Self::UnsupportedLanguage => "E_UNSUPPORTED_LANGUAGE",
            Self::NoPrimaryEntrypoint => "E_NO_PRIMARY_ENTRYPOINT",
            Self::MultiplePrimaryEntrypoints => "E_MULTIPLE_PRIMARY_ENTRYPOINTS",
            Self::DuplicateEntrypointFunction => "E_DUPLICATE_ENTRYPOINT_FUNCTION",
            Self::FunctionNotFound => "E_FUNCTION_NOT_FOUND",
            Self::FunctionSchemaMismatch => "E_FUNCTION_SCHEMA_MISMATCH",
            Self::InvalidConcurrencyPoolSize => "E_INVALID_CONCURRENCY_POOL_SIZE",
            Self::InvalidConcurrencyMaxCallsPerWorker => {
                "E_INVALID_CONCURRENCY_MAX_CALLS_PER_WORKER"
            }
            Self::InvalidConcurrencyMaxRssMb => "E_INVALID_CONCURRENCY_MAX_RSS_MB",
            Self::UnsupportedConcurrencyInProcessMode => {
                "E_UNSUPPORTED_CONCURRENCY_IN_PROCESS_MODE"
            }
            Self::UnsupportedConcurrencyForLanguage => "E_UNSUPPORTED_CONCURRENCY_FOR_LANGUAGE",
            Self::AddonLockfileMissing => "E_ADDON_LOCKFILE_MISSING",
            Self::AddonLockfileSignatureInvalid => "E_ADDON_LOCKFILE_SIGNATURE_INVALID",
            Self::AddonShaMismatch => "E_ADDON_SHA_MISMATCH",
            Self::AddonSignatureInvalid => "E_ADDON_SIGNATURE_INVALID",
            Self::AddonParamInvalid => "E_ADDON_PARAM_INVALID",
            Self::AddonEnvCollision => "E_ADDON_ENV_COLLISION",
            Self::AddonRegistryUnreachable => "E_ADDON_REGISTRY_UNREACHABLE",
            Self::AddonLocalPathDrift => "E_ADDON_LOCAL_PATH_DRIFT",
            Self::AddonLocalPathInPublish => "E_ADDON_LOCAL_PATH_IN_PUBLISH",
            Self::AddonNixParseError => "E_ADDON_NIX_PARSE_ERROR",
            Self::AddonEgressViolation => "E_ADDON_EGRESS_VIOLATION",
            Self::AddonQuotaExceeded => "E_ADDON_QUOTA_EXCEEDED",
            Self::AddonTyposquatBlocked => "E_ADDON_TYPOSQUAT_BLOCKED",
            Self::AddonTenantNamespaceDenied => "E_ADDON_TENANT_NAMESPACE_DENIED",
            Self::AddonReproducibilityFailed => "E_ADDON_REPRODUCIBILITY_FAILED",
            Self::AddonRoothashMismatch => "E_ADDON_ROOTHASH_MISMATCH",
            Self::AddonTierNotImplemented => "E_ADDON_TIER_NOT_IMPLEMENTED",
            Self::AddonSeccompProfileDenied => "E_ADDON_SECCOMP_PROFILE_DENIED",
            Self::AddonNotFound => "E_ADDON_NOT_FOUND",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for ErrorCode {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_variant_has_stable_string() {
        let all = [
            ErrorCode::UnsupportedMajor,
            ErrorCode::MinorTooHigh,
            ErrorCode::MalformedVersion,
            ErrorCode::UnknownField,
            ErrorCode::MalformedManifest,
            ErrorCode::EmptyApps,
            ErrorCode::MultiAppDeferred,
            ErrorCode::SourceKindDeferred,
            ErrorCode::SecretsNotImplemented,
            ErrorCode::PersistDeferred,
            ErrorCode::NetworkPortsWithNone,
            ErrorCode::CompileOutputExistsNotDir,
            ErrorCode::CompileStagingFailed,
            ErrorCode::CompileArchiveFailed,
            ErrorCode::MvmNotFound,
            ErrorCode::SourcePathNotFound,
            ErrorCode::SourcePathNotDir,
            ErrorCode::SourceCopyFailed,
            ErrorCode::SourceGlobInvalid,
            ErrorCode::SourceOutOfTreeSymlink,
            ErrorCode::MvmVersionTooOld,
            ErrorCode::NetworkWildcard,
            ErrorCode::InvalidId,
            ErrorCode::UnpinnedDeps,
            ErrorCode::LockfileNotFound,
            ErrorCode::DepsRequiredForFunctionWorkload,
            ErrorCode::SecretInSchema,
            ErrorCode::FunctionNetworkHostForbidden,
            ErrorCode::UnsupportedLanguage,
            ErrorCode::NoPrimaryEntrypoint,
            ErrorCode::MultiplePrimaryEntrypoints,
            ErrorCode::DuplicateEntrypointFunction,
            ErrorCode::FunctionNotFound,
            ErrorCode::FunctionSchemaMismatch,
            ErrorCode::InvalidConcurrencyPoolSize,
            ErrorCode::InvalidConcurrencyMaxCallsPerWorker,
            ErrorCode::InvalidConcurrencyMaxRssMb,
            ErrorCode::UnsupportedConcurrencyInProcessMode,
            ErrorCode::UnsupportedConcurrencyForLanguage,
            ErrorCode::AddonLockfileMissing,
            ErrorCode::AddonLockfileSignatureInvalid,
            ErrorCode::AddonShaMismatch,
            ErrorCode::AddonSignatureInvalid,
            ErrorCode::AddonParamInvalid,
            ErrorCode::AddonEnvCollision,
            ErrorCode::AddonRegistryUnreachable,
            ErrorCode::AddonLocalPathDrift,
            ErrorCode::AddonLocalPathInPublish,
            ErrorCode::AddonNixParseError,
            ErrorCode::AddonEgressViolation,
            ErrorCode::AddonQuotaExceeded,
            ErrorCode::AddonTyposquatBlocked,
            ErrorCode::AddonTenantNamespaceDenied,
            ErrorCode::AddonReproducibilityFailed,
            ErrorCode::AddonRoothashMismatch,
            ErrorCode::AddonTierNotImplemented,
            ErrorCode::AddonSeccompProfileDenied,
            ErrorCode::AddonNotFound,
        ];
        for code in all {
            assert!(code.as_str().starts_with("E_"), "{code} missing E_ prefix");
        }
    }

    #[test]
    fn serializes_as_plain_string() {
        let json = serde_json::to_string(&ErrorCode::SecretsNotImplemented).unwrap();
        assert_eq!(json, "\"E_SECRETS_NOT_IMPLEMENTED\"");
    }

    // The upstream `all_codes_match_registry` test cross-checked the
    // enum against `schema/error-codes.json` at the mvmforge repo
    // root. That registry hasn't been ported into the mvm tree yet
    // (it's a separate plan-60 follow-up). When it lands, restore the
    // test here. Until then, `every_variant_has_stable_string` above
    // is the local consistency check.
}
