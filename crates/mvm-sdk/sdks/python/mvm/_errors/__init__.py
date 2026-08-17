"""SDK error taxonomy, generated from `schema/sdk-errors-v0.json`.

Do not edit `types.py` by hand. The hierarchy and the broker status
mapping are owned by the Rust registry at
`crates/mvm-sdk/src/error_taxonomy.rs`; to refresh after a change there,
run `cargo xtask gen-stubs` from the workspace root.
"""

from mvm._errors.types import (
    EmittingContextError,
    MsgpackUnavailable,
    MvmTransportError,
    NoVmIntrospectionError,
    PayloadTooLarge,
    RemoteError,
    SecretInArgError,
    SecretInArgWarning,
    STATUS_ERRORS,
    STATUS_OK,
    BadRequestError,
    HostServiceError,
    InvalidInputError,
    NotBoundError,
    RateLimitedError,
    ServiceError,
    TransportError,
    UnavailableError,
    VerbNotImplementedError,
)

__all__ = [
    "EmittingContextError",
    "MsgpackUnavailable",
    "MvmTransportError",
    "NoVmIntrospectionError",
    "PayloadTooLarge",
    "RemoteError",
    "SecretInArgError",
    "SecretInArgWarning",
    "STATUS_ERRORS",
    "STATUS_OK",
    "BadRequestError",
    "HostServiceError",
    "InvalidInputError",
    "NotBoundError",
    "RateLimitedError",
    "ServiceError",
    "TransportError",
    "UnavailableError",
    "VerbNotImplementedError",
]
