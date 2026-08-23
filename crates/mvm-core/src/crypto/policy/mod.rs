//! Policy enforcement primitives — Control 1 of the filesystem-volumes plan.
//!
//! Single source of truth for input validation, path canonicalization,
//! resource caps, and quota metering. Every new agent / supervisor /
//! gateway handler routes through these types so a verb cannot invent
//! its own validation discipline by accident.
//!
//! Today this module ships only the slice needed by the W1 sandbox-SDK
//! foundation work (tag input validation + TTL parsing). Path policy,
//! resource limits, and quota meters land alongside their consumers in
//! W2 (FS RPC, process control, etc.).

pub mod mount;
pub mod path;
pub mod tags;
pub mod ttl;

pub use mount::{
    MOUNT_ALLOW_ROOTS, MountPathError, MountPathPolicy, PROTECTED_RUNTIME_PATHS,
    validate_mount_path,
};
pub use path::{
    CanonicalPath, OsCanonicalizer, PathCanonicalizer, PathOp, PathPolicy, PolicyError,
};
pub use tags::{InputValidator, MAX_TAG_KEY_LEN, MAX_TAG_VALUE_LEN, MAX_TAGS, TagValidationError};
pub use ttl::{TtlParseError, parse_ttl};
