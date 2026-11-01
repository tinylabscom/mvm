//! Policy enforcement primitives.
//!
//! Single source of truth for input validation, path canonicalization,
//! resource caps, and quota metering. Every new agent / supervisor /
//! gateway handler routes through these types so a verb cannot invent
//! its own validation discipline by accident.

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
