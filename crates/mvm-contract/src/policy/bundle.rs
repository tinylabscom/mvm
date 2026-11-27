//! `PolicyId` — the identifier an audit entry's `bundle_id` field carries.

use alloc::string::String;

use serde::{Deserialize, Serialize};

/// Identifier recorded in an audit entry's optional `bundle_id` field.
/// The host admits no policy bundle, so it writes `None`; the type stays so
/// audit chains that carry the field keep parsing and verifying.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PolicyId(pub String);
