//! Public identity only. Native custody belongs to the host layer.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Public enrollment record. Persisting it does not grant producer access.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrolledIdentity {
    pub installation: Uuid,
    pub public_key: [u8; 32],
}
