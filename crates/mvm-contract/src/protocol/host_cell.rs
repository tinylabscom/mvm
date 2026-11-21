//! `host.cell.v1` payload types — host-held state cells and the liveness
//! signal. The `signal` verb takes an empty object and answers with one.
//!
//! The caller names a cell. Its tenant, unit and execution epoch are not
//! payload fields: they come from the broker registration the call arrived
//! on, and whether the unit writes or reads the cell comes from the admitted
//! topology. A workload cannot claim a role or an epoch by asking.
//!
//! Every type here is `deny_unknown_fields`, so a client built against a newer
//! contract is refused rather than half served.

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

/// The service these payloads belong to.
pub const HOST_CELL_SERVICE: &str = "host.cell.v1";

/// Longest cell name accepted, in bytes.
pub const MAX_CELL_NAME_LEN: usize = 256;

/// Request for `host.cell.v1::write`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct CellWriteRequest {
    /// The cell, as the topology names it.
    pub cell: String,
    /// Must be greater than the stored version.
    pub version: u64,
    /// The new value, at most the cell's declared size, as base64.
    #[serde(with = "crate::plan::verb_grant::sig_base64")]
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub value: Vec<u8>,
}

/// Response for `host.cell.v1::write`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct CellWriteResponse {
    /// The version now committed.
    pub version: u64,
}

/// Request for `host.cell.v1::read`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct CellReadRequest {
    /// The cell, as the topology names it.
    pub cell: String,
}

/// Response for `host.cell.v1::read`. Version 0 with an empty value is a cell
/// that has not been written yet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct CellReadResponse {
    pub version: u64,
    /// The committed value, as base64.
    #[serde(with = "crate::plan::verb_grant::sig_base64")]
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub value: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_fields_are_refused() {
        let write = serde_json::json!({"cell": "c", "version": 1, "value": "", "unit": "x"});
        assert!(serde_json::from_value::<CellWriteRequest>(write).is_err());
        let read = serde_json::json!({"cell": "c", "epoch": 3});
        assert!(serde_json::from_value::<CellReadRequest>(read).is_err());
    }

    #[test]
    fn requests_round_trip() {
        let write = CellWriteRequest {
            cell: "setpoint".into(),
            version: 7,
            value: vec![1, 2, 3],
        };
        let back: CellWriteRequest =
            serde_json::from_value(serde_json::to_value(&write).unwrap()).unwrap();
        assert_eq!(back, write);
        assert_eq!(serde_json::to_value(&write).unwrap()["value"], "AQID");
        let numbers = serde_json::json!({"cell": "c", "version": 1, "value": [1, 2, 3]});
        assert!(serde_json::from_value::<CellWriteRequest>(numbers).is_err());
    }
}
