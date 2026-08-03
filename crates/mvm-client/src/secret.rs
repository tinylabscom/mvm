//! Write-only local secret lifecycle service.
//!
//! Issue #2081 composes `SecretStore`, binding metadata, reference checks,
//! and audit emission behind one canonical service. The service exposes
//! metadata only — no reveal path, no serializable type carrying secret
//! material.
