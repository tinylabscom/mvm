//! Write-only local secret lifecycle service.
//!
//! Composes `SecretStore`, binding metadata, reference checks, and audit
//! emission behind one canonical service. The service exposes metadata
//! only — no reveal path, no serializable type carrying secret material.
